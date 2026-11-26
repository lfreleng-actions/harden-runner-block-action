// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// The central egress-policy override: one file an organisation
// administrator edits to move every job that loads the org's allow-list
// from block mode to audit mode for a bounded time.
//
// Block mode depends on infrastructure nobody in the organisation
// operates. harden-runner's agent resolves every allow-list hostname
// through dns.google once, with no retry, and reverts on the first
// SERVFAIL; when an upstream authoritative server flakes, as
// Canonical's did for the ubuntu.com archive hosts, most jobs in the
// estate fail at their first step, and the pull requests that would
// change the workflows fail the same way. The override exists for that
// day. It lives in the same special repository as the allow-list, on a
// dedicated branch a repository ruleset keeps writable by
// administrators alone, so flipping it is one signed commit with no
// pull request in the way.
//
// What the switch can do is deliberately narrow:
//
//   - It can only loosen to 'audit', never add an endpoint or change
//     where the allow-list comes from.
//   - It must carry an expiry, at most MAX_UNTIL_MS ahead. A forgotten
//     switch turns itself off.
//   - Every error path (file absent, unreachable, malformed, expired,
//     too far ahead) leaves the override off, and the job's egress
//     policy whatever the DNS check made it. The switch fails closed.
//   - Every job it affects says so: a log line always, and a warning
//     annotation and a step-summary block where the caller reports.
//
// This module reads the override and reports it; it publishes no
// egress policy itself. pre reads it BEFORE the DNS check, because
// that check can end the step ('invalid_records: error', or a list
// that filters to nothing), and an override nobody consulted rescues
// nothing. The DNS check then publishes the one effective policy.
//
// The override reaches harden-runner two ways. A workflow that reads
//   egress-policy: ${{ env.HARDEN_RUNNER_EGRESS_POLICY }}
// runs harden-runner in audit mode, keeps its monitoring and never
// reverts. A workflow that hard-codes 'block' still runs the agent in
// block mode, so the agent may revert; the main step then warns and
// continues instead of failing the job. Either way the job runs.
//
// The file is plain 'key=value' lines, '#' starting a comment line:
//
//   egress_policy=audit
//   until=2026-11-12T18:00:00Z
//   reason=Canonical authoritative DNS answering SERVFAIL via dns.google
//
// 'egress_policy=block' switches the override off while leaving the
// file in place.

import {
  annotate,
  info,
  maskSecret,
  saveState,
  setOutput,
  stepSummary,
} from './actions-io.mjs';
import { REQUEST_TIMEOUT_MS, httpsGet } from './fetch.mjs';
import { ORG_RE } from './inputs.mjs';

export const OVERRIDE_BRANCH = 'harden-runner-ops';
export const OVERRIDE_FILE = 'egress_override.txt';
// Carried from pre to main, so main knows to warn rather than fail
// when the agent never enforces.
export const OVERRIDE_STATE = 'egress_override';
export const MAX_UNTIL_MS = 72 * 60 * 60 * 1000;

// Fetched by fully qualified ref, so a tag named like the branch cannot
// stand in for it: a branch ruleset says nothing about tags, and a bare
// ref in the URL would let whoever can push a tag publish an override.
const OVERRIDE_REF = `refs/heads/${OVERRIDE_BRANCH}`;

const KEYS = new Set(['egress_policy', 'until', 'reason']);
const POLICIES = new Set(['audit', 'block']);
// Date and time, UTC, seconds optional: what 'date -u +%FT%TZ' prints.
const UNTIL_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?Z$/;
const REASON_MAX = 200;
const QUOTE_MAX = 40;
// Everything that is not plainly inert in a log line becomes '?'. The
// runner reads '##[' as a command anywhere in a line, and '::' at its
// start, so text from the file never reaches the log with brackets,
// control characters or anything else outside this set.
const UNSAFE_RE = /[^A-Za-z0-9 .,;:'()/_#-]/g;

// Text from the override file, or from a failure to read it, made
// safe to log: reduced to the inert set and bounded in length.
export function safeText(value, max = QUOTE_MAX) {
  return String(value).replace(UNSAFE_RE, '?').slice(0, max);
}

const TITLE_ACTIVE = 'Central egress override active: audit mode';
const TITLE_IGNORED = 'Central egress override ignored';

function invalid(problem) {
  return { state: 'invalid', until: '', reason: '', problem };
}

// The expiry as milliseconds, or NaN. Date.parse() alone would accept
// a day that does not exist, reading '2026-11-31' as 1 December, so
// the parsed instant is formatted again and must read back as what
// was written (with the seconds the writer may have omitted).
function parseUntil(until) {
  if (!UNTIL_RE.test(until)) return NaN;
  const ms = Date.parse(until);
  if (!Number.isFinite(ms)) return NaN;
  const written = until.length === 17 ? `${until.slice(0, 16)}:00Z` : until;
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z') === written ? ms : NaN;
}

// Parse the override file. Pure. Returns { state, until, reason,
// problem } with state one of:
//
//   active   egress_policy=audit with an expiry still ahead
//   off      egress_policy=block, or an empty file
//   expired  egress_policy=audit whose expiry has passed
//   invalid  anything else; 'problem' says what
//
// The reason is free text for the summary and the annotation, so it is
// reduced to a safe character set and a bounded length rather than
// refused: a reason is never worth failing the switch over. Every
// 'problem' quotes the file only through safeText(), so a rejected
// value cannot act on the log it is reported in.
export function parseOverride(text, nowMs) {
  const fields = {};
  for (const raw of String(text).replace(/^\uFEFF/, '').split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) return invalid(`line is not key=value: '${safeText(line)}'`);
    const key = line.slice(0, eq).trim();
    if (!KEYS.has(key)) return invalid(`unknown key '${safeText(key)}'`);
    if (key in fields) return invalid(`key '${key}' repeated`);
    fields[key] = line.slice(eq + 1).trim();
  }

  if (Object.keys(fields).length === 0) {
    return { state: 'off', until: '', reason: '', problem: '' };
  }
  const policy = fields.egress_policy;
  if (policy === undefined) return invalid("missing 'egress_policy'");
  if (!POLICIES.has(policy)) {
    return invalid(`egress_policy must be 'audit' or 'block' (received '${safeText(policy)}')`);
  }
  const reason = safeText(fields.reason || '', REASON_MAX);
  if (policy === 'block') {
    return { state: 'off', until: '', reason, problem: '' };
  }

  const until = fields.until;
  if (until === undefined) return invalid("'egress_policy=audit' needs 'until'");
  const untilMs = parseUntil(until);
  if (!Number.isFinite(untilMs)) {
    return invalid(`'until' must be a UTC time like 2026-01-31T18:00:00Z (received '${safeText(until)}')`);
  }
  if (untilMs <= nowMs) {
    return { state: 'expired', until, reason, problem: '' };
  }
  if (untilMs - nowMs > MAX_UNTIL_MS) {
    const hours = MAX_UNTIL_MS / 3_600_000;
    return invalid(`'until' is more than ${hours} h away; set it within ${hours} h and renew`);
  }
  return { state: 'active', until, reason, problem: '' };
}

// Where the override may live, most specific first, in the '.github'
// repository of the org that hosts the allow-list: a directory named
// for the workflow's own org, then the family directory. The same
// shape as the allow-list search chain, so a consumer org can hold its
// jobs at block while the host's family default flips the rest.
export function overrideCandidates(hostOrg, workflowOrg) {
  const base = `https://raw.githubusercontent.com/${hostOrg}/.github/${OVERRIDE_REF}/.github/harden-runner`;
  return [`${base}/${workflowOrg}/${OVERRIDE_FILE}`, `${base}/${OVERRIDE_FILE}`];
}

// The whole lookup, both candidates included, shares one deadline: a
// switch that cannot be read in that time is reported as unreadable,
// and costs the job no more than one fetch would.
export const LOOKUP_TIMEOUT_MS = REQUEST_TIMEOUT_MS;

// Fetch the first candidate that exists. Returns { url, text }, or
// { url, error } when a fetch failed for a reason other than absence,
// or null when no candidate exists. Only a 404 moves on to the next
// candidate: any other failure is reported, because a switch that may
// be set but cannot be read deserves a mention.
//
// A private host repository answers an anonymous read with 404, so
// the 'token' the caller supplied for the allow-list fetch goes with
// the request. It goes only to raw.githubusercontent.com, and the
// fetcher drops it on any redirect.
export async function fetchOverride(hostOrg, workflowOrg, {
  token = '',
  fetchText = httpsGet,
  deadline = Date.now() + LOOKUP_TIMEOUT_MS,
} = {}) {
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  for (const url of overrideCandidates(hostOrg, workflowOrg)) {
    try {
      return { url, text: await fetchText(url, { headers, deadline }) };
    } catch (e) {
      if (e?.status === 404) continue;
      return { url, error: e?.message || String(e) };
    }
  }
  return null;
}

const OFF = Object.freeze({ active: false, source: '', until: '', reason: '' });

// Publish what was read, and return it. The egress policy is not this
// module's to publish (see the header).
function publish(override) {
  setOutput('override_active', override.active ? 'true' : 'false');
  setOutput('override_source', override.source);
  setOutput('override_until', override.until);
  setOutput('override_reason', override.reason);
  saveState(OVERRIDE_STATE, override.active ? 'audit' : '');
  return override;
}

function summariseActive(parsed, url) {
  stepSummary([
    '',
    '### ⚠️ Central egress override active',
    '',
    `- Egress policy published: \`audit\` (until \`${parsed.until}\`)`,
    `- Reason: ${parsed.reason || '_none given_'}`,
    `- Source: \`${url}\``,
    '',
    'Jobs that read `HARDEN_RUNNER_EGRESS_POLICY` run harden-runner in ',
    'audit mode. Jobs that hard-code `block` continue without egress ',
    "filtering when harden-runner's agent does not enforce.",
    '',
  ].join('\n'));
}

// An override that is off says so without claiming a policy: the DNS
// check decides that, and 'invalid_records: warning' may already have
// chosen audit.
const NOT_APPLIED = 'not applied; the egress policy is unchanged';

function ignored(inputs, problem, url) {
  const message = `${problem} (${url}); ${NOT_APPLIED}`;
  info(`Central egress override ignored: ${message} ⚠️`);
  if (inputs.summary) annotate('warning', TITLE_IGNORED, message);
}

// Read the organisation's override and report it. `hostOrg` is the org
// whose '.github' repository supplied the allow-list; the workflow's
// own org selects the directory within it. Returns { active, source,
// until, reason }, also published as the override_* outputs, with
// 'active' saved for main. The caller publishes the egress policy.
export async function readEgressOverride(inputs, hostOrg, { fetchText = httpsGet, now = Date.now } = {}) {
  if (!inputs.centralOverride) {
    info('Central egress override not consulted (central_override: false) ℹ️');
    return publish(OFF);
  }
  const workflowOrg = inputs.workflowOrg || '';
  if (!ORG_RE.test(hostOrg) || !ORG_RE.test(workflowOrg)) {
    info(
      'Central egress override not consulted: no valid org to read it from ' +
      `(host '${safeText(hostOrg)}', workflow '${safeText(workflowOrg)}') ℹ️`,
    );
    return publish(OFF);
  }

  maskSecret(inputs.token);
  const found = await fetchOverride(hostOrg, workflowOrg, {
    token: inputs.token || '',
    fetchText,
    deadline: now() + LOOKUP_TIMEOUT_MS,
  });
  if (found === null) {
    info(`No central egress override for ${workflowOrg} in ${hostOrg}/.github (branch ${OVERRIDE_BRANCH}) ✅`);
    return publish(OFF);
  }
  if (found.error !== undefined) {
    ignored(inputs, `could not be read: ${safeText(found.error, REASON_MAX)}`, found.url);
    return publish({ ...OFF, source: found.url });
  }

  const parsed = parseOverride(found.text, now());
  if (parsed.state === 'invalid') {
    ignored(inputs, parsed.problem, found.url);
    return publish({ ...OFF, source: found.url });
  }
  if (parsed.state !== 'active') {
    const why = parsed.state === 'expired' ? `expired at ${parsed.until}` : 'egress_policy=block';
    info(`Central egress override present but ${why} (${found.url}); ${NOT_APPLIED} ✅`);
    return publish({ ...OFF, source: found.url });
  }

  const message =
    `audit mode until ${parsed.until}` +
    `${parsed.reason ? `: ${parsed.reason}` : ''} (${found.url})`;
  info(`Central egress override active: ${message} ⚠️`);
  if (inputs.summary) {
    annotate('warning', TITLE_ACTIVE, message);
    summariseActive(parsed, found.url);
  }
  return publish({ active: true, source: found.url, until: parsed.until, reason: parsed.reason });
}

// Whether pre found an active override, as main sees it.
export function overrideFromState(env = process.env) {
  return env[`STATE_${OVERRIDE_STATE}`] === 'audit';
}
