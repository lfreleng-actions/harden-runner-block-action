// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Unit tests for the central egress-policy override.
//
// The file is parsed against a fixed clock, the fetch is a fake that
// serves or refuses each candidate URL, and the runner files are temp
// files, so every path (absent, active, expired, off, malformed,
// unreadable, disabled) runs deterministically and offline.
//
// Run with: node --test tests/test_egress_override.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  MAX_UNTIL_MS,
  OVERRIDE_BRANCH,
  applyEgressOverride,
  fetchOverride,
  overrideCandidates,
  overrideFromState,
  parseOverride,
} from '../src/egress-override.mjs';
import { parseKeyValueFile } from '../src/actions-io.mjs';

const NOW = Date.parse('2026-11-11T15:00:00Z');
const TOMORROW = '2026-11-12T18:00:00Z';

const ACTIVE_FILE = [
  '# Flipped during the Canonical DNS incident',
  'egress_policy=audit',
  `until=${TOMORROW}`,
  'reason=Canonical authoritative DNS answering SERVFAIL via dns.google',
  '',
].join('\n');

// --- parseOverride ------------------------------------------------------

test('parses an active override with comments and a trailing newline', () => {
  assert.deepEqual(parseOverride(ACTIVE_FILE, NOW), {
    state: 'active',
    until: TOMORROW,
    reason: 'Canonical authoritative DNS answering SERVFAIL via dns.google',
    problem: '',
  });
});

test('accepts CRLF, a BOM, surrounding whitespace and an until without seconds', () => {
  const text = '\uFEFF egress_policy = audit \r\nuntil=2026-11-12T18:00Z\r\n';
  const r = parseOverride(text, NOW);
  assert.equal(r.state, 'active');
  assert.equal(r.until, '2026-11-12T18:00Z');
  assert.equal(r.reason, '');
});

test('an empty file, or one holding only comments, is off', () => {
  assert.equal(parseOverride('', NOW).state, 'off');
  assert.equal(parseOverride('# nothing to see\n\n', NOW).state, 'off');
});

test('egress_policy=block is off, whatever else the file says', () => {
  const r = parseOverride(`egress_policy=block\nuntil=${TOMORROW}\nreason=done`, NOW);
  assert.equal(r.state, 'off');
  assert.equal(r.reason, 'done');
});

test('an until in the past is expired, not active', () => {
  const r = parseOverride('egress_policy=audit\nuntil=2026-11-11T14:59:59Z', NOW);
  assert.equal(r.state, 'expired');
  assert.equal(r.until, '2026-11-11T14:59:59Z');
});

test('an until equal to now is expired', () => {
  assert.equal(parseOverride('egress_policy=audit\nuntil=2026-11-11T15:00:00Z', NOW).state, 'expired');
});

test('an until more than the horizon away is invalid', () => {
  const justInside = new Date(NOW + MAX_UNTIL_MS).toISOString().replace(/\.\d{3}Z$/, 'Z');
  assert.equal(parseOverride(`egress_policy=audit\nuntil=${justInside}`, NOW).state, 'active');
  const r = parseOverride('egress_policy=audit\nuntil=2026-11-14T15:00:01Z', NOW);
  assert.equal(r.state, 'invalid');
  assert.match(r.problem, /more than 72 h away/);
});

test('audit without until is invalid', () => {
  const r = parseOverride('egress_policy=audit', NOW);
  assert.equal(r.state, 'invalid');
  assert.match(r.problem, /needs 'until'/);
});

test('an until that is not a UTC timestamp is invalid', () => {
  for (const until of ['tomorrow', '2026-11-12', '2026-11-12T18:00:00+01:00', '2026-11-12 18:00:00Z', '2026-13-40T00:00:00Z']) {
    const r = parseOverride(`egress_policy=audit\nuntil=${until}`, NOW);
    assert.equal(r.state, 'invalid', until);
    assert.match(r.problem, /'until' must be a UTC time/);
  }
});

test('a calendar date that does not exist is invalid, not rolled forward', () => {
  // Date.parse() reads 31 November as 1 December; the override must not.
  const late = Date.parse('2026-11-29T15:00:00Z');
  for (const until of ['2026-11-31T18:00:00Z', '2026-11-31T18:00Z', '2026-02-29T00:00:00Z', '2026-04-31T00:00:00Z', '2026-11-30T24:00:00Z', '2026-11-30T23:60:00Z']) {
    const r = parseOverride(`egress_policy=audit\nuntil=${until}`, late);
    assert.equal(r.state, 'invalid', until);
    assert.match(r.problem, /'until' must be a UTC time/);
  }
  assert.equal(parseOverride('egress_policy=audit\nuntil=2026-11-30T18:00:00Z', late).state, 'active');
  assert.equal(parseOverride('egress_policy=audit\nuntil=2028-02-29T00:00:00Z', Date.parse('2028-02-27T00:00:00Z')).state, 'active', 'a real leap day');
});

test('a missing or unknown policy is invalid', () => {
  assert.match(parseOverride(`until=${TOMORROW}`, NOW).problem, /missing 'egress_policy'/);
  assert.match(parseOverride('egress_policy=open', NOW).problem, /must be 'audit' or 'block'/);
  assert.match(parseOverride('egress_policy=Audit', NOW).problem, /must be 'audit' or 'block'/);
});

test('unknown keys, repeated keys and non key=value lines are invalid', () => {
  assert.match(parseOverride('egress_policy=audit\nallowed=evil.example', NOW).problem, /unknown key 'allowed'/);
  assert.match(parseOverride('egress_policy=audit\negress_policy=block', NOW).problem, /repeated/);
  assert.match(parseOverride('egress_policy=audit\naudit', NOW).problem, /not key=value: 'audit'/);
  assert.match(parseOverride('=audit', NOW).problem, /not key=value/);
});

test('the reason is reduced to safe characters and a bounded length', () => {
  const nasty = 'see `rm -rf`\u0007 | https://x/y?a=b%0A::error::x ' + 'z'.repeat(300);
  const r = parseOverride(`egress_policy=audit\nuntil=${TOMORROW}\nreason=${nasty}`, NOW);
  assert.equal(r.state, 'active');
  assert.equal(r.reason.length, 200);
  assert.doesNotMatch(r.reason, /[`|\u0007?%]*[`|\u0007%]/);
  assert.match(r.reason, /^see \?rm -rf\?\? \? https:\/\/x\/y\?a\?b\?0A::error::x z+$/);
});

// --- candidates and fetch ----------------------------------------------

test('candidates read the workflow org directory in the host repo first, then the family default, by qualified branch ref', () => {
  const urls = overrideCandidates('lfreleng-actions', 'onap');
  assert.deepEqual(urls, [
    `https://raw.githubusercontent.com/lfreleng-actions/.github/refs/heads/${OVERRIDE_BRANCH}/.github/harden-runner/onap/egress_override.txt`,
    `https://raw.githubusercontent.com/lfreleng-actions/.github/refs/heads/${OVERRIDE_BRANCH}/.github/harden-runner/egress_override.txt`,
  ]);
  for (const url of urls) {
    assert.match(url, /\/refs\/heads\//, 'a tag named like the branch must not be able to stand in for it');
  }
});

function fakeFetch(responses) {
  const calls = [];
  const headers = [];
  const fetchText = async (url, _redirects, extraHeaders = {}) => {
    calls.push(url);
    headers.push(extraHeaders);
    const r = responses[url];
    if (r === undefined) {
      const e = new Error(`HTTP 404 fetching ${url}`);
      e.status = 404;
      throw e;
    }
    if (r instanceof Error) throw r;
    return r;
  };
  return { fetchText, calls, headers };
}

const [ORG_URL, FAMILY_URL] = overrideCandidates('acme', 'acme');

test('fetchOverride returns null when every candidate is absent', async () => {
  const f = fakeFetch({});
  assert.equal(await fetchOverride('acme', 'acme', '', f.fetchText), null);
  assert.deepEqual(f.calls, [ORG_URL, FAMILY_URL]);
  assert.deepEqual(f.headers, [{}, {}], 'no token, no Authorization header');
});

test('fetchOverride stops at the org-specific file', async () => {
  const f = fakeFetch({ [ORG_URL]: 'egress_policy=block', [FAMILY_URL]: ACTIVE_FILE });
  assert.deepEqual(await fetchOverride('acme', 'acme', '', f.fetchText), { url: ORG_URL, text: 'egress_policy=block' });
  assert.deepEqual(f.calls, [ORG_URL]);
});

test('fetchOverride falls through a 404 to the family default', async () => {
  const f = fakeFetch({ [FAMILY_URL]: ACTIVE_FILE });
  assert.deepEqual(await fetchOverride('acme', 'acme', '', f.fetchText), { url: FAMILY_URL, text: ACTIVE_FILE });
});

test('fetchOverride reports any failure other than absence instead of moving on', async () => {
  const timeout = new Error('Timeout (15s) fetching https://raw.githubusercontent.com/...');
  const f = fakeFetch({ [ORG_URL]: timeout, [FAMILY_URL]: ACTIVE_FILE });
  const r = await fetchOverride('acme', 'acme', '', f.fetchText);
  assert.equal(r.url, ORG_URL);
  assert.match(r.error, /Timeout/);
  assert.deepEqual(f.calls, [ORG_URL], 'a switch that cannot be read is not assumed absent');
});

test('fetchOverride sends the caller token as a bearer header, so a private host repo can answer', async () => {
  const f = fakeFetch({ [FAMILY_URL]: ACTIVE_FILE });
  await fetchOverride('acme', 'acme', 'ghp_secret', f.fetchText);
  assert.deepEqual(f.headers, [
    { Authorization: 'Bearer ghp_secret' },
    { Authorization: 'Bearer ghp_secret' },
  ]);
});

// --- applyEgressOverride -------------------------------------------------

// Run the policy against temp runner files, capturing stdout. The DNS
// check has already published block, as it does in pre, so the test
// can see whether the override's later lines replace it.
async function run(inputs, responses, hostOrg = 'acme') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hrba-override-'));
  const keys = ['GITHUB_OUTPUT', 'GITHUB_ENV', 'GITHUB_STATE', 'GITHUB_STEP_SUMMARY', 'HARDEN_RUNNER_EGRESS_POLICY'];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  for (const k of keys) process.env[k] = path.join(dir, k.toLowerCase());
  fs.writeFileSync(process.env.GITHUB_OUTPUT, 'egress_policy=block\n');
  fs.writeFileSync(process.env.GITHUB_ENV, 'HARDEN_RUNNER_EGRESS_POLICY=block\n');
  fs.writeFileSync(process.env.GITHUB_STATE, '');
  fs.writeFileSync(process.env.GITHUB_STEP_SUMMARY, '');
  delete process.env.HARDEN_RUNNER_EGRESS_POLICY;

  const f = fakeFetch(responses);
  let stdout = '';
  const out = process.stdout.write;
  process.stdout.write = (s) => { stdout += s; return true; };
  let policy;
  try {
    policy = await applyEgressOverride(
      { centralOverride: true, summary: true, workflowOrg: 'acme', token: '', ...inputs },
      hostOrg,
      { fetchText: f.fetchText, now: () => NOW },
    );
  } finally {
    process.stdout.write = out;
  }
  const read = (k) => fs.readFileSync(path.join(dir, k.toLowerCase()), 'utf8');
  const result = {
    policy,
    stdout,
    calls: f.calls,
    headers: f.headers,
    outputs: parseKeyValueFile(read('GITHUB_OUTPUT')),
    env: parseKeyValueFile(read('GITHUB_ENV')),
    state: parseKeyValueFile(read('GITHUB_STATE')),
    summary: read('GITHUB_STEP_SUMMARY'),
    processEnv: process.env.HARDEN_RUNNER_EGRESS_POLICY,
  };
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  fs.rmSync(dir, { recursive: true, force: true });
  return result;
}

const OFF_OUTPUTS = { override_active: 'false', override_until: '', override_reason: '' };

test('no override file anywhere: block, outputs off, no annotation', async () => {
  const r = await run({}, {});
  assert.equal(r.policy, 'block');
  assert.deepEqual({ ...r.outputs }, { egress_policy: 'block', override_source: '', ...OFF_OUTPUTS });
  assert.equal(r.env.HARDEN_RUNNER_EGRESS_POLICY, 'block');
  assert.equal(r.state.egress_override, '');
  assert.match(r.stdout, /No central egress override for acme \(branch harden-runner-ops\)/);
  assert.doesNotMatch(r.stdout, /::warning/);
  assert.equal(r.summary, '');
});

test('an active override publishes audit over the DNS check, with state, annotation and summary', async () => {
  const r = await run({}, { [FAMILY_URL]: ACTIVE_FILE });
  assert.equal(r.policy, 'audit');
  assert.equal(r.outputs.egress_policy, 'audit', 'the later line wins');
  assert.equal(r.outputs.override_active, 'true');
  assert.equal(r.outputs.override_source, FAMILY_URL);
  assert.equal(r.outputs.override_until, TOMORROW);
  assert.match(r.outputs.override_reason, /^Canonical authoritative DNS/);
  assert.equal(r.env.HARDEN_RUNNER_EGRESS_POLICY, 'audit');
  assert.equal(r.processEnv, 'audit', 'the rest of pre sees it too');
  assert.equal(r.state.egress_override, 'audit');
  assert.match(r.stdout, /::warning title=Central egress override active%3A audit mode::HARDEN_RUNNER_EGRESS_POLICY=audit published until 2026-11-12T18:00:00Z/);
  assert.match(r.summary, /### ⚠️ Central egress override active/);
  assert.match(r.summary, /until `2026-11-12T18:00:00Z`/);
  assert.match(r.summary, /Reason: Canonical authoritative DNS/);
});

test('the org-specific file wins over the family default', async () => {
  const r = await run({}, { [ORG_URL]: 'egress_policy=block', [FAMILY_URL]: ACTIVE_FILE });
  assert.equal(r.policy, 'block');
  assert.equal(r.outputs.override_source, ORG_URL, 'the file that decided is named');
  assert.equal(r.outputs.override_active, 'false');
  assert.match(r.stdout, /present but egress_policy=block/);
  assert.deepEqual(r.calls, [ORG_URL]);
});

test('an expired override stays in block mode, naming the expiry, without a warning', async () => {
  const r = await run({}, { [ORG_URL]: 'egress_policy=audit\nuntil=2026-11-11T09:00:00Z' });
  assert.equal(r.policy, 'block');
  assert.equal(r.outputs.override_active, 'false');
  assert.equal(r.outputs.egress_policy, 'block');
  assert.match(r.stdout, /present but expired at 2026-11-11T09:00:00Z/);
  assert.doesNotMatch(r.stdout, /::warning/);
});

test('a malformed override is ignored with a warning and block mode', async () => {
  const r = await run({}, { [ORG_URL]: 'egress_policy=audit\nuntil=soon' });
  assert.equal(r.policy, 'block');
  assert.equal(r.outputs.override_active, 'false');
  assert.equal(r.outputs.override_source, ORG_URL, 'the file that was read is named, as for off and expired');
  assert.equal(r.outputs.egress_policy, 'block');
  assert.equal(r.env.HARDEN_RUNNER_EGRESS_POLICY, 'block');
  assert.match(r.stdout, /::warning title=Central egress override ignored::'until' must be a UTC time/);
  assert.match(r.stdout, /staying in block mode/);
});

test('an unreadable override is ignored with a warning rather than assumed absent', async () => {
  const r = await run({}, { [ORG_URL]: new Error('HTTP 503 fetching ' + ORG_URL) });
  assert.equal(r.policy, 'block');
  assert.equal(r.outputs.override_source, ORG_URL);
  assert.match(r.stdout, /::warning title=Central egress override ignored::could not be read: HTTP 503/);
  assert.deepEqual(r.calls, [ORG_URL]);
});

test('warnings and the summary follow allow_list_summary; the log line does not', async () => {
  const active = await run({ summary: false }, { [ORG_URL]: ACTIVE_FILE });
  assert.equal(active.policy, 'audit');
  assert.doesNotMatch(active.stdout, /::warning/);
  assert.equal(active.summary, '');
  assert.match(active.stdout, /Central egress override active:/);

  const broken = await run({ summary: false }, { [ORG_URL]: 'nonsense' });
  assert.doesNotMatch(broken.stdout, /::warning/);
  assert.match(broken.stdout, /Central egress override ignored:/);
});

test('central_override: false never fetches and publishes off', async () => {
  const r = await run({ centralOverride: false }, { [ORG_URL]: ACTIVE_FILE });
  assert.equal(r.policy, 'block');
  assert.deepEqual(r.calls, []);
  assert.equal(r.outputs.override_active, 'false');
  assert.equal(r.outputs.egress_policy, 'block');
  assert.match(r.stdout, /not consulted \(central_override: false\)/);
});

test('an org name that could not form a URL is not fetched', async () => {
  const host = await run({}, {}, 'bad..org/../x');
  assert.equal(host.policy, 'block');
  assert.deepEqual(host.calls, []);
  assert.match(host.stdout, /no valid org to read it from/);
  const workflow = await run({ workflowOrg: '' }, { [ORG_URL]: ACTIVE_FILE });
  assert.equal(workflow.policy, 'block');
  assert.deepEqual(workflow.calls, []);
});

test('a cross-org config reads the workflow org directory in the host repo', async () => {
  // An onap workflow loading lfreleng-actions' list: onap's own
  // directory in lfreleng-actions/.github decides, so onap can stay at
  // block while the family default flips everyone else.
  const [onapUrl, familyUrl] = overrideCandidates('lfreleng-actions', 'onap');
  assert.match(onapUrl, /lfreleng-actions\/\.github\/.*\/harden-runner\/onap\/egress_override\.txt$/);
  const held = await run({ workflowOrg: 'onap' }, { [onapUrl]: 'egress_policy=block', [familyUrl]: ACTIVE_FILE }, 'lfreleng-actions');
  assert.equal(held.policy, 'block');
  assert.deepEqual(held.calls, [onapUrl]);
  const flipped = await run({ workflowOrg: 'onap' }, { [familyUrl]: ACTIVE_FILE }, 'lfreleng-actions');
  assert.equal(flipped.policy, 'audit');
  assert.deepEqual(flipped.calls, [onapUrl, familyUrl]);
  // The host org's own directory is never consulted for another org's
  // workflow.
  const [hostOwnUrl] = overrideCandidates('lfreleng-actions', 'lfreleng-actions');
  const other = await run({ workflowOrg: 'onap' }, { [hostOwnUrl]: ACTIVE_FILE }, 'lfreleng-actions');
  assert.equal(other.policy, 'block');
});

test('the caller token is masked and sent with the override read', async () => {
  const r = await run({ token: 'ghp_private' }, { [ORG_URL]: ACTIVE_FILE });
  assert.equal(r.policy, 'audit');
  assert.match(r.stdout, /^::add-mask::ghp_private$/m);
  assert.deepEqual(r.headers, [{ Authorization: 'Bearer ghp_private' }]);
  const anon = await run({}, { [ORG_URL]: ACTIVE_FILE });
  assert.doesNotMatch(anon.stdout, /::add-mask::/);
  assert.deepEqual(anon.headers, [{}]);
});

// --- overrideFromState ----------------------------------------------------

test('main reads the override from the state pre saved', () => {
  assert.equal(overrideFromState({ STATE_egress_override: 'audit' }), true);
  assert.equal(overrideFromState({ STATE_egress_override: '' }), false);
  assert.equal(overrideFromState({}), false);
  assert.equal(overrideFromState({ STATE_egress_override: 'block' }), false);
});
