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
  LOOKUP_TIMEOUT_MS,
  MAX_UNTIL_MS,
  OVERRIDE_BRANCH,
  fetchOverride,
  overrideCandidates,
  overrideFromState,
  parseOverride,
  readEgressOverride,
  safeText,
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
  const options = [];
  const fetchText = async (url, opts = {}) => {
    calls.push(url);
    options.push(opts);
    const r = responses[url];
    if (r === undefined) {
      const e = new Error(`HTTP 404 fetching ${url}`);
      e.status = 404;
      throw e;
    }
    if (r instanceof Error) throw r;
    return r;
  };
  return { fetchText, calls, options, headers: () => options.map((o) => o.headers) };
}

const [ORG_URL, FAMILY_URL] = overrideCandidates('acme', 'acme');

test('fetchOverride returns null when every candidate is absent', async () => {
  const f = fakeFetch({});
  assert.equal(await fetchOverride('acme', 'acme', { fetchText: f.fetchText }), null);
  assert.deepEqual(f.calls, [ORG_URL, FAMILY_URL]);
  assert.deepEqual(f.headers(), [{}, {}], 'no token, no Authorization header');
});

test('fetchOverride stops at the org-specific file', async () => {
  const f = fakeFetch({ [ORG_URL]: 'egress_policy=block', [FAMILY_URL]: ACTIVE_FILE });
  assert.deepEqual(await fetchOverride('acme', 'acme', { fetchText: f.fetchText }), { url: ORG_URL, text: 'egress_policy=block' });
  assert.deepEqual(f.calls, [ORG_URL]);
});

test('fetchOverride falls through a 404 to the family default', async () => {
  const f = fakeFetch({ [FAMILY_URL]: ACTIVE_FILE });
  assert.deepEqual(await fetchOverride('acme', 'acme', { fetchText: f.fetchText }), { url: FAMILY_URL, text: ACTIVE_FILE });
});

test('fetchOverride reports any failure other than absence instead of moving on', async () => {
  const timeout = new Error('Timeout (deadline reached) fetching https://raw.githubusercontent.com/...');
  const f = fakeFetch({ [ORG_URL]: timeout, [FAMILY_URL]: ACTIVE_FILE });
  const r = await fetchOverride('acme', 'acme', { fetchText: f.fetchText });
  assert.equal(r.url, ORG_URL);
  assert.match(r.error, /Timeout/);
  assert.deepEqual(f.calls, [ORG_URL], 'a switch that cannot be read is not assumed absent');
});

test('fetchOverride sends the caller token as a bearer header, so a private host repo can answer', async () => {
  const f = fakeFetch({ [FAMILY_URL]: ACTIVE_FILE });
  await fetchOverride('acme', 'acme', { token: 'ghp_secret', fetchText: f.fetchText });
  assert.deepEqual(f.headers(), [
    { Authorization: 'Bearer ghp_secret' },
    { Authorization: 'Bearer ghp_secret' },
  ]);
});

test('both candidates share one deadline, so the lookup costs at most one fetch', async () => {
  const f = fakeFetch({ [FAMILY_URL]: ACTIVE_FILE });
  await fetchOverride('acme', 'acme', { fetchText: f.fetchText, deadline: 12_345 });
  assert.deepEqual(f.options.map((o) => o.deadline), [12_345, 12_345]);
});

// --- readEgressOverride --------------------------------------------------

// Read the override against temp runner files, capturing stdout. The
// DNS check has published a policy already in these files, as a stand-
// in for any earlier writer: the override must leave it alone, since
// publishing the policy is the DNS check's job. Every piece of cleanup
// sits in the finally, so a test that throws leaves nothing redirected.
async function run(inputs, responses, hostOrg = 'acme') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hrba-override-'));
  const keys = ['GITHUB_OUTPUT', 'GITHUB_ENV', 'GITHUB_STATE', 'GITHUB_STEP_SUMMARY'];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  const read = (k) => fs.readFileSync(path.join(dir, k.toLowerCase()), 'utf8');
  const f = fakeFetch(responses);
  let stdout = '';
  const out = process.stdout.write;
  try {
    for (const k of keys) {
      process.env[k] = path.join(dir, k.toLowerCase());
      fs.writeFileSync(process.env[k], '');
    }
    process.stdout.write = (s) => { stdout += s; return true; };
    const override = await readEgressOverride(
      { centralOverride: true, summary: true, workflowOrg: 'acme', token: '', ...inputs },
      hostOrg,
      { fetchText: f.fetchText, now: () => NOW },
    );
    return {
      override,
      stdout,
      calls: f.calls,
      headers: f.headers(),
      deadlines: f.options.map((o) => o.deadline),
      outputs: parseKeyValueFile(read('GITHUB_OUTPUT')),
      env: read('GITHUB_ENV'),
      state: parseKeyValueFile(read('GITHUB_STATE')),
      summary: read('GITHUB_STEP_SUMMARY'),
    };
  } finally {
    process.stdout.write = out;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const OFF_OUTPUTS = { override_active: 'false', override_until: '', override_reason: '' };

function assertPublishesNoPolicy(r) {
  assert.equal(r.outputs.egress_policy, undefined, 'the egress policy is the DNS check\'s to publish');
  assert.equal(r.env, '', 'nothing reaches GITHUB_ENV');
}

test('no override file anywhere: inactive, outputs off, no annotation', async () => {
  const r = await run({}, {});
  assert.equal(r.override.active, false);
  assert.deepEqual({ ...r.outputs }, { override_source: '', ...OFF_OUTPUTS });
  assertPublishesNoPolicy(r);
  assert.equal(r.state.egress_override, '');
  assert.match(r.stdout, /No central egress override for acme in acme\/\.github \(branch harden-runner-ops\)/);
  assert.doesNotMatch(r.stdout, /block mode/, 'an absent override claims no policy');
  assert.doesNotMatch(r.stdout, /::warning/);
  assert.equal(r.summary, '');
});

test('an active override reports itself with state, annotation and summary, and publishes no policy', async () => {
  const r = await run({}, { [FAMILY_URL]: ACTIVE_FILE });
  assert.deepEqual(r.override, {
    active: true,
    source: FAMILY_URL,
    until: TOMORROW,
    reason: 'Canonical authoritative DNS answering SERVFAIL via dns.google',
  });
  assert.equal(r.outputs.override_active, 'true');
  assert.equal(r.outputs.override_source, FAMILY_URL);
  assert.equal(r.outputs.override_until, TOMORROW);
  assert.match(r.outputs.override_reason, /^Canonical authoritative DNS/);
  assertPublishesNoPolicy(r);
  assert.equal(r.state.egress_override, 'audit');
  assert.match(r.stdout, /::warning title=Central egress override active%3A audit mode::audit mode until 2026-11-12T18:00:00Z/);
  assert.match(r.summary, /### ⚠️ Central egress override active/);
  assert.match(r.summary, /until `2026-11-12T18:00:00Z`/);
  assert.match(r.summary, /Reason: Canonical authoritative DNS/);
  assert.deepEqual(r.deadlines, [NOW + LOOKUP_TIMEOUT_MS, NOW + LOOKUP_TIMEOUT_MS], 'the lookup deadline runs from the injected clock');
});

test('the org-specific file wins over the family default', async () => {
  const r = await run({}, { [ORG_URL]: 'egress_policy=block', [FAMILY_URL]: ACTIVE_FILE });
  assert.equal(r.override.active, false);
  assert.equal(r.outputs.override_source, ORG_URL, 'the file that decided is named');
  assert.equal(r.outputs.override_active, 'false');
  assert.match(r.stdout, /present but egress_policy=block .*; not applied; the egress policy is unchanged/);
  assert.deepEqual(r.calls, [ORG_URL]);
});

test('an expired override is inactive, naming the expiry, without a warning', async () => {
  const r = await run({}, { [ORG_URL]: 'egress_policy=audit\nuntil=2026-11-11T09:00:00Z' });
  assert.equal(r.override.active, false);
  assert.equal(r.outputs.override_active, 'false');
  assertPublishesNoPolicy(r);
  assert.match(r.stdout, /present but expired at 2026-11-11T09:00:00Z/);
  assert.doesNotMatch(r.stdout, /block mode/);
  assert.doesNotMatch(r.stdout, /::warning/);
});

test('a malformed override is ignored with a warning, and claims no policy', async () => {
  const r = await run({}, { [ORG_URL]: 'egress_policy=audit\nuntil=soon' });
  assert.equal(r.override.active, false);
  assert.equal(r.outputs.override_active, 'false');
  assert.equal(r.outputs.override_source, ORG_URL, 'the file that was read is named, as for off and expired');
  assertPublishesNoPolicy(r);
  assert.match(r.stdout, /::warning title=Central egress override ignored::'until' must be a UTC time/);
  assert.match(r.stdout, /not applied; the egress policy is unchanged/);
  assert.doesNotMatch(r.stdout, /block mode/);
});

test('an unreadable override is ignored with a warning rather than assumed absent', async () => {
  const r = await run({}, { [ORG_URL]: new Error('HTTP 503 fetching ' + ORG_URL) });
  assert.equal(r.override.active, false);
  assert.equal(r.outputs.override_source, ORG_URL);
  assert.match(r.stdout, /::warning title=Central egress override ignored::could not be read: HTTP 503/);
  assert.deepEqual(r.calls, [ORG_URL]);
});

// The runner reads '##[name]' as a command anywhere in a log line, so
// nothing taken from the file may reach the log with its brackets.
const HOSTILE = [
  ['until', 'egress_policy=audit\nuntil=##[echo]on'],
  ['policy', 'egress_policy=##[stop-commands]tok'],
  ['unknown key', 'x##[echo]off=1'],
  ['line', 'x ##[add-mask]secret'],
];

for (const [what, text] of HOSTILE) {
  test(`a rejected ${what} cannot become a runner command in the log`, async () => {
    const r = await run({}, { [ORG_URL]: text });
    assert.equal(r.override.active, false);
    assert.match(r.stdout, /Central egress override ignored/);
    assert.doesNotMatch(r.stdout, /##\[/);
    assert.doesNotMatch(r.stdout, /[[\]]/);
  });
}

test('an unreadable file\'s error text is made safe too', async () => {
  const r = await run({}, { [ORG_URL]: new Error('bad ##[echo]on\nnext line') });
  assert.doesNotMatch(r.stdout, /##\[/);
  assert.match(r.stdout, /could not be read: bad ##\?echo\?on\?next line/);
});

test('safeText keeps the inert set, replaces the rest, and bounds the length', () => {
  assert.equal(safeText("ok: a-b_c (d) 'e', f; g/h #1."), "ok: a-b_c (d) 'e', f; g/h #1.");
  assert.equal(safeText('##[echo]on\r\n%0A'), '##?echo?on???0A');
  assert.equal(safeText('x'.repeat(100)).length, 40);
  assert.equal(safeText('x'.repeat(100), 60).length, 60);
});

test('warnings and the summary follow allow_list_summary; the log line does not', async () => {
  const active = await run({ summary: false }, { [ORG_URL]: ACTIVE_FILE });
  assert.equal(active.override.active, true);
  assert.doesNotMatch(active.stdout, /::warning/);
  assert.equal(active.summary, '');
  assert.match(active.stdout, /Central egress override active:/);

  const broken = await run({ summary: false }, { [ORG_URL]: 'nonsense' });
  assert.doesNotMatch(broken.stdout, /::warning/);
  assert.match(broken.stdout, /Central egress override ignored:/);
});

test('central_override: false never fetches and publishes off', async () => {
  const r = await run({ centralOverride: false }, { [ORG_URL]: ACTIVE_FILE });
  assert.equal(r.override.active, false);
  assert.deepEqual(r.calls, []);
  assert.equal(r.outputs.override_active, 'false');
  assertPublishesNoPolicy(r);
  assert.match(r.stdout, /not consulted \(central_override: false\)/);
});

test('an org name that could not form a URL is not fetched', async () => {
  const host = await run({}, {}, 'bad..org/../x');
  assert.equal(host.override.active, false);
  assert.deepEqual(host.calls, []);
  assert.match(host.stdout, /no valid org to read it from/);
  const workflow = await run({ workflowOrg: '' }, { [ORG_URL]: ACTIVE_FILE });
  assert.equal(workflow.override.active, false);
  assert.deepEqual(workflow.calls, []);
});

test('a cross-org config reads the workflow org directory in the host repo', async () => {
  // An onap workflow loading lfreleng-actions' list: onap's own
  // directory in lfreleng-actions/.github decides, so onap can stay at
  // block while the family default flips everyone else.
  const [onapUrl, familyUrl] = overrideCandidates('lfreleng-actions', 'onap');
  assert.match(onapUrl, /lfreleng-actions\/\.github\/.*\/harden-runner\/onap\/egress_override\.txt$/);
  const held = await run({ workflowOrg: 'onap' }, { [onapUrl]: 'egress_policy=block', [familyUrl]: ACTIVE_FILE }, 'lfreleng-actions');
  assert.equal(held.override.active, false);
  assert.deepEqual(held.calls, [onapUrl]);
  const flipped = await run({ workflowOrg: 'onap' }, { [familyUrl]: ACTIVE_FILE }, 'lfreleng-actions');
  assert.equal(flipped.override.active, true);
  assert.deepEqual(flipped.calls, [onapUrl, familyUrl]);
  // The host org's own directory is never consulted for another org's
  // workflow.
  const [hostOwnUrl] = overrideCandidates('lfreleng-actions', 'lfreleng-actions');
  const other = await run({ workflowOrg: 'onap' }, { [hostOwnUrl]: ACTIVE_FILE }, 'lfreleng-actions');
  assert.equal(other.override.active, false);
});

test('the caller token is masked and sent with the override read', async () => {
  const r = await run({ token: 'ghp_private' }, { [ORG_URL]: ACTIVE_FILE });
  assert.equal(r.override.active, true);
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
