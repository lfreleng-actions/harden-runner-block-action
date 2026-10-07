// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Unit tests for DNS validation and the invalid_records policy.
//
// No network access: every DoH response comes from a fake fetch, so
// each verdict path (and each failure the real providers only produce
// occasionally) is exercised deterministically.
//
// Run with: node --test tests/test_dns_validate.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  applyMode,
  classifyResponse,
  hostOf,
  resolveHost,
  validateAllowList,
} from '../src/dns-validate.mjs';
import { enforceInvalidRecordsPolicy } from '../src/dns-policy.mjs';

const A = (name) => ({ Status: 0, Answer: [{ name, type: 1, data: '192.0.2.10' }] });
const CNAME_ONLY = { Status: 0, Answer: [{ type: 5, data: 'target.example.' }] };
const AAAA_ONLY = { Status: 0, Answer: [{ type: 28, data: '2001:db8::1' }] };
const NODATA = { Status: 0 };
const NXDOMAIN = { Status: 3 };
const SERVFAIL = { Status: 2 };

const noSleep = async () => {};

// A fake fetch driven by a per-provider, per-host script. Each script
// entry is a body to return, an Error for the request to reject with,
// a SyntaxError for the body to fail parsing with, or a number to
// answer as an HTTP status. The last entry repeats once the script
// runs out.
function fakeFetch(scripts) {
  const calls = [];
  const fetchImpl = async (url) => {
    const u = new URL(url);
    const host = u.searchParams.get('name');
    calls.push({ provider: u.hostname, host });
    const script = scripts[u.hostname]?.[host] ?? scripts[u.hostname]?.['*'];
    if (script === undefined) throw new Error(`no script for ${u.hostname} ${host}`);
    const seen = calls.filter((c) => c.provider === u.hostname && c.host === host).length;
    const step = script[Math.min(seen, script.length) - 1];
    if (step instanceof SyntaxError) {
      return { ok: true, status: 200, json: async () => { throw step; } };
    }
    if (step instanceof Error) throw step;
    if (typeof step === 'number') return { ok: false, status: step, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => step };
  };
  return { fetchImpl, calls };
}

const opts = (fetchImpl, extra = {}) => ({ fetchImpl, sleep: noSleep, ...extra });

test('hostOf strips ports and trailing dots, skips wildcards', () => {
  assert.equal(hostOf('GitHub.com:443'), 'github.com');
  assert.equal(hostOf('example.org.'), 'example.org');
  assert.equal(hostOf('gerrit.example.org:29418'), 'gerrit.example.org');
  assert.equal(hostOf('*.githubusercontent.com:443'), null);
});

test('classifyResponse mirrors the agent: only an A record is valid', () => {
  assert.equal(classifyResponse(A('x')).verdict, 'valid');
  // The agent fails open on all of these, so they are invalid.
  assert.equal(classifyResponse(CNAME_ONLY).verdict, 'invalid');
  assert.equal(classifyResponse(AAAA_ONLY).verdict, 'invalid');
  assert.equal(classifyResponse(NODATA).verdict, 'invalid');
  assert.match(classifyResponse(NXDOMAIN).detail, /NXDOMAIN/);
  // A server-side failure says nothing about the record: retry.
  assert.deepEqual(classifyResponse(SERVFAIL), { verdict: 'retry', detail: 'SERVFAIL' });
});

test('falls back to Cloudflare only on a Google transport failure', async () => {
  const { fetchImpl, calls } = fakeFetch({
    'dns.google': { '*': [new Error('ECONNRESET')] },
    'cloudflare-dns.com': { '*': [A('h')] },
  });
  const r = await resolveHost('h.example', opts(fetchImpl));
  assert.equal(r.verdict, 'valid');
  assert.equal(r.provider, 'cloudflare-dns.com');
  assert.deepEqual(calls.map((c) => c.provider), ['dns.google', 'cloudflare-dns.com']);
});

test('an HTTP error is retried against the same provider, without fallback', async () => {
  // The agent's http.Client.Do() succeeds on a 5xx, so it never reaches
  // Cloudflare; a Cloudflare NXDOMAIN must not decide the verdict.
  const { fetchImpl, calls } = fakeFetch({
    'dns.google': { '*': [503, A('h')] },
    'cloudflare-dns.com': { '*': [NXDOMAIN] },
  });
  const r = await resolveHost('h.example', opts(fetchImpl));
  assert.equal(r.verdict, 'valid');
  assert.equal(r.provider, 'dns.google');
  assert.ok(calls.every((c) => c.provider === 'dns.google'));
});

test('a persistent HTTP error is indeterminate', async () => {
  const { fetchImpl } = fakeFetch({
    'dns.google': { '*': [503] },
    'cloudflare-dns.com': { '*': [NXDOMAIN] },
  });
  const r = await resolveHost('gone.example', opts(fetchImpl));
  assert.equal(r.verdict, 'indeterminate');
  assert.match(r.detail, /HTTP 503/);
});

test('an unparsable body is retried, without fallback', async () => {
  const { fetchImpl, calls } = fakeFetch({
    'dns.google': { '*': [new SyntaxError('bad json')] },
    'cloudflare-dns.com': { '*': [A('h')] },
  });
  const r = await resolveHost('h.example', opts(fetchImpl));
  assert.equal(r.verdict, 'indeterminate');
  assert.match(r.detail, /unreadable response/);
  assert.ok(calls.every((c) => c.provider === 'dns.google'));
});

test('SERVFAIL is retried against the same provider, without fallback', async () => {
  const { fetchImpl, calls } = fakeFetch({
    'dns.google': { '*': [SERVFAIL, SERVFAIL, A('h')] },
    'cloudflare-dns.com': { '*': [new Error('must not be called')] },
  });
  const r = await resolveHost('h.example', opts(fetchImpl));
  assert.equal(r.verdict, 'valid');
  assert.equal(r.attempts, 3);
  assert.ok(calls.every((c) => c.provider === 'dns.google'));
});

test('a persistent SERVFAIL is indeterminate, not invalid', async () => {
  const { fetchImpl } = fakeFetch({ 'dns.google': { '*': [SERVFAIL] } });
  const r = await resolveHost('flaky.example', opts(fetchImpl));
  assert.equal(r.verdict, 'indeterminate');
  assert.match(r.detail, /SERVFAIL/);
});

test('both providers unreachable is indeterminate after every attempt', async () => {
  const { fetchImpl, calls } = fakeFetch({
    'dns.google': { '*': [new Error('ETIMEDOUT')] },
    'cloudflare-dns.com': { '*': [new Error('ETIMEDOUT')] },
  });
  const r = await resolveHost('h.example', opts(fetchImpl, { attempts: 3 }));
  assert.equal(r.verdict, 'indeterminate');
  assert.equal(calls.length, 6);
});

test('backoff grows between attempts', async () => {
  const waits = [];
  const { fetchImpl } = fakeFetch({ 'dns.google': { '*': [SERVFAIL] } });
  await resolveHost('h.example', {
    fetchImpl,
    sleep: async (ms) => waits.push(ms),
    random: () => 0.5, // jitter factor 1.0
    backoffBaseMs: 100,
    attempts: 3,
  });
  assert.deepEqual(waits, [100, 200]);
});

test('an expired deadline stops further queries', async () => {
  let clock = 0;
  const { fetchImpl, calls } = fakeFetch({ 'dns.google': { '*': [SERVFAIL] } });
  const r = await resolveHost('h.example', opts(fetchImpl, {
    now: () => clock,
    deadline: 10,
    sleep: async (ms) => { clock += ms; },
    backoffBaseMs: 100,
  }));
  assert.equal(r.verdict, 'indeterminate');
  assert.match(r.detail, /deadline/);
  assert.equal(calls.length, 1);
  // The backoff is clamped to the deadline, not slept in full.
  assert.equal(clock, 10);
});

test('no backoff is slept once the deadline has passed', async () => {
  let clock = 0;
  const waits = [];
  const { fetchImpl } = fakeFetch({ 'dns.google': { '*': [SERVFAIL] } });
  // The query itself consumes the remaining time.
  const slowFetch = async (url, init) => { clock = 50; return fetchImpl(url, init); };
  const r = await resolveHost('h.example', opts(slowFetch, {
    now: () => clock,
    deadline: 50,
    sleep: async (ms) => { waits.push(ms); clock += ms; },
  }));
  assert.equal(r.verdict, 'indeterminate');
  assert.deepEqual(waits, []);
  assert.equal(clock, 50);
});

test(".internal names are invalid without a query", async () => {
  const { fetchImpl, calls } = fakeFetch({});
  const r = await resolveHost('metadata.google.internal', opts(fetchImpl));
  assert.equal(r.verdict, 'invalid');
  assert.equal(calls.length, 0);
});

test('validateAllowList queries each host once and reports every token', async () => {
  const { fetchImpl, calls } = fakeFetch({
    'dns.google': {
      'ok.example': [A('ok.example')],
      'gone.example': [NODATA],
      'flaky.example': [SERVFAIL],
    },
  });
  const r = await validateAllowList(
    [
      'ok.example:443',
      'gone.example:443',
      'gone.example:29418',
      '*.wild.example:443',
      'flaky.example:443',
      'ok.example:80',
    ],
    opts(fetchImpl),
  );
  assert.equal(r.hostsChecked, 3);
  assert.equal(r.wildcardsSkipped, 1);
  assert.deepEqual(r.invalid.map((x) => x.token), ['gone.example:443', 'gone.example:29418']);
  assert.deepEqual(r.indeterminate.map((x) => x.token), ['flaky.example:443']);
  assert.equal(calls.filter((c) => c.host === 'gone.example').length, 1);
  // One host in three without a verdict exceeds the 25% threshold.
  assert.equal(r.degraded, true);
});

test('degraded is set only when many hosts reach no verdict', async () => {
  const hosts = Array.from({ length: 8 }, (_, i) => `h${i}.example`);
  const script = Object.fromEntries(hosts.map((h) => [h, [A(h)]]));
  script['h0.example'] = [SERVFAIL];
  const { fetchImpl } = fakeFetch({ 'dns.google': script });
  const r = await validateAllowList(hosts, opts(fetchImpl));
  assert.equal(r.indeterminate.length, 1);
  assert.equal(r.degraded, false);
});

const RESULT = {
  invalid: [{ token: 'gone.example:443', detail: 'no A record (NODATA)' }],
  indeterminate: [{ token: 'flaky.example:443', detail: 'SERVFAIL' }],
  degraded: false,
};
const TOKENS = ['ok.example:443', 'gone.example:443', 'flaky.example:443'];

test('filter drops invalid and indeterminate entries', () => {
  const o = applyMode('filter', TOKENS, RESULT);
  assert.deepEqual(o.tokens, ['ok.example:443']);
  assert.equal(o.egressPolicy, 'block');
  assert.equal(o.fail, false);
});

test('filter keeps indeterminate entries when validation is degraded', () => {
  const o = applyMode('filter', TOKENS, { ...RESULT, degraded: true });
  assert.deepEqual(o.tokens, ['ok.example:443', 'flaky.example:443']);
});

test('warning switches to audit only for invalid entries', () => {
  assert.equal(applyMode('warning', TOKENS, RESULT).egressPolicy, 'audit');
  const onlyIndeterminate = { ...RESULT, invalid: [] };
  assert.equal(applyMode('warning', TOKENS, onlyIndeterminate).egressPolicy, 'block');
  assert.deepEqual(applyMode('warning', TOKENS, RESULT).tokens, TOKENS);
});

test('error fails only for invalid entries, never for indeterminate', () => {
  assert.equal(applyMode('error', TOKENS, RESULT).fail, true);
  assert.equal(applyMode('error', TOKENS, { ...RESULT, invalid: [] }).fail, false);
});

test('ignore changes nothing', () => {
  const o = applyMode('ignore', TOKENS, RESULT);
  assert.deepEqual(o.tokens, TOKENS);
  assert.equal(o.egressPolicy, 'block');
  assert.equal(o.fail, false);
});

// Run the policy against temp runner files, capturing stdout.
async function runPolicy(inputs, result) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hrba-'));
  const files = Object.fromEntries(
    ['GITHUB_ENV', 'GITHUB_OUTPUT', 'GITHUB_STEP_SUMMARY'].map((k) => {
      const f = path.join(dir, k);
      fs.writeFileSync(f, '');
      return [k, f];
    }),
  );
  const saved = Object.fromEntries(Object.keys(files).map((k) => [k, process.env[k]]));
  Object.assign(process.env, files);
  const write = process.stdout.write;
  let stdout = '';
  process.stdout.write = (s) => { stdout += s; return true; };
  try {
    const tokens = await enforceInvalidRecordsPolicy(inputs, TOKENS, async () => ({
      hostsChecked: 3, wildcardsSkipped: 0, elapsedMs: 5, ...result,
    }));
    const read = (k) => fs.readFileSync(files[k], 'utf8');
    return {
      tokens,
      stdout,
      env: read('GITHUB_ENV'),
      output: read('GITHUB_OUTPUT'),
      summary: read('GITHUB_STEP_SUMMARY'),
    };
  } finally {
    process.stdout.write = write;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('reporting invocation writes the summary and annotations', async () => {
  const r = await runPolicy({ invalidRecords: 'filter', summary: true }, RESULT);
  assert.deepEqual(r.tokens, ['ok.example:443']);
  assert.match(r.summary, /Allow-list DNS validation/);
  assert.match(r.stdout, /::warning title=Unresolvable allow-list entries filtered::/);
  assert.match(r.stdout, /::warning title=Allow-list entries could not be validated::/);
  assert.match(r.output, /^invalid_records=gone\.example:443$/m);
  assert.match(r.output, /^invalid_count=1$/m);
  assert.match(r.output, /^indeterminate_count=1$/m);
  assert.match(r.env, /^HARDEN_RUNNER_EGRESS_POLICY=block$/m);
  // The filtered list supersedes the earlier allowed_endpoints line.
  const lines = r.output.split('\n').filter((l) => l.startsWith('allowed_endpoints='));
  assert.equal(lines.at(-1), 'allowed_endpoints=ok.example:443');
});

test('non-reporting invocations enforce silently', async () => {
  const r = await runPolicy({ invalidRecords: 'filter', summary: false }, RESULT);
  assert.deepEqual(r.tokens, ['ok.example:443']);
  assert.equal(r.summary, '');
  assert.doesNotMatch(r.stdout, /^::/m);
  assert.match(r.stdout, /invalid: gone\.example:443/);
});

test('ignore annotates but writes no summary', async () => {
  const r = await runPolicy({ invalidRecords: 'ignore', summary: true }, RESULT);
  assert.equal(r.summary, '');
  assert.match(r.stdout, /harden-runner fails open/);
});

test('warning publishes audit to the environment', async () => {
  const r = await runPolicy({ invalidRecords: 'warning', summary: true }, RESULT);
  assert.match(r.env, /^HARDEN_RUNNER_EGRESS_POLICY=audit$/m);
  assert.match(r.output, /^egress_policy=audit$/m);
  assert.deepEqual(r.tokens, TOKENS);
});

test('a clean result reports success and changes nothing', async () => {
  const r = await runPolicy(
    { invalidRecords: 'filter', summary: true },
    { invalid: [], indeterminate: [], degraded: false },
  );
  assert.deepEqual(r.tokens, TOKENS);
  assert.match(r.summary, /every hostname resolved/);
  assert.doesNotMatch(r.stdout, /^::/m);
  assert.doesNotMatch(r.output, /^allowed_endpoints=/m);
});
