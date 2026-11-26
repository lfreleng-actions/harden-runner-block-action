// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Lifecycle tests: the real pre and main entry points, run as the
// runner runs them, in child processes with their own runner files.
//
// The unit suites exercise each module with its collaborators faked;
// these check what only the composition can show. The DNS check can
// end the step, so the central egress override has to be read before
// it, and the policy the job ends up with, the state main reads and
// the outputs main republishes have to agree.
//
// The network is mocked inside each child: https.request serves the
// override file (or a 404) and global fetch answers the DoH lookups,
// with names starting 'bad' NXDOMAIN and everything else resolving.
//
// Run with: node --test tests/test_pre_lifecycle.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseKeyValueFile } from '../src/actions-io.mjs';

const SRC = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');

const BOOTSTRAP = `
  import https from 'node:https';
  import { syncBuiltinESMExports } from 'node:module';
  import { EventEmitter } from 'node:events';
  import { Readable } from 'node:stream';
  import { pathToFileURL } from 'node:url';
  const body = process.env.TEST_OVERRIDE_BODY;
  https.request = (options, callback) => {
    const req = new EventEmitter();
    req.destroy = () => {};
    req.end = () => queueMicrotask(() => {
      const serve = body !== undefined && options.path.endsWith('/acme/egress_override.txt');
      const res = Readable.from(serve ? [Buffer.from(body)] : []);
      res.statusCode = serve ? 200 : 404;
      res.headers = {};
      callback(res);
    });
    return req;
  };
  syncBuiltinESMExports();
  globalThis.fetch = async (url) => {
    const bad = url.searchParams.get('name').startsWith('bad');
    return {
      ok: true,
      json: async () => (bad
        ? { Status: 3, Answer: [] }
        : { Status: 0, Answer: [{ type: 1, data: '192.0.2.1' }] }),
    };
  };
  await import(pathToFileURL(process.env.TEST_ENTRY).href);
`;

const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
const ACTIVE = `egress_policy=audit\nuntil=${iso(Date.now() + 3_600_000)}\nreason=lifecycle test\n`;

function runEntry(entry, dir, env) {
  const clean = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => !/^(INPUT_|STATE_|GITHUB_|RUNNER_)/.test(k)),
  );
  return spawnSync(process.execPath, ['--input-type=module', '--eval', BOOTSTRAP], {
    env: { ...clean, ...env, TEST_ENTRY: path.join(SRC, entry), RUNNER_TEMP: dir },
    encoding: 'utf8',
    timeout: 20_000,
  });
}

// Run pre and, when it succeeds, main, as the runner would: main gets
// pre's state as STATE_* and a fresh outputs file.
function runJob({ list, mode, override }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hrba-lifecycle-'));
  try {
    const file = (name) => path.join(dir, name);
    for (const name of ['pre_output', 'main_output', 'env', 'state', 'summary']) {
      fs.writeFileSync(file(name), '');
    }
    fs.writeFileSync(file('list'), list);
    const inputs = {
      GITHUB_REPOSITORY_OWNER: 'acme',
      GITHUB_ENV: file('env'),
      GITHUB_STATE: file('state'),
      GITHUB_STEP_SUMMARY: file('summary'),
      INPUT_ALLOW_LIST_PATH: file('list'),
      INPUT_INVALID_RECORDS: mode,
      INPUT_AGENT_TIMEOUT: '0',
      ...(override === undefined ? {} : { TEST_OVERRIDE_BODY: override }),
    };
    const pre = runEntry('pre.mjs', dir, { ...inputs, GITHUB_OUTPUT: file('pre_output') });
    const state = parseKeyValueFile(fs.readFileSync(file('state'), 'utf8'));
    const env = fs.readFileSync(file('env'), 'utf8');
    const job = { pre, state, env, envVars: parseKeyValueFile(env) };
    if (pre.status !== 0) return job;
    const stateEnv = Object.fromEntries(Object.entries(state).map(([k, v]) => [`STATE_${k}`, v]));
    job.main = runEntry('main.mjs', dir, { ...inputs, ...stateEnv, GITHUB_OUTPUT: file('main_output') });
    job.outputs = parseKeyValueFile(fs.readFileSync(file('main_output'), 'utf8'));
    return job;
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const policyLines = (env) => env.split('\n').filter((l) => l.startsWith('HARDEN_RUNNER_EGRESS_POLICY='));

test('without an override, error mode ends the step in pre', () => {
  const job = runJob({ list: 'bad.example:443 good.example:443', mode: 'error' });
  assert.equal(job.pre.status, 1, job.pre.stdout);
  assert.match(job.pre.stdout, /No central egress override for acme/);
  assert.match(job.pre.stdout, /::error::1 unresolvable allow-list entry found; failing/);
});

test('an active override keeps an error-mode job going, from pre through main', () => {
  const job = runJob({ list: 'bad.example:443 good.example:443', mode: 'error', override: ACTIVE });
  assert.equal(job.pre.status, 0, job.pre.stdout + job.pre.stderr);
  assert.match(job.pre.stdout, /not failing although invalid_records is 'error'/);
  assert.deepEqual(policyLines(job.env), ['HARDEN_RUNNER_EGRESS_POLICY=audit'], 'one policy, published once');
  assert.equal(job.envVars.CONNECTION_ALLOW_LIST, 'bad.example:443 good.example:443');
  assert.equal(job.state.egress_override, 'audit');
  assert.equal(job.main.status, 0, job.main.stdout + job.main.stderr);
  assert.equal(job.outputs.override_active, 'true');
  assert.equal(job.outputs.egress_policy, 'audit');
});

test('an active override publishes an all-invalid list unfiltered instead of refusing it', () => {
  const job = runJob({ list: 'bad.example:443', mode: 'filter', override: ACTIVE });
  assert.equal(job.pre.status, 0, job.pre.stdout + job.pre.stderr);
  assert.equal(job.envVars.CONNECTION_ALLOW_LIST, 'bad.example:443');
  assert.equal(job.envVars.HARDEN_RUNNER_EGRESS_POLICY, 'audit');
  assert.equal(job.main.status, 0);
});

test('without an override, an all-invalid list is still refused', () => {
  const job = runJob({ list: 'bad.example:443', mode: 'filter' });
  assert.equal(job.pre.status, 1);
  assert.match(job.pre.stdout, /refusing to publish an empty list/);
});

test('an inactive override leaves warning mode\'s audit in place, and says so truthfully', () => {
  const job = runJob({ list: 'bad.example:443 good.example:443', mode: 'warning', override: 'egress_policy=block\n' });
  assert.equal(job.pre.status, 0, job.pre.stdout + job.pre.stderr);
  assert.match(job.pre.stdout, /present but egress_policy=block .*not applied; the egress policy is unchanged/);
  assert.doesNotMatch(job.pre.stdout, /block mode/);
  assert.deepEqual(policyLines(job.env), ['HARDEN_RUNNER_EGRESS_POLICY=audit']);
  assert.equal(job.state.egress_override, '');
  assert.equal(job.outputs.override_active, 'false');
  assert.equal(job.outputs.egress_policy, 'audit');
});
