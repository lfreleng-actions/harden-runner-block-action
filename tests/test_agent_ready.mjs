// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Unit tests for the wait on harden-runner's agent.
//
// The agent directory is a temp dir and the clock and sleep are fakes,
// so each path (ready, late ready, config error, revert, timeout,
// stale files from an earlier job, nothing to wait for) runs
// deterministically and in no time.
//
// Run with: node --test tests/test_agent_ready.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  enforceAgentReadyPolicy,
  markAgentFiles,
  unresolvedEndpoint,
  waitForAgent,
} from '../src/agent-ready.mjs';
import { RESTART_TIMEOUT_MS, restartInFlight, restartTimeoutMs } from '../src/agent-restart.mjs';

// A clock that advances only when the waiter sleeps. `onTick` runs
// after each sleep with the new time, so a test can make the agent
// write its files part-way through the wait.
function fakeClock(onTick = () => {}) {
  let t = 1_000_000;
  const sleeps = [];
  return {
    now: () => t,
    sleep: async (ms) => {
      sleeps.push(ms);
      t += ms;
      onTick(t);
    },
    sleeps,
  };
}

async function withAgentDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hrba-agent-'));
  try {
    return await fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const wait = (dir, clock, extra = {}) => waitForAgent({
  dir,
  platform: 'linux',
  timeoutMs: 10_000,
  pollMs: 250,
  now: clock.now,
  sleep: clock.sleep,
  ...extra,
});

test('skips when the platform has no Linux agent', async () => {
  const r = await waitForAgent({ platform: 'darwin' });
  assert.equal(r.status, 'skipped');
  assert.match(r.reason, /darwin/);
});

test('skips when harden-runner created no agent directory', async () => {
  const r = await waitForAgent({ dir: path.join(os.tmpdir(), 'hrba-no-such-dir'), platform: 'linux' });
  assert.equal(r.status, 'skipped');
  assert.match(r.reason, /did not install an agent/);
});

test('ready at once when the status file already says Initialized', async () => {
  await withAgentDir(async (dir) => {
    fs.writeFileSync(path.join(dir, 'agent.status'), 'Initialized');
    const clock = fakeClock();
    const r = await wait(dir, clock);
    assert.deepEqual(r, { status: 'ready', waitedMs: 0 });
    assert.equal(clock.sleeps.length, 0);
  });
});

test('keeps polling until the agent writes its status', async () => {
  await withAgentDir(async (dir) => {
    const clock = fakeClock((t) => {
      // The agent finishes its DNS pass 2.5 s in.
      if (t === 1_000_000 + 2_500) fs.writeFileSync(path.join(dir, 'agent.status'), 'Initialized');
    });
    const r = await wait(dir, clock);
    assert.equal(r.status, 'ready');
    assert.equal(r.waitedMs, 2_500);
    assert.equal(clock.sleeps.length, 10);
  });
});

test('reports an agent that could not read its configuration', async () => {
  await withAgentDir(async (dir) => {
    fs.writeFileSync(path.join(dir, 'agent.status'), 'Error reading config file open x: no such file');
    const r = await wait(dir, fakeClock());
    assert.equal(r.status, 'failed');
    assert.match(r.detail, /Error reading config file/);
  });
});

test('stops waiting once the agent log shows a revert', async () => {
  await withAgentDir(async (dir) => {
    const log = path.join(dir, 'agent.log');
    const clock = fakeClock((t) => {
      if (t === 1_000_000 + 1_000) {
        fs.writeFileSync(log, [
          'Error resolving allowed domain jenkins.example.org.',
          'Reverted changes',
          '',
        ].join('\n'));
      }
    });
    const r = await wait(dir, clock);
    assert.equal(r.status, 'reverted');
    assert.equal(r.waitedMs, 1_000);
    assert.match(r.detail, /jenkins\.example\.org/);
    assert.match(r.detail, /Reverted changes/);
  });
});

test('times out with the log tail when the agent never reports', async () => {
  await withAgentDir(async (dir) => {
    const lines = Array.from({ length: 30 }, (_, i) => `domain resolved: host${i}.example.`);
    fs.writeFileSync(path.join(dir, 'agent.log'), lines.join('\n'));
    const clock = fakeClock();
    const r = await wait(dir, clock);
    assert.equal(r.status, 'timeout');
    assert.equal(r.waitedMs, 10_000);
    assert.equal(clock.sleeps.length, 40);
    assert.doesNotMatch(r.detail, /host0\.example/, 'tail drops the oldest lines');
    assert.match(r.detail, /host29\.example/);
  });
});

test('times out with no detail when there is no log at all', async () => {
  await withAgentDir(async (dir) => {
    const r = await wait(dir, fakeClock());
    assert.equal(r.status, 'timeout');
    assert.equal(r.detail, '');
  });
});

// The agent opens its status file and then writes to it; a poll can
// land in between and see an empty file.
test('keeps polling while the status file exists but is empty', async () => {
  await withAgentDir(async (dir) => {
    const status = path.join(dir, 'agent.status');
    fs.writeFileSync(status, '');
    const clock = fakeClock((t) => {
      if (t === 1_000_000 + 500) fs.writeFileSync(status, 'Initialized');
    });
    const r = await wait(dir, clock);
    assert.equal(r.status, 'ready');
    assert.equal(r.waitedMs, 500);
  });
});

// The agent writes 'Initialized', keeps running, and reverts without
// removing the status file when a worker fails afterwards.
test('a revert in the log outranks an Initialized status', async () => {
  await withAgentDir(async (dir) => {
    fs.writeFileSync(path.join(dir, 'agent.status'), 'Initialized');
    fs.writeFileSync(path.join(dir, 'agent.log'), [
      'done',
      'Error in Initialization listen udp 127.0.0.1:53: bind: address already in use',
      'Reverted changes',
      '',
    ].join('\n'));
    const r = await wait(dir, fakeClock());
    assert.equal(r.status, 'reverted');
    assert.match(r.detail, /address already in use/);
  });
});

// step-security/agent run 41654001736 in lfreleng-actions/dependamerge:
// an implicit GitHub Actions endpoint hit SERVFAIL at dns.google.
const IMPLICIT_REVERT_LOG = [
  'Tue, 03 Nov 2026 14:28:31 GMT:Error resolving allowed domain error in response from dns.google unable to resolve domain productionresultssa128.blob.core.windows.net., status 2',
  'Tue, 03 Nov 2026 14:28:31 GMT:unable to resolve domain: productionresultssa128.blob.core.windows.net. err: unable to resolve domain productionresultssa128.blob.core.windows.net., status 2',
  'Tue, 03 Nov 2026 14:28:31 GMT:Reverted changes',
  '',
].join('\n');
const IMPLICIT_HOST = 'productionresultssa128.blob.core.windows.net';

test('a revert carries the endpoint the agent could not resolve', async () => {
  await withAgentDir(async (dir) => {
    fs.writeFileSync(path.join(dir, 'agent.log'), IMPLICIT_REVERT_LOG);
    const r = await wait(dir, fakeClock());
    assert.equal(r.status, 'reverted');
    assert.equal(r.endpoint, IMPLICIT_HOST);
  });
});

test('a revert whose log names no endpoint carries an empty one', async () => {
  await withAgentDir(async (dir) => {
    fs.writeFileSync(path.join(dir, 'agent.log'), 'Error in Initialization\nReverted changes\n');
    const r = await wait(dir, fakeClock());
    assert.equal(r.status, 'reverted');
    assert.equal(r.endpoint, '');
  });
});

test('unresolvedEndpoint strips the trailing dot and takes the last name', () => {
  assert.equal(unresolvedEndpoint(IMPLICIT_REVERT_LOG), IMPLICIT_HOST);
  assert.equal(unresolvedEndpoint(
    'unable to resolve domain: A.example.\nunable to resolve domain: B.Example. err: x\n',
  ), 'b.example');
  assert.equal(unresolvedEndpoint('Reverted changes\n'), '');
});

// --- persistent runners: the agent appends to files an earlier job left

test('markAgentFiles records size and inode, or zero for absent files', async () => {
  await withAgentDir(async (dir) => {
    assert.deepEqual(markAgentFiles(dir), { status: { size: 0, ino: 0 }, log: { size: 0, ino: 0 } });
    fs.writeFileSync(path.join(dir, 'agent.log'), 'old\n');
    const marks = markAgentFiles(dir);
    assert.equal(marks.log.size, 4);
    assert.ok(marks.log.ino > 0);
    assert.deepEqual(marks.status, { size: 0, ino: 0 });
  });
});

// harden-runner's isAgentInstalled() is the existence of agent.status,
// and it reuses an installed agent rather than starting another.
test('a status file that existed before pre means a reused agent: skipped', async () => {
  await withAgentDir(async (dir) => {
    const status = path.join(dir, 'agent.status');
    fs.writeFileSync(status, 'Initialized');
    const marks = markAgentFiles(dir);
    const clock = fakeClock();
    const r = await wait(dir, clock, { marks });
    assert.equal(r.status, 'skipped');
    assert.match(r.reason, /reuses an installed agent/);
    assert.equal(clock.sleeps.length, 0);
  });
});

test("an earlier job's revert does not fail this job once the log grows", async () => {
  await withAgentDir(async (dir) => {
    const log = path.join(dir, 'agent.log');
    const status = path.join(dir, 'agent.status');
    fs.writeFileSync(log, 'Error resolving allowed domain old.example.\nReverted changes\n');
    const marks = markAgentFiles(dir);
    const clock = fakeClock((t) => {
      // This job's agent appends to the same log, then reports ready.
      if (t === 1_000_000 + 250) fs.appendFileSync(log, 'domain resolved: a.example.\n');
      if (t === 1_000_000 + 750) fs.writeFileSync(status, 'Initialized');
    });
    const r = await wait(dir, clock, { marks });
    assert.equal(r.status, 'ready');
    assert.equal(r.waitedMs, 750);
  });
});

test("an earlier job's revert alone is no verdict for this job", async () => {
  await withAgentDir(async (dir) => {
    fs.writeFileSync(path.join(dir, 'agent.log'), 'Reverted changes\n');
    const marks = markAgentFiles(dir);
    const r = await wait(dir, fakeClock(), { marks });
    assert.equal(r.status, 'timeout');
    assert.equal(r.detail, '', 'nothing of this job\'s is quoted');
  });
});

test("this job's revert is seen when it follows an earlier job's log", async () => {
  await withAgentDir(async (dir) => {
    const log = path.join(dir, 'agent.log');
    fs.writeFileSync(log, 'done\n');
    const marks = markAgentFiles(dir);
    const clock = fakeClock((t) => {
      if (t === 1_000_000 + 250) fs.appendFileSync(log, 'Error resolving allowed domain new.example.\nReverted changes\n');
    });
    const r = await wait(dir, clock, { marks });
    assert.equal(r.status, 'reverted');
    assert.doesNotMatch(r.detail, /^done$/m, 'only this job\'s lines are quoted');
    assert.match(r.detail, /new\.example/);
  });
});

test('a log truncated or replaced since pre is read from the start', async () => {
  await withAgentDir(async (dir) => {
    const log = path.join(dir, 'agent.log');
    fs.writeFileSync(log, 'a long log from an earlier job that said nothing of note\n');
    const marks = markAgentFiles(dir);
    // Truncated: shorter than the mark, so the offset no longer applies.
    fs.writeFileSync(log, 'Reverted changes\n');
    let r = await wait(dir, fakeClock(), { marks });
    assert.equal(r.status, 'reverted');
    // Replaced: a new inode, although the file is longer than the mark.
    // Written beside the old file and renamed over it, so the two
    // inodes are guaranteed to differ.
    const fresh = path.join(dir, 'agent.log.new');
    const lines = Array.from({ length: 5 }, (_, i) => `domain resolved: host${i}.example.`);
    fs.writeFileSync(fresh, `${lines.join('\n')}\nReverted changes\n`);
    fs.renameSync(fresh, log);
    r = await wait(dir, fakeClock(), { marks });
    assert.equal(r.status, 'reverted');
    assert.match(r.detail, /host0\.example/, 'the whole replaced file counts');
  });
});

// --- enforceAgentReadyPolicy -------------------------------------------

const MARKS = { status: { size: 0, ino: 0 }, log: { size: 2048, ino: 43 } };

// Run the policy with runner files in a temp dir, a fake waiter, and
// stdout captured. process.exit is stubbed so 'error' mode can be
// observed rather than ending the test process.
// `env` sets further variables for the run, and `outputs` is what the
// outputs file already holds, as it does once main has republished
// pre's outputs.
//
// `result` is what the waiter returns, or an array of what each
// successive wait returns (the last repeats). Restarts never reach
// systemd: `restart` is a fake, by default one that succeeds at once,
// and every call is recorded with the clock and the command timeout
// it was given. The clock advances by each wait's waitedMs and by
// whatever `restart` adds through its `advance` argument. `mark`
// returns the fresh marks, and may advance the clock the same way.
const FRESH_MARKS = { status: { size: 11, ino: 7 }, log: { size: 4096, ino: 43 } };

async function runPolicy(inputs, result, { env = {}, outputs = '', restart = () => {}, mark = () => {} } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hrba-policy-'));
  const keys = ['GITHUB_OUTPUT', 'STATE_agent_files', 'CONNECTION_ALLOW_LIST', ...Object.keys(env)];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  process.env.GITHUB_OUTPUT = path.join(dir, 'output');
  fs.writeFileSync(process.env.GITHUB_OUTPUT, outputs);
  process.env.STATE_agent_files = JSON.stringify(MARKS);
  delete process.env.CONNECTION_ALLOW_LIST;
  Object.assign(process.env, env);

  let stdout = '';
  let stderr = '';
  let exitCode = null;
  let waiterArgs = null;
  const waits = [];
  const restarts = [];
  const results = Array.isArray(result) ? result : [result];
  let t = 0;
  const out = process.stdout.write;
  const errw = process.stderr.write;
  const exit = process.exit;
  process.stdout.write = (s) => { stdout += s; return true; };
  process.stderr.write = (s) => { stderr += s; return true; };
  process.exit = (code) => { exitCode = code; throw new Error('__exit__'); };
  try {
    await enforceAgentReadyPolicy(
      inputs,
      async (args) => {
        if (waiterArgs === null) waiterArgs = args;
        waits.push({ ...args, at: t });
        const r = results[Math.min(waits.length - 1, results.length - 1)];
        t += r?.waitedMs ?? 0;
        return r;
      },
      {
        restart: (remainingMs) => {
          restarts.push({ at: t, remainingMs });
          restart((ms) => { t += ms; }, remainingMs);
        },
        mark: () => {
          mark((ms) => { t += ms; });
          return FRESH_MARKS;
        },
        now: () => t,
      },
    );
  } catch (e) {
    if (e.message !== '__exit__') throw e;
  } finally {
    process.stdout.write = out;
    process.stderr.write = errw;
    process.exit = exit;
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  const output = fs.readFileSync(path.join(dir, 'output'), 'utf8');
  fs.rmSync(dir, { recursive: true, force: true });
  return { stdout, stderr, exitCode, output, waiterArgs, waits, restarts };
}

test('agent_timeout 0 disables the wait without calling the waiter', async () => {
  const r = await runPolicy({ agentTimeout: 0, agentNotReady: 'error' });
  assert.equal(r.waiterArgs, null);
  assert.equal(r.exitCode, null);
  assert.match(r.output, /^agent_status=disabled$/m);
  assert.match(r.output, /^agent_wait_ms=0$/m);
});

test('passes the timeout and the file marks from pre to the waiter', async () => {
  const r = await runPolicy(
    { agentTimeout: 45, agentNotReady: 'error' },
    { status: 'ready', waitedMs: 1_200 },
  );
  assert.deepEqual(r.waiterArgs, { timeoutMs: 45_000, marks: MARKS });
  assert.equal(r.exitCode, null);
  assert.match(r.output, /^agent_status=ready$/m);
  assert.match(r.output, /^agent_wait_ms=1200$/m);
  assert.match(r.stdout, /enforcement in place after 1200 ms/);
});

test('a skipped wait publishes its reason and passes', async () => {
  const r = await runPolicy(
    { agentTimeout: 120, agentNotReady: 'error' },
    { status: 'skipped', reason: 'no agent', waitedMs: 0 },
  );
  assert.equal(r.exitCode, null);
  assert.match(r.output, /^agent_status=skipped$/m);
  assert.doesNotMatch(r.stdout, /::warning/);
});

test('error mode fails the step on a timeout', async () => {
  const r = await runPolicy(
    { agentTimeout: 120, agentNotReady: 'error' },
    { status: 'timeout', detail: 'domain resolved: a.example.', waitedMs: 120_000 },
  );
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /::error title=harden-runner agent did not start::.*did not report ready within 120\.0 s/);
  assert.match(r.stdout, /Agent log \(tail\):\ndomain resolved: a\.example\./);
  assert.match(r.output, /^agent_status=timeout$/m, 'outputs are published before failing');
});

test('error mode fails the step on a revert, quoting the log', async () => {
  const r = await runPolicy(
    { agentTimeout: 120, agentNotReady: 'error' },
    { status: 'reverted', detail: 'Reverted changes', waitedMs: 800 },
  );
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /::error title=harden-runner agent did not start::.*reverted its changes after 0\.8 s/);
  assert.match(r.stderr, /reverted its changes/);
});

test('error mode fails the step on an agent error, quoting it', async () => {
  const r = await runPolicy(
    { agentTimeout: 120, agentNotReady: 'error' },
    { status: 'failed', detail: 'Error reading config file', waitedMs: 300 },
  );
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /::error title=harden-runner agent did not start::.*reported an error after 0\.3 s: Error reading config file/);
  assert.doesNotMatch(r.stdout, /Agent log \(tail\)/, 'the status text is the whole detail');
});

test('warning mode annotates and continues', async () => {
  const r = await runPolicy(
    { agentTimeout: 120, agentNotReady: 'warning' },
    { status: 'timeout', detail: '', waitedMs: 120_000 },
  );
  assert.equal(r.exitCode, null);
  assert.match(r.stdout, /::warning title=harden-runner agent did not start::/);
  assert.match(r.stdout, /continuing because agent_not_ready is 'warning'/);
  assert.doesNotMatch(r.stdout, /::error/);
  assert.match(r.output, /^agent_status=timeout$/m);
});

// --- revert diagnoses ---------------------------------------------------

const ERROR_INPUTS = { agentTimeout: 120, agentNotReady: 'error', envVarName: 'CONNECTION_ALLOW_LIST' };
const IMPLICIT_RESULT = {
  status: 'reverted', detail: IMPLICIT_REVERT_LOG.trim(), endpoint: IMPLICIT_HOST, waitedMs: 0,
};

test('a revert on an implicit endpoint names it and says to re-run', async () => {
  const r = await runPolicy(ERROR_INPUTS, IMPLICIT_RESULT, {
    env: { CONNECTION_ALLOW_LIST: 'github.com:443 *.blob.core.windows.net:443 pypi.org:443' },
  });
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /::error title=harden-runner agent did not start::.*reverted its changes after 0\.0 s/);
  assert.match(r.stdout, /productionresultssa128\.blob\.core\.windows\.net, which is not in the allow-list/);
  assert.match(r.stdout, /harden-runner adds it itself/);
  assert.match(r.stdout, /no allow-list entry caused the revert/);
  assert.match(r.stdout, /re-run the job/);
  assert.ok(
    r.output.split('\n').includes(`agent_unresolved_endpoint=${IMPLICIT_HOST}`),
    r.output,
  );
});

test('a revert on a listed endpoint calls it a transient failure', async () => {
  const r = await runPolicy(ERROR_INPUTS, IMPLICIT_RESULT, {
    env: { CONNECTION_ALLOW_LIST: `github.com:443 ${IMPLICIT_HOST}:443` },
  });
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /productionresultssa128\.blob\.core\.windows\.net, an allow-list entry that resolved/);
  assert.match(r.stdout, /transient resolver failure rather than a stale entry/);
  assert.doesNotMatch(r.stdout, /adds it itself/);
});

test('a revert on an entry the pre-check also failed on says so', async () => {
  const r = await runPolicy(ERROR_INPUTS, IMPLICIT_RESULT, {
    env: { CONNECTION_ALLOW_LIST: `github.com:443 ${IMPLICIT_HOST}:443` },
    outputs: `invalid_records=${IMPLICIT_HOST}:443\n`,
  });
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /pre-check could not resolve either/);
  assert.doesNotMatch(r.stdout, /transient/);
});

test('without the env var the allowed_endpoints output is the list', async () => {
  const r = await runPolicy(ERROR_INPUTS, IMPLICIT_RESULT, {
    outputs: `allowed_endpoints=${IMPLICIT_HOST}:443\n`,
  });
  assert.match(r.stdout, /an allow-list entry that resolved/);
});

test('a revert naming no endpoint keeps the plain message', async () => {
  const r = await runPolicy(ERROR_INPUTS, { status: 'reverted', detail: 'Reverted changes', endpoint: '', waitedMs: 800 }, {
    env: { CONNECTION_ALLOW_LIST: 'github.com:443' },
  });
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /::error title=harden-runner agent did not start::.*the job has no egress filtering ❌$/m);
  assert.doesNotMatch(r.stdout, /could not resolve/);
  assert.match(r.output, /^agent_unresolved_endpoint=$/m);
});

test('warning mode annotates with the same diagnosis and continues', async () => {
  const r = await runPolicy({ ...ERROR_INPUTS, agentNotReady: 'warning' }, IMPLICIT_RESULT, {
    env: { CONNECTION_ALLOW_LIST: 'github.com:443' },
  });
  assert.equal(r.exitCode, null);
  assert.match(r.stdout, /::warning title=harden-runner agent did not start::.*harden-runner adds it itself/);
  assert.match(r.stdout, /continuing because agent_not_ready is 'warning'/);
});

test('outputs carry no endpoint unless the agent reverted', async () => {
  const r = await runPolicy(ERROR_INPUTS, { status: 'ready', waitedMs: 5 });
  assert.match(r.output, /^agent_unresolved_endpoint=$/m);
  const d = await runPolicy({ ...ERROR_INPUTS, agentTimeout: 0 });
  assert.match(d.output, /^agent_unresolved_endpoint=$/m);
});

// --- restarting the agent after a transient revert ----------------------

const IMPLICIT_ENV = { env: { CONNECTION_ALLOW_LIST: 'github.com:443' } };
const READY = { status: 'ready', waitedMs: 9_000 };
const revertAfter = (waitedMs) => ({ ...IMPLICIT_RESULT, waitedMs });

test('a revert then Initialized after one restart ends ready', async () => {
  const r = await runPolicy(ERROR_INPUTS, [revertAfter(10_000), READY], IMPLICIT_ENV);
  assert.equal(r.exitCode, null);
  assert.equal(r.restarts.length, 1);
  assert.match(r.output, /^agent_status=ready$/m);
  assert.match(r.output, /^agent_restarts=1$/m);
  assert.match(r.output, /^agent_wait_ms=19000$/m, 'both waits count');
  assert.match(r.output, /^agent_unresolved_endpoint=$/m);
  assert.ok(
    r.stdout.includes(`could not resolve ${IMPLICIT_HOST} (implicit); restarting it, attempt 1 of 2`),
    r.stdout,
  );
  assert.match(r.stdout, /enforcement in place after 19000 ms after 1 restart\(s\)/);
  assert.doesNotMatch(r.stdout, /::error|::warning/);
});

test('the wait after a restart takes fresh marks and no reused-agent skip', async () => {
  const r = await runPolicy(ERROR_INPUTS, [revertAfter(10_000), READY], IMPLICIT_ENV);
  assert.deepEqual(r.waits[0], { timeoutMs: 120_000, marks: MARKS, at: 0 });
  assert.deepEqual(r.waits[1], { timeoutMs: 110_000, marks: FRESH_MARKS, restarted: true, at: 10_000 });
});

test('a listed or unknown endpoint is retried too', async () => {
  const listed = await runPolicy(ERROR_INPUTS, [revertAfter(1_000), READY], {
    env: { CONNECTION_ALLOW_LIST: `github.com:443 ${IMPLICIT_HOST}:443` },
  });
  assert.match(listed.stdout, /\(listed\); restarting it/);
  assert.match(listed.output, /^agent_restarts=1$/m);
  const unknown = await runPolicy(ERROR_INPUTS, [revertAfter(1_000), READY]);
  assert.match(unknown.stdout, /\(unknown\); restarting it/);
  assert.match(unknown.output, /^agent_status=ready$/m);
});

test('a revert on a flagged endpoint restarts nothing', async () => {
  const r = await runPolicy(ERROR_INPUTS, [revertAfter(1_000), READY], {
    env: { CONNECTION_ALLOW_LIST: `github.com:443 ${IMPLICIT_HOST}:443` },
    outputs: `invalid_records=${IMPLICIT_HOST}:443\n`,
  });
  assert.equal(r.restarts.length, 0);
  assert.equal(r.exitCode, 1);
  assert.match(r.output, /^agent_restarts=0$/m);
  assert.doesNotMatch(r.stdout, /restart/);
});

test('a revert naming no endpoint restarts nothing', async () => {
  const r = await runPolicy(ERROR_INPUTS, [{ status: 'reverted', detail: 'Reverted changes', endpoint: '', waitedMs: 800 }, READY]);
  assert.equal(r.restarts.length, 0);
  assert.equal(r.exitCode, 1);
});

test('attempts spent ends failed with the count in the message', async () => {
  const r = await runPolicy(ERROR_INPUTS, revertAfter(1_000), IMPLICIT_ENV);
  assert.equal(r.restarts.length, 2);
  assert.equal(r.waits.length, 3);
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /::error title=harden-runner agent did not start::harden-runner's agent reverted its changes after 3\.0 s/);
  assert.match(r.stdout, /still not ready after 2 restart\(s\) ❌$/m);
  assert.match(r.output, /^agent_status=reverted$/m);
  assert.match(r.output, /^agent_restarts=2$/m);
  assert.match(r.output, /^agent_wait_ms=3000$/m);
});

test('warning mode annotates after the attempts are spent and continues', async () => {
  const r = await runPolicy({ ...ERROR_INPUTS, agentNotReady: 'warning' }, revertAfter(1_000), IMPLICIT_ENV);
  assert.equal(r.exitCode, null);
  assert.equal(r.restarts.length, 2);
  assert.match(r.stdout, /::warning title=harden-runner agent did not start::.*after 2 restart\(s\)/);
});

test('agent_restart_attempts 0 restarts nothing', async () => {
  const r = await runPolicy({ ...ERROR_INPUTS, agentRestartAttempts: 0 }, [revertAfter(800), READY], IMPLICIT_ENV);
  assert.equal(r.restarts.length, 0);
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /reverted its changes after 0\.8 s .*re-run the job ❌$/m);
  assert.doesNotMatch(r.stdout, /restart/);
  assert.match(r.output, /^agent_restarts=0$/m);
});

test('agent_restart_attempts sets the number of restarts', async () => {
  const r = await runPolicy({ ...ERROR_INPUTS, agentRestartAttempts: 3 }, revertAfter(1_000), IMPLICIT_ENV);
  assert.equal(r.restarts.length, 3);
  assert.match(r.stdout, /attempt 3 of 3/);
});

test('the deadline is shared: a late restart gets only what remains', async () => {
  // Reverts 100 s into a 120 s window; the restart itself takes 5 s.
  const r = await runPolicy(
    ERROR_INPUTS,
    [revertAfter(100_000), { status: 'timeout', detail: '', waitedMs: 15_000 }],
    { ...IMPLICIT_ENV, restart: (advance) => advance(5_000) },
  );
  assert.equal(r.restarts.length, 1, 'a timeout is not retried');
  assert.equal(r.waits[1].timeoutMs, 15_000);
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /did not report ready within 120\.0 s; the job may have no egress filtering; still not ready after 1 restart\(s\)/);
  assert.match(r.output, /^agent_wait_ms=120000$/m);
});

// What execFileSync throws when it kills a command at its timeout.
const timedOut = () => Object.assign(new Error('spawnSync sudo ETIMEDOUT'), { code: 'ETIMEDOUT', signal: 'SIGTERM', status: null });
const TIMEOUT = { status: 'timeout', detail: '', waitedMs: 0 };

test('a restart near the deadline gets only the time that remains', async () => {
  // Reverts 110 s into a 120 s window: the restart command is given
  // 10 s rather than its usual 15 s, uses all of it and times out.
  // systemd may still be running it, so the agent files get one last
  // look with no time left, and no further restart follows.
  const r = await runPolicy(ERROR_INPUTS, [revertAfter(110_000), TIMEOUT], {
    ...IMPLICIT_ENV,
    restart: (advance, remainingMs) => {
      advance(remainingMs);
      throw timedOut();
    },
  });
  assert.deepEqual(r.restarts, [{ at: 110_000, remainingMs: 10_000 }]);
  assert.equal(r.waits.length, 2);
  assert.deepEqual(r.waits[1], { timeoutMs: 0, marks: FRESH_MARKS, restarted: true, at: 120_000 });
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /did not report ready within 120\.0 s; .*still not ready after 1 restart\(s\) ❌$/m);
  assert.match(r.output, /^agent_status=timeout$/m);
  assert.match(r.output, /^agent_wait_ms=120000$/m);
});

test('a restart that times out at the client but completes in systemd ends ready', async () => {
  // The client is killed after 15 s, but systemd runs the queued job
  // and the agent comes up: the step waits for it, with the marks taken
  // before the restart and the deadline unchanged, and restarts nothing
  // more.
  const r = await runPolicy(ERROR_INPUTS, [revertAfter(1_000), READY], {
    ...IMPLICIT_ENV,
    restart: (advance, remainingMs) => {
      advance(Math.min(15_000, remainingMs));
      throw timedOut();
    },
  });
  assert.equal(r.restarts.length, 1, 'no second restart over an in-flight one');
  assert.equal(r.waits.length, 2);
  assert.deepEqual(r.waits[1], { timeoutMs: 104_000, marks: FRESH_MARKS, restarted: true, at: 16_000 });
  assert.equal(r.exitCode, null);
  assert.match(r.stdout, /systemd may still be restarting harden-runner's agent, so waiting for it rather than restarting it again/);
  assert.doesNotMatch(r.stdout, /Restarting harden-runner's agent failed/);
  assert.match(r.output, /^agent_status=ready$/m);
  assert.match(r.output, /^agent_restarts=1$/m);
  assert.match(r.output, /^agent_wait_ms=25000$/m);
});

test('a revert after a timed-out restart may be retried, the job having run', async () => {
  let calls = 0;
  const r = await runPolicy(ERROR_INPUTS, [revertAfter(1_000), revertAfter(1_000), READY], {
    ...IMPLICIT_ENV,
    restart: (advance) => {
      calls += 1;
      if (calls === 1) {
        advance(15_000);
        throw timedOut();
      }
    },
  });
  assert.equal(r.restarts.length, 2);
  assert.equal(r.waits.length, 3);
  assert.equal(r.exitCode, null);
  assert.match(r.output, /^agent_status=ready$/m);
});

test('restartInFlight separates a killed client from a definite failure', () => {
  assert.equal(restartInFlight(timedOut()), true);
  assert.equal(restartInFlight(Object.assign(new Error('killed'), { signal: 'SIGKILL', status: null })), true);
  assert.equal(restartInFlight(Object.assign(new Error('exit 1'), { signal: null, status: 1 })), false);
  assert.equal(restartInFlight(Object.assign(new Error('spawnSync sudo ENOENT'), { code: 'ENOENT', signal: null, status: null })), false);
  assert.equal(restartInFlight(new Error('sudo: a password is required')), false);
});

test('the restart command timeout is capped at the time remaining', () => {
  assert.equal(RESTART_TIMEOUT_MS, 15_000);
  assert.equal(restartTimeoutMs(10_000), 10_000);
  assert.equal(restartTimeoutMs(60_000), 15_000);
  assert.equal(restartTimeoutMs(0), 1);
});

test('no restart once the window is spent', async () => {
  const r = await runPolicy(ERROR_INPUTS, [revertAfter(120_000), READY], IMPLICIT_ENV);
  assert.equal(r.restarts.length, 0);
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /No time left within agent_timeout/);
  assert.match(r.output, /^agent_restarts=0$/m);
});

test('no restart when marking the files spends what remains', async () => {
  // Reverts 119 s into a 120 s window, and taking the marks takes the
  // last second: no restart is dispatched or counted.
  const r = await runPolicy(ERROR_INPUTS, [revertAfter(119_000), READY], {
    ...IMPLICIT_ENV,
    mark: (advance) => advance(1_000),
  });
  assert.equal(r.restarts.length, 0);
  assert.equal(r.waits.length, 1);
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /No time left within agent_timeout/);
  assert.doesNotMatch(r.stdout, /attempt 1 of/);
  assert.match(r.output, /^agent_restarts=0$/m);
});

test('a restart command that fails counts as a spent attempt', async () => {
  const r = await runPolicy(ERROR_INPUTS, [revertAfter(1_000), READY], {
    ...IMPLICIT_ENV,
    restart: () => { throw new Error('sudo: a password is required'); },
  });
  assert.equal(r.restarts.length, 2);
  assert.equal(r.waits.length, 1, 'no wait follows a failed restart');
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /Restarting harden-runner's agent failed: sudo: a password is required/);
  assert.match(r.stdout, /still not ready after 2 restart\(s\) ❌$/m);
  assert.match(r.output, /^agent_restarts=2$/m);
});

test('a timeout or failed outcome restarts nothing', async () => {
  const timeout = await runPolicy(ERROR_INPUTS, [{ status: 'timeout', detail: '', waitedMs: 120_000 }, READY]);
  assert.equal(timeout.restarts.length, 0);
  assert.equal(timeout.exitCode, 1);
  assert.match(timeout.output, /^agent_restarts=0$/m);
  const failed = await runPolicy(ERROR_INPUTS, [{ status: 'failed', detail: 'Error reading config file', waitedMs: 300 }, READY]);
  assert.equal(failed.restarts.length, 0);
  assert.equal(failed.exitCode, 1);
  assert.match(failed.stdout, /::error title=harden-runner agent did not start::harden-runner's agent reported an error/);
});

test('a revert after a restart on a flagged endpoint stops the retries', async () => {
  const flagged = { ...IMPLICIT_RESULT, endpoint: 'stale.example', waitedMs: 1_000 };
  const r = await runPolicy(ERROR_INPUTS, [revertAfter(1_000), flagged], {
    env: { CONNECTION_ALLOW_LIST: 'github.com:443 stale.example:443' },
    outputs: 'invalid_records=stale.example:443\n',
  });
  assert.equal(r.restarts.length, 1);
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /stale\.example, an allow-list entry that this action's pre-check could not resolve either/);
  assert.match(r.output, /^agent_unresolved_endpoint=stale\.example$/m);
});

test('outputs carry agent_restarts 0 when the wait is disabled', async () => {
  const r = await runPolicy({ ...ERROR_INPUTS, agentTimeout: 0 });
  assert.match(r.output, /^agent_restarts=0$/m);
});

// A restart this action made is not a reused agent, even though the
// earlier start left an 'Initialized' in the status file.
test('after a restart a pre-existing status file does not skip the wait', async () => {
  await withAgentDir(async (dir) => {
    const status = path.join(dir, 'agent.status');
    fs.writeFileSync(status, 'Initialized');
    const marks = markAgentFiles(dir);
    const clock = fakeClock((t) => {
      if (t === 1_000_000 + 500) fs.appendFileSync(status, 'Initialized');
    });
    const r = await wait(dir, clock, { marks, restarted: true });
    assert.equal(r.status, 'ready');
    assert.equal(r.waitedMs, 500);
  });
});
