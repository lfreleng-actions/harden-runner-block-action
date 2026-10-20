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
import { enforceAgentReadyPolicy, markAgentFiles, waitForAgent } from '../src/agent-ready.mjs';

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
async function runPolicy(inputs, result) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hrba-policy-'));
  const keys = ['GITHUB_OUTPUT', 'STATE_agent_files'];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  process.env.GITHUB_OUTPUT = path.join(dir, 'output');
  fs.writeFileSync(process.env.GITHUB_OUTPUT, '');
  process.env.STATE_agent_files = JSON.stringify(MARKS);

  let stdout = '';
  let stderr = '';
  let exitCode = null;
  let waiterArgs = null;
  const out = process.stdout.write;
  const errw = process.stderr.write;
  const exit = process.exit;
  process.stdout.write = (s) => { stdout += s; return true; };
  process.stderr.write = (s) => { stderr += s; return true; };
  process.exit = (code) => { exitCode = code; throw new Error('__exit__'); };
  try {
    await enforceAgentReadyPolicy(inputs, async (args) => { waiterArgs = args; return result; });
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
  return { stdout, stderr, exitCode, output, waiterArgs };
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
  assert.match(r.stdout, /::error::.*did not report ready within 120\.0 s/);
  assert.match(r.stdout, /Agent log \(tail\):\ndomain resolved: a\.example\./);
  assert.match(r.output, /^agent_status=timeout$/m, 'outputs are published before failing');
});

test('error mode fails the step on a revert, quoting the log', async () => {
  const r = await runPolicy(
    { agentTimeout: 120, agentNotReady: 'error' },
    { status: 'reverted', detail: 'Reverted changes', waitedMs: 800 },
  );
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /::error::.*reverted its changes after 0\.8 s/);
  assert.match(r.stderr, /reverted its changes/);
});

test('error mode fails the step on an agent error, quoting it', async () => {
  const r = await runPolicy(
    { agentTimeout: 120, agentNotReady: 'error' },
    { status: 'failed', detail: 'Error reading config file', waitedMs: 300 },
  );
  assert.equal(r.exitCode, 1);
  assert.match(r.stdout, /::error::.*reported an error after 0\.3 s: Error reading config file/);
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
