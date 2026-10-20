// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Wait for step-security/harden-runner's agent to report that egress
// enforcement is in place, and apply the 'agent_not_ready' policy.
//
// harden-runner's pre hook installs its agent as a systemd service and
// then polls for /home/agent/agent.status thirty times, 300 ms apart.
// When the file has not appeared after those nine seconds it logs
// 'timed out' and returns success, and the job's main steps begin.
//
// In block mode the agent resolves every non-wildcard allowed endpoint,
// then switches the runner's DNS and installs its firewall rules, and
// writes that file after all of it is done. With a shared organisation
// allow-list of a hundred and fifty hostnames the resolving alone takes
// nine to ten seconds, so harden-runner's wait expires on EVERY run,
// and the first main step to open a connection races the agent: a
// request sent before the switch succeeds, one sent during the
// systemd-resolved and Docker restarts fails with a bare 'fetch
// failed', and one sent after is filtered as intended. Which of the
// three a run gets is a matter of milliseconds.
//
// This module closes the window. The loader's main step runs after
// every pre hook and before any other main step, so it is the one
// place every consumer of this action already has between
// harden-runner's pre hook and the first step that uses the network.
// It waits for the status file with a timeout long enough for any
// allow-list, and stops early when the agent log shows the agent gave
// up. The policy input decides what a job does when enforcement never
// arrives: the default fails it, because a job that runs with no
// egress filtering while every step reports success is the outcome
// this action exists to prevent.
//
// The agent is Linux-only in the form watched here (the Windows agent
// keeps its status file under a directory harden-runner saves in its
// own state, which this action cannot read). Elsewhere, and whenever
// harden-runner never created the agent directory -- no harden-runner
// step, or the StepSecurity API declined to monitor the run -- there
// is nothing to wait for and the step says so.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { annotate, fail, info, setOutput } from './actions-io.mjs';

export const AGENT_DIR = '/home/agent';
export const AGENT_MODES = Object.freeze(['error', 'warning']);

// The agent writes exactly this when enforcement is in place, and an
// error description instead when it cannot read its configuration.
export const READY_MARKER = 'Initialized';
// Logged by the agent after it undid its changes, just before exiting.
export const REVERTED_MARKER = 'Reverted changes';

export const DEFAULTS = Object.freeze({
  timeoutMs: 120_000,
  pollMs: 250,
});

const LOG_TAIL_LINES = 20;

const defaultSleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Read what the agent has written to a file during THIS job. Both
// files are opened O_APPEND, so on a persistent runner an earlier
// job's 'Initialized' or 'Reverted changes' is still there, and a
// modification time cannot separate the two: one new line makes the
// whole file fresh. Pre therefore records each file's size and inode
// before harden-runner's pre hook can start the agent, and main reads
// from that offset. A file that is smaller than its mark, or has a
// different inode, has been truncated or replaced since, so all of it
// is this job's. The size, identity and read all come from one open
// descriptor, so they describe the same file, and only the bytes past
// the mark are read: an accumulated log is not re-read on every poll.
// Returns null while the file does not exist.
function readSince(file, mark) {
  let fd;
  try {
    fd = fs.openSync(file, 'r');
  } catch {
    return null;
  }
  try {
    const stat = fs.fstatSync(fd);
    const sameFile = mark && stat.ino === mark.ino && stat.size >= mark.size;
    const offset = sameFile ? mark.size : 0;
    const buffer = Buffer.alloc(stat.size - offset);
    const read = fs.readSync(fd, buffer, 0, buffer.length, offset);
    return buffer.toString('utf8', 0, read);
  } catch {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

// Where each agent file ends right now, for readSince() in main. An
// absent file, the normal case on a fresh runner, gets a zero mark.
export function markAgentFiles(dir = AGENT_DIR) {
  const mark = (name) => {
    try {
      const { size, ino } = fs.statSync(path.join(dir, name));
      return { size, ino };
    } catch {
      return { size: 0, ino: 0 };
    }
  };
  return { status: mark('agent.status'), log: mark('agent.log') };
}

export const MARKS_STATE = 'agent_files';

function parseMarks(text) {
  try {
    const parsed = JSON.parse(text);
    if (parsed && parsed.status && parsed.log) return parsed;
  } catch {
    // fall through
  }
  return null;
}

function tail(text) {
  const lines = text.split('\n').filter(Boolean);
  return lines.slice(-LOG_TAIL_LINES).join('\n');
}

// Poll for the agent's verdict. Resolves to one of:
//
//   { status: 'skipped',  reason }  nothing to wait for
//   { status: 'ready' }             enforcement is in place
//   { status: 'failed',   detail }  the agent reported an error
//   { status: 'reverted', detail }  the agent undid its changes
//   { status: 'timeout',  detail }  no verdict before the deadline
//
// each with waitedMs. `marks` is what markAgentFiles() returned in pre;
// without it the whole of each file counts as this job's. The clock
// and sleep are injectable so the tests run in no time.
//
// A status file that already existed when pre ran means harden-runner
// starts no agent: its isAgentInstalled() test is that same file's
// existence, and on a self-hosted runner, a custom VM image or a
// hosted runner carrying an installed agent it reuses the agent it
// finds rather than installing another. Whatever harden-runner reused
// wrote its verdict before this job began, so there is nothing new to
// wait for and the wait is skipped, as it is without an agent
// directory. The log mark still matters: a previous job's agent that
// reverted left a log but no status file, so harden-runner does
// install, and the old 'Reverted changes' must not count.
//
// The revert check comes first: the agent writes 'Initialized' and
// then keeps running, and when a worker fails afterwards it reverts
// without removing the status file. Had enforcement come and gone
// before main looked, a status-first check would call the job ready.
// An empty status file is not a verdict either: the agent creates the
// file and then writes to it, and a poll can land between the two.
export async function waitForAgent({
  timeoutMs = DEFAULTS.timeoutMs,
  marks = null,
  dir = AGENT_DIR,
  platform = process.platform,
  pollMs = DEFAULTS.pollMs,
  now = Date.now,
  sleep = defaultSleep,
} = {}) {
  if (platform !== 'linux') {
    return { status: 'skipped', reason: `no Linux agent on ${platform}`, waitedMs: 0 };
  }
  if (!fs.existsSync(dir)) {
    return { status: 'skipped', reason: `${dir} absent: harden-runner did not install an agent`, waitedMs: 0 };
  }
  if (marks?.status?.size > 0) {
    return {
      status: 'skipped',
      reason: 'agent.status existed before this job began: harden-runner reuses an installed agent rather than starting one',
      waitedMs: 0,
    };
  }

  const statusFile = path.join(dir, 'agent.status');
  const logFile = path.join(dir, 'agent.log');
  const started = now();
  const deadline = started + timeoutMs;

  for (;;) {
    const waitedMs = now() - started;
    const log = readSince(logFile, marks?.log) ?? '';
    if (log.includes(REVERTED_MARKER)) {
      return { status: 'reverted', detail: tail(log), waitedMs };
    }
    const status = (readSince(statusFile, marks?.status) ?? '').trim();
    if (status !== '') {
      if (status.startsWith(READY_MARKER)) return { status: 'ready', waitedMs };
      return { status: 'failed', detail: status, waitedMs };
    }
    if (now() >= deadline) {
      return { status: 'timeout', detail: tail(log), waitedMs };
    }
    await sleep(pollMs);
  }
}

const NOT_READY_TITLE = 'harden-runner agent did not start';

function describe(result, timeoutMs) {
  const seconds = (ms) => `${(ms / 1000).toFixed(1)} s`;
  switch (result.status) {
    case 'failed':
      return `harden-runner's agent reported an error after ${seconds(result.waitedMs)}: ${result.detail}`;
    case 'reverted':
      return `harden-runner's agent reverted its changes after ${seconds(result.waitedMs)} ` +
        '(see the agent log below); the job has no egress filtering';
    default:
      return `harden-runner's agent did not report ready within ${seconds(timeoutMs)}; ` +
        'the job may have no egress filtering';
  }
}

// Wait for the agent as the inputs ask, publish the outcome as outputs,
// and fail or warn when enforcement never arrived.
export async function enforceAgentReadyPolicy(inputs, waiter = waitForAgent) {
  const timeoutMs = inputs.agentTimeout * 1000;
  if (timeoutMs === 0) {
    setOutput('agent_status', 'disabled');
    setOutput('agent_wait_ms', '0');
    info('Not waiting for the harden-runner agent (agent_timeout: 0) ℹ️');
    return;
  }

  const marks = parseMarks(process.env[`STATE_${MARKS_STATE}`] || '');
  const result = await waiter({ timeoutMs, marks });
  setOutput('agent_status', result.status);
  setOutput('agent_wait_ms', String(result.waitedMs));

  if (result.status === 'skipped') {
    info(`Not waiting for the harden-runner agent: ${result.reason} ℹ️`);
    return;
  }
  if (result.status === 'ready') {
    info(`harden-runner agent ready: egress enforcement in place after ${result.waitedMs} ms ✅`);
    return;
  }

  const message = describe(result, timeoutMs);
  if (result.detail && result.status !== 'failed') {
    info('Agent log (tail):');
    info(result.detail);
  }
  if (inputs.agentNotReady === 'error') {
    fail(`${message} ❌`);
  }
  annotate('warning', NOT_READY_TITLE, message);
  info(`${message}; continuing because agent_not_ready is 'warning' ⚠️`);
}
