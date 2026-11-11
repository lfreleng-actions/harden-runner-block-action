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
// together with the endpoints it adds itself (among them some 190
// GitHub Actions hostnames it fetches from the GitHub meta API), then
// switches the runner's DNS and installs its firewall rules, and
// writes that file after all of it is done. One failed lookup of any
// of those names makes it revert. With a shared organisation
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
// The agent gives up on one failed lookup, and Google's DNS-over-HTTPS
// answers SERVFAIL now and then for a name that resolves a minute
// later. When the agent reverts on an endpoint this action reads as a
// transient failure (one its pre-check resolved, one harden-runner
// adds itself, or one it cannot classify), the step restarts the
// agent's service and waits again, up to 'agent_restart_attempts'
// times. The restarts share the 'agent_timeout' budget and never
// extend it. Nothing else is retried: an entry the pre-check flagged
// is stale, a timeout would spend the wait again, and a configuration
// error repeats on every start. When the attempts run out the policy
// applies as before, so the default stays fail-closed.
//
// The agent is Linux-only in the form watched here (the Windows agent
// keeps its status file under a directory harden-runner saves in its
// own state, which this action cannot read). Elsewhere, and whenever
// harden-runner never created the agent directory -- no harden-runner
// step, or the StepSecurity API declined to monitor the run -- there
// is nothing to wait for and the step says so.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { annotate, fail, info, parseKeyValueFile, setOutput } from './actions-io.mjs';
import { restartAgent, restartInFlight } from './agent-restart.mjs';
import { hostOf } from './dns-validate.mjs';

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
  restartAttempts: 2,
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

// The agent logs a failed pre-resolution as
//   unable to resolve domain: <name>. err: ...
// with the name fully qualified. Returns the last such name, without
// the trailing dot and lower-cased, or '' when the log names none.
const UNRESOLVED_RE = /unable to resolve domain: ([A-Za-z0-9_.-]+)/g;

export function unresolvedEndpoint(log) {
  let name = '';
  for (const m of log.matchAll(UNRESOLVED_RE)) name = m[1];
  return name.replace(/\.$/, '').toLowerCase();
}

// Poll for the agent's verdict. Resolves to one of:
//
//   { status: 'skipped',  reason }  nothing to wait for
//   { status: 'ready' }             enforcement is in place
//   { status: 'failed',   detail }  the agent reported an error
//   { status: 'reverted', detail, endpoint }
//                                   the agent undid its changes;
//                                   endpoint is the name it could not
//                                   resolve, or '' when the log has none
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
//
// `restarted` says this action restarted the agent itself, after a
// revert, and took the marks just before. A status file the earlier
// start wrote (an 'Initialized' that a revert then undid) is not a
// reused agent then, and the wait goes ahead past the new marks.
export async function waitForAgent({
  timeoutMs = DEFAULTS.timeoutMs,
  marks = null,
  restarted = false,
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
  if (!restarted && marks?.status?.size > 0) {
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
      return { status: 'reverted', detail: tail(log), endpoint: unresolvedEndpoint(log), waitedMs };
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

const LIST_OUTPUT = 'allowed_endpoints';
const FLAGGED_OUTPUTS = ['invalid_records', 'indeterminate_records'];

function hostsOf(value) {
  return new Set((value || '').split(/\s+/).filter(Boolean).map(hostOf).filter(Boolean));
}

// Who owns the endpoint the agent could not resolve. Pre published the
// final allow-list in the env var named by env_var_name and as the
// 'allowed_endpoints' output, which main has republished; the outputs
// file also carries the names pre's own DNS check failed on. The agent
// never pre-resolves a wildcard, so an exact host match suffices.
//
//   'listed'    an allow-list entry that pre's check resolved
//   'flagged'   an allow-list entry that pre's check also failed on
//   'implicit'  not in the allow-list: one harden-runner adds itself
//   'unknown'   the published allow-list is not available here
export function classifyEndpoint(endpoint, envVarName) {
  let outputs = {};
  try {
    outputs = parseKeyValueFile(fs.readFileSync(process.env.GITHUB_OUTPUT, 'utf8'));
  } catch {
    // no outputs file: classify from the env var alone
  }
  const published = (envVarName && process.env[envVarName]) ?? outputs[LIST_OUTPUT];
  if (published === undefined) return 'unknown';
  if (!hostsOf(published).has(endpoint)) return 'implicit';
  const flagged = FLAGGED_OUTPUTS.some((name) => hostsOf(outputs[name]).has(endpoint));
  return flagged ? 'flagged' : 'listed';
}

const REVERT_DIAGNOSES = {
  listed: (host) =>
    `It could not resolve ${host}, an allow-list entry that resolved in this ` +
    "action's pre-check: a transient resolver failure rather than a stale " +
    'entry; re-run the job',
  flagged: (host) =>
    `It could not resolve ${host}, an allow-list entry that this action's ` +
    'pre-check could not resolve either (see invalid_records and ' +
    'indeterminate_records); check or remove the entry',
  implicit: (host) =>
    `It could not resolve ${host}, which is not in the allow-list: ` +
    'harden-runner adds it itself (the GitHub Actions domains it fetches ' +
    'from the GitHub meta API), so no allow-list entry caused the revert ' +
    'and editing the list will not help; a transient resolver failure, ' +
    're-run the job',
  unknown: (host) => `It could not resolve ${host}`,
};

function describe(result, timeoutMs, ownership) {
  const seconds = (ms) => `${(ms / 1000).toFixed(1)} s`;
  switch (result.status) {
    case 'failed':
      return `harden-runner's agent reported an error after ${seconds(result.waitedMs)}: ${result.detail}`;
    case 'reverted': {
      const base = `harden-runner's agent reverted its changes after ${seconds(result.waitedMs)} ` +
        '(see the agent log below); the job has no egress filtering';
      if (!result.endpoint) return base;
      return `${base}. ${REVERT_DIAGNOSES[ownership](result.endpoint)}`;
    }
    default:
      return `harden-runner's agent did not report ready within ${seconds(timeoutMs)}; ` +
        'the job may have no egress filtering';
  }
}

// Only a revert on a name this action reads as a transient resolver
// failure is retried. A 'flagged' entry failed pre's check too and
// will fail again; a revert naming no endpoint is not a resolver
// failure at all; a timeout would spend the wait again; and a config
// error repeats on every start.
const RETRIED_OWNERSHIPS = new Set(['listed', 'implicit', 'unknown']);

function ownershipOf(result, envVarName) {
  if (result.status !== 'reverted' || !result.endpoint) return null;
  return classifyEndpoint(result.endpoint, envVarName);
}

// Wait for the agent as the inputs ask, restart it after a transient
// revert while attempts and time remain, publish the outcome as
// outputs, and fail or warn when enforcement never arrived. Every
// wait and restart shares one deadline, 'agent_timeout' from the
// start of the first wait, and each gets only what remains. The restart
// command, the marks and the clock are injectable so the tests need
// neither systemd nor sudo.
export async function enforceAgentReadyPolicy(inputs, waiter = waitForAgent, {
  restart = restartAgent,
  mark = markAgentFiles,
  now = Date.now,
} = {}) {
  const timeoutMs = inputs.agentTimeout * 1000;
  if (timeoutMs === 0) {
    setOutput('agent_status', 'disabled');
    setOutput('agent_wait_ms', '0');
    setOutput('agent_unresolved_endpoint', '');
    setOutput('agent_restarts', '0');
    info('Not waiting for the harden-runner agent (agent_timeout: 0) ℹ️');
    return;
  }
  const maxRestarts = inputs.agentRestartAttempts ?? DEFAULTS.restartAttempts;

  let marks = parseMarks(process.env[`STATE_${MARKS_STATE}`] || '');
  const started = now();
  const deadline = started + timeoutMs;
  let result = await waiter({ timeoutMs, marks });
  let ownership = ownershipOf(result, inputs.envVarName);
  let restarts = 0;

  while (RETRIED_OWNERSHIPS.has(ownership) && restarts < maxRestarts) {
    // Fresh marks, so this start's verdict is not confused with the
    // 'Reverted changes' or status the previous start wrote. Taken
    // before the deadline check, so time spent marking cannot let a
    // restart start after the deadline.
    marks = mark();
    const remainingMs = deadline - now();
    if (remainingMs <= 0) {
      info(`No time left within agent_timeout to restart harden-runner's agent ℹ️`);
      break;
    }
    restarts += 1;
    info(
      `harden-runner's agent reverted its changes: it could not resolve ` +
      `${result.endpoint} (${ownership}); restarting it, attempt ` +
      `${restarts} of ${maxRestarts} 🔄`,
    );
    if (result.detail) {
      info('Agent log (tail):');
      info(result.detail);
    }
    try {
      restart(remainingMs);
    } catch (e) {
      if (!restartInFlight(e)) {
        info(`Restarting harden-runner's agent failed: ${e.message} ⚠️`);
        continue;
      }
      // Restarting again could kill an agent the queued job has just
      // started, so read its verdict from the agent files instead, with
      // the same marks and deadline. A verdict means the job ran.
      info(
        `The restart command did not finish (${e.message}); systemd may ` +
        "still be restarting harden-runner's agent, so waiting for it " +
        'rather than restarting it again ⏳',
      );
    }
    const next = await waiter({ timeoutMs: Math.max(0, deadline - now()), marks, restarted: true });
    // A wait cannot skip once the agent has run; were it to, keep the
    // revert rather than pass a job that has no filtering.
    if (next.status === 'skipped') break;
    result = next;
    ownership = ownershipOf(result, inputs.envVarName);
  }
  if (restarts > 0) result = { ...result, waitedMs: now() - started };

  const endpoint = result.status === 'reverted' ? result.endpoint || '' : '';
  setOutput('agent_status', result.status);
  setOutput('agent_wait_ms', String(result.waitedMs));
  setOutput('agent_unresolved_endpoint', endpoint);
  setOutput('agent_restarts', String(restarts));

  if (result.status === 'skipped') {
    info(`Not waiting for the harden-runner agent: ${result.reason} ℹ️`);
    return;
  }
  const afterRestarts = restarts > 0 ? ` after ${restarts} restart(s)` : '';
  if (result.status === 'ready') {
    info(`harden-runner agent ready: egress enforcement in place after ${result.waitedMs} ms${afterRestarts} ✅`);
    return;
  }

  const described = describe(result, timeoutMs, ownership);
  const message = restarts > 0 ? `${described}; still not ready${afterRestarts}` : described;
  if (result.detail && result.status !== 'failed') {
    info('Agent log (tail):');
    info(result.detail);
  }
  if (inputs.agentNotReady === 'error') {
    fail(`${message} ❌`, NOT_READY_TITLE);
  }
  annotate('warning', NOT_READY_TITLE, message);
  info(`${message}; continuing because agent_not_ready is 'warning' ⚠️`);
}
