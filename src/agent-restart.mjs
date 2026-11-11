// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Restart step-security/harden-runner's agent after a transient revert,
// for the policy in agent-ready.mjs.

import { execFileSync } from 'node:child_process';

// harden-runner's pre hook starts the agent with 'sudo service agent
// start' and its unit sets no Restart=, so a reverted agent stays
// stopped. A restart re-reads the same configuration and resolves the
// list again from a clean slate: the agent undid its DNS and firewall
// changes before it exited. Bounded as harden-runner bounds its start,
// and '-n' makes sudo fail at once rather than wait for a password on
// a runner without passwordless sudo. The command never gets more
// than what remains of 'agent_timeout', so a late restart cannot
// overrun it; the floor of 1 ms keeps execFileSync's 0 (no timeout)
// out of reach.
export const RESTART_TIMEOUT_MS = 15_000;

export function restartTimeoutMs(remainingMs) {
  return Math.max(1, Math.min(RESTART_TIMEOUT_MS, remainingMs));
}

export function restartAgent(remainingMs = RESTART_TIMEOUT_MS) {
  execFileSync('sudo', ['-n', 'systemctl', 'restart', 'agent.service'], {
    timeout: restartTimeoutMs(remainingMs),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

// Whether a restart that threw may still be under way. Killing the
// sudo/systemctl client on a timeout, or by any signal, does not
// cancel a job it already queued with systemd, so the agent may yet
// start. A client that exited non-zero or never spawned (no
// passwordless sudo, no systemd) definitely restarted nothing.
export function restartInFlight(error) {
  return error?.code === 'ETIMEDOUT' || Boolean(error?.signal);
}
