// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Config-mode resolution.
//
// The 'config' input names an allow-list by repository spec rather than
// by path or URL. Resolving that spec is the job of the shared Python
// resolver (src/resolve_config_source.py), which is mirrored
// byte-for-byte across the actions that consume it; this module drives
// it and publishes the result.

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import { exportEnv, fail, info, maskSecret } from './actions-io.mjs';

// The resolver allows allow-list files up to 1 MiB and serialises the
// token list as JSON on stdout; raise maxBuffer well above Node's 1 MiB
// default so a near-limit file cannot trigger ENOBUFS before the env
// var is exported.
const MAX_RESOLVER_OUTPUT_BYTES = 16 * 1024 * 1024;

function resolverScriptPath() {
  return path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    'resolve_config_source.py',
  );
}

// Build the child environment for the resolver.
//
// The token is passed via the environment (CONFIG_TOKEN), never on the
// command line, so it cannot appear in a process listing. We also strip
// the runner-provided INPUT_TOKEN from the child environment: the
// resolver reads (and pops) CONFIG_TOKEN, so leaving INPUT_TOKEN in
// place would still leak the secret into the git subprocesses the
// resolver spawns.
function resolverEnv(token) {
  const childEnv = { ...process.env, CONFIG_TOKEN: token };
  delete childEnv.INPUT_TOKEN;
  return childEnv;
}

// Invoke the resolver for one spec and return its parsed JSON.
function resolveSpec({ spec, token, workflowOrg, summaryTarget }) {
  const res = spawnSync('python3', [
    resolverScriptPath(),
    '--config', spec,
    '--workflow-org', workflowOrg,
    '--family', 'harden-runner',
    '--mode', 'endpoints',
    '--token-env', 'CONFIG_TOKEN',
    '--content-key', 'allowed_endpoints',
    '--summary-title', '🛡️ Harden Runner Allow-list',
    '--summary-unit', 'Endpoints',
    '--github-output', process.env.GITHUB_OUTPUT || '',
    '--step-summary', summaryTarget,
    '--json-stdout',
  ], {
    encoding: 'utf8',
    env: resolverEnv(token),
    maxBuffer: MAX_RESOLVER_OUTPUT_BYTES,
  });

  if (res.stderr) {
    process.stderr.write(res.stderr);
  }
  if (res.status !== 0) {
    fail(`Failed to resolve allow-list from config '${spec}' ❌`);
  }

  try {
    return JSON.parse(res.stdout.trim());
  } catch {
    fail('Could not parse config resolver output ❌');
    return undefined; // unreachable
  }
}

export function runConfigFlow({ config, token, workflowOrg, envVarName, summary }) {
  maskSecret(token);

  // Preflight: the shared resolver needs python3 on the runner.
  const probe = spawnSync('python3', ['--version'], { encoding: 'utf8' });
  if (probe.status !== 0) {
    fail("python3 is required for the 'config' input but was not found ❌");
  }

  // An empty --step-summary target suppresses the summary block (e.g.
  // matrix legs other than the first).
  const summaryTarget = summary ? (process.env.GITHUB_STEP_SUMMARY || '') : '';

  const data = resolveSpec({ spec: config, token, workflowOrg, summaryTarget });

  if (!data.found) {
    // Unlike python-audit-action, an empty allow-list is fatal here:
    // harden-runner block mode with no endpoints breaks all egress.
    fail(`No allow-list found via config '${config}' ❌`);
  }

  // The resolver already wrote the step outputs and summary; we only
  // need to publish the env var the downstream harden-runner pre hook
  // consumes.
  exportEnv(envVarName, data.tokens.join(' '));
  info(`Loaded ${data.count} allow-list endpoints via config ✅`);
}
