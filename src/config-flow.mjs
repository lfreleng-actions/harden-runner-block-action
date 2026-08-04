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
//
// 'supplemental_config' names a second list, resolved by the same
// resolver and concatenated with the first. Merging two already-resolved
// lists is this action's concern alone, so it happens here rather than
// in the mirrored resolver, which would otherwise need paired pull
// requests and would impose the new behaviour on its '--mode vulns'
// consumer. The resolver is simply invoked twice.

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';
import {
  exportEnv,
  fail,
  info,
  maskSecret,
  setOutput,
  stepSummary,
} from './actions-io.mjs';
import {
  checkResolvedTrust,
  describeSource,
  mergeAllowLists,
} from './supplemental.mjs';

// The resolver allows allow-list files up to 1 MiB and serialises the
// token list as JSON on stdout; raise maxBuffer well above Node's 1 MiB
// default so a near-limit file cannot trigger ENOBUFS before the env
// var is exported.
const MAX_RESOLVER_OUTPUT_BYTES = 16 * 1024 * 1024;

const SUMMARY_TITLE = '🛡️ Harden Runner Allow-list';

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
//
// Summary and output writing are the caller's to enable. The baseline
// call keeps the resolver's own reporting; the supplemental call passes
// both targets empty so it neither appends a second summary block nor
// overwrites the baseline's resolved_* outputs with its own
// coordinates.
function resolveSpec({ spec, token, workflowOrg, summaryTarget, outputTarget }) {
  const res = spawnSync('python3', [
    resolverScriptPath(),
    '--config', spec,
    '--workflow-org', workflowOrg,
    '--family', 'harden-runner',
    '--mode', 'endpoints',
    '--token-env', 'CONFIG_TOKEN',
    '--content-key', 'allowed_endpoints',
    '--summary-title', SUMMARY_TITLE,
    '--summary-unit', 'Endpoints',
    '--github-output', outputTarget,
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
    fail(`Could not parse config resolver output for '${spec}' ❌`);
    return undefined; // unreachable
  }
}

// Resolve the supplemental list, or return null when it is absent and
// its absence is tolerated.
//
// The spec-level trust check has already run during input validation,
// so nothing reaches here that was refusable without a fetch.
function resolveSupplemental(inputs) {
  const {
    supplementalConfig: spec,
    supplementalUnpinned: unpinned,
    supplementalRequired: required,
    token,
    workflowOrg,
  } = inputs;

  const extra = resolveSpec({
    spec,
    token,
    workflowOrg,
    summaryTarget: '',
    outputTarget: '',
  });

  if (!extra.found) {
    if (required) {
      fail(`No allow-list found via supplemental_config '${spec}' ❌`);
    }
    info(
      `No supplemental allow-list found via '${spec}'; ` +
      'continuing with the baseline alone ℹ️',
    );
    return null;
  }

  // The same rule again, now against the coordinates the resolver
  // actually used rather than against our own reading of the spec. It
  // runs after the fetch but before a single token is merged, so a
  // divergence between the two parsers costs a wasted fetch instead of
  // a widened allow-list.
  const resolved = checkResolvedTrust(
    { hostOrg: extra.host_org, ref: extra.ref },
    unpinned,
    workflowOrg,
  );
  if (!resolved.ok) {
    fail(
      `Supplemental list '${describeSource(extra) || spec}' rejected: ` +
      `${resolved.reason} ❌`,
    );
  }

  return extra;
}

function summariseSupplemental({ spec, extra, merge, total }) {
  // Leading blank line: this block is appended directly after the
  // resolver's own, and a heading needs one to render as a heading.
  const lines = ['', `### ${SUMMARY_TITLE} (supplemental)`, ''];
  if (!extra) {
    lines.push(
      `- Supplemental: \`${spec}\``,
      '- Result: not found; continuing with the baseline alone',
    );
  } else {
    // Show the distinct count only when it differs from the number of
    // entries read, so the "new + already" figures below always add up
    // to something stated rather than appearing not to.
    const read = extra.count === merge.supplementalUnique
      ? `**${extra.count}**`
      : `**${extra.count}** (${merge.supplementalUnique} distinct)`;
    lines.push(
      `- Supplemental: \`${describeSource(extra)}\``,
      `- Commit SHA: \`${extra.resolved_sha || '(n/a)'}\``,
      `- Endpoints read: ${read}`,
      `- Merged: **${merge.added}** new, ` +
      `**${merge.overlap}** already in the baseline`,
      `- Endpoints after merge: **${total}**`,
    );
  }
  lines.push('');
  stepSummary(lines.join('\n'));
}

export function runConfigFlow(inputs) {
  const { config, token, workflowOrg, envVarName, summary } = inputs;

  maskSecret(token);

  // Preflight: the shared resolver needs python3 on the runner.
  const probe = spawnSync('python3', ['--version'], { encoding: 'utf8' });
  if (probe.status !== 0) {
    fail("python3 is required for the 'config' input but was not found ❌");
  }

  // An empty --step-summary target suppresses the summary block (e.g.
  // matrix legs other than the first).
  const summaryTarget = summary ? (process.env.GITHUB_STEP_SUMMARY || '') : '';

  const data = resolveSpec({
    spec: config,
    token,
    workflowOrg,
    summaryTarget,
    outputTarget: process.env.GITHUB_OUTPUT || '',
  });

  if (!data.found) {
    // Unlike python-audit-action, an empty allow-list is fatal here:
    // harden-runner block mode with no endpoints breaks all egress.
    fail(`No allow-list found via config '${config}' ❌`);
  }

  let tokens = data.tokens;

  if (inputs.supplementalConfig !== '') {
    const extra = resolveSupplemental(inputs);
    let merge = null;

    if (extra) {
      merge = mergeAllowLists(tokens, extra.tokens);
      tokens = merge.tokens;
      info(
        `Merged ${merge.added} endpoint(s) from the supplemental list ` +
        `(${merge.supplementalUnique} distinct read, ${merge.overlap} ` +
        'already in the baseline) ✅',
      );
      if (merge.baselineDuplicates > 0) {
        info(
          `Collapsed ${merge.baselineDuplicates} duplicate entr(y/ies) ` +
          'within the baseline list ℹ️',
        );
      }

      // The baseline call already wrote allowed_endpoints and count for
      // its own list. Publish both again so they describe what is
      // actually enforced: GITHUB_OUTPUT is read in order, so the later
      // line for a key wins, exactly as calling setOutput twice does.
      // Leaving count behind would be worse than cosmetic, given these
      // outputs exist to answer "what did this job allow".
      //
      // The condition tests both ways the merged list can differ from
      // what the resolver published. Testing only 'added > 0' would miss
      // a baseline that carried duplicates, whose collapse changes the
      // list without adding to it.
      if (merge.added > 0 || merge.baselineDuplicates > 0) {
        setOutput('allowed_endpoints', tokens.join(' '));
        setOutput('count', String(tokens.length));
      }
    }

    // Reported separately from the baseline's own outputs so that,
    // during an incident, "which list granted this endpoint" has an
    // answer.
    setOutput('supplemental_source', extra ? describeSource(extra) : '');
    setOutput('supplemental_count', String(extra ? extra.count : 0));
    // For an unpinned list the commit is the only audit trail there is:
    // the spec names a branch, and the branch moves.
    setOutput('supplemental_sha', extra ? (extra.resolved_sha || '') : '');

    if (summary) {
      summariseSupplemental({
        spec: inputs.supplementalConfig,
        extra,
        merge,
        total: tokens.length,
      });
    }
  }

  // The resolver already wrote the step outputs and summary; we only
  // need to publish the env var the downstream harden-runner pre hook
  // consumes.
  exportEnv(envVarName, tokens.join(' '));
  info(`Loaded ${tokens.length} allow-list endpoints via config ✅`);
}
