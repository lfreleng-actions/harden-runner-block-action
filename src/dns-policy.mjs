// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Enforcement and reporting of the 'invalid_records' policy.
//
// Validation runs in EVERY invocation, because every job starts its own
// harden-runner agent and each agent resolves the allow-list for
// itself: a check confined to the first job would leave every other
// job free to fail open. Validation is cheap (a few hundred
// milliseconds for ~150 names), so this costs little.
//
// Reporting is a different matter. The step summary and the
// annotations are emitted only where 'allow_list_summary' is true,
// which callers already set on exactly one invocation per workflow, so
// a workflow with ten jobs reports a stale hostname once rather than
// ten times. Every invocation still logs its findings to the console,
// and 'error' mode fails every job, because a failing job must say why.

import {
  annotate,
  exportEnv,
  fail,
  info,
  setOutput,
  stepSummary,
} from './actions-io.mjs';
import { applyMode, validateAllowList } from './dns-validate.mjs';

// Published unconditionally, so a caller can wire
//   egress-policy: ${{ env.HARDEN_RUNNER_EGRESS_POLICY }}
// once and have 'warning' mode switch the job to audit.
export const EGRESS_POLICY_ENV = 'HARDEN_RUNNER_EGRESS_POLICY';

const TITLE_INDETERMINATE = 'Allow-list entries could not be validated';

function listEntries(records) {
  return records.map((r) => r.token).join(', ');
}

// Per-mode annotation level, title and consequence. The text follows
// the shared "<n> unresolvable allow-list entries ..." lead-in.
const CONSEQUENCES = {
  filter: {
    level: 'warning',
    title: 'Unresolvable allow-list entries filtered',
    text:
      'removed before reaching harden-runner, which would otherwise ' +
      'fail open and permit all outbound connections',
  },
  warning: {
    level: 'warning',
    title: 'Unresolvable allow-list entries: audit mode',
    text:
      `found; ${EGRESS_POLICY_ENV}=audit published, so jobs that pass ` +
      "it to harden-runner's egress-policy run in audit mode instead " +
      'of block',
  },
  error: {
    level: 'error',
    title: 'Unresolvable allow-list entries',
    text: "found; failing because invalid_records is 'error'",
  },
  ignore: {
    level: 'warning',
    title: 'Unresolvable allow-list entries: harden-runner fails open',
    text:
      'found; harden-runner will fail open and permit ALL outbound ' +
      "network connections (invalid_records is 'ignore')",
  },
};

function consequence(mode, count) {
  const { level, title, text } = CONSEQUENCES[mode];
  const entries = count === 1 ? 'entry' : 'entries';
  return { level, title, text: `${count} unresolvable allow-list ${entries} ${text}` };
}

function indeterminateNote(mode, result) {
  if (result.degraded) {
    return (
      'More than a quarter of the lookups reached no verdict, so the ' +
      'DNS-over-HTTPS providers look unreachable from this runner; ' +
      'these entries were left in place rather than stripping the ' +
      'allow-list wholesale'
    );
  }
  return mode === 'filter'
    ? 'Removed as a precaution: harden-runner may fail open on them'
    : 'Left in place: harden-runner may fail open on them';
}

function logFindings(result) {
  info(
    `DNS validation: ${result.hostsChecked} hostname(s) checked in ` +
    `${result.elapsedMs} ms (${result.wildcardsSkipped} wildcard ` +
    'entr(y/ies) skipped)',
  );
  for (const r of result.invalid) {
    info(`  ❌ invalid: ${r.token} (${r.detail})`);
  }
  for (const r of result.indeterminate) {
    info(`  ⚠️ indeterminate: ${r.token} (${r.detail})`);
  }
}

function summaryTable(records, verdict) {
  return records.map(
    (r) => `| \`${r.token}\` | ${verdict} | ${r.detail} |`,
  );
}

function writeSummary(mode, result, outcome) {
  const lines = ['', '### 🔎 Allow-list DNS validation', ''];
  lines.push(
    `- Mode (\`invalid_records\`): \`${mode}\``,
    `- Hostnames checked: **${result.hostsChecked}** in ` +
    `**${result.elapsedMs} ms**`,
    `- Wildcard entries skipped: ${result.wildcardsSkipped} ` +
    '(harden-runner never pre-resolves them)',
  );
  if (result.invalid.length === 0 && result.indeterminate.length === 0) {
    lines.push('- Result: every hostname resolved ✅', '');
    stepSummary(lines.join('\n'));
    return;
  }
  lines.push(
    `- Invalid: **${result.invalid.length}**, ` +
    `indeterminate: **${result.indeterminate.length}**`,
    `- Egress policy published: \`${outcome.egressPolicy}\``,
    '',
    '| Entry | Verdict | Detail |',
    '| ----- | ------- | ------ |',
    ...summaryTable(result.invalid, '❌ invalid'),
    ...summaryTable(result.indeterminate, '⚠️ indeterminate'),
    '',
  );
  if (result.invalid.length > 0) {
    lines.push(`${consequence(mode, result.invalid.length).text}.`, '');
  }
  if (result.indeterminate.length > 0) {
    lines.push(`Indeterminate entries: ${indeterminateNote(mode, result)}.`, '');
  }
  stepSummary(lines.join('\n'));
}

function annotateFindings(mode, result) {
  if (result.invalid.length > 0 && mode !== 'error') {
    const c = consequence(mode, result.invalid.length);
    annotate(c.level, c.title, `${c.text}: ${listEntries(result.invalid)}`);
  }
  if (result.indeterminate.length > 0) {
    annotate(
      'warning',
      TITLE_INDETERMINATE,
      `${result.indeterminate.length} allow-list entr(y/ies) reached no ` +
      `DNS verdict after retries. ${indeterminateNote(mode, result)}: ` +
      listEntries(result.indeterminate),
    );
  }
}

// Validate the allow-list tokens, enforce the configured mode and
// publish the results. Returns the tokens the job should enforce.
export async function enforceInvalidRecordsPolicy(inputs, tokens, validate = validateAllowList) {
  const mode = inputs.invalidRecords;
  const result = await validate(tokens);
  const outcome = applyMode(mode, tokens, result);

  logFindings(result);

  setOutput('invalid_records', result.invalid.map((r) => r.token).join(' '));
  setOutput('invalid_count', String(result.invalid.length));
  setOutput(
    'indeterminate_records',
    result.indeterminate.map((r) => r.token).join(' '),
  );
  setOutput('indeterminate_count', String(result.indeterminate.length));
  setOutput('egress_policy', outcome.egressPolicy);
  exportEnv(EGRESS_POLICY_ENV, outcome.egressPolicy);

  if (inputs.summary) {
    if (mode !== 'ignore') writeSummary(mode, result, outcome);
    annotateFindings(mode, result);
  }

  if (outcome.fail) {
    const c = consequence(mode, result.invalid.length);
    fail(`${c.text}: ${listEntries(result.invalid)} ❌`);
  }

  if (outcome.tokens.length === 0) {
    // Block mode with nothing allowed would break every connection the
    // job makes; that is a broken allow-list, not one to enforce.
    fail('Every allow-list entry failed DNS validation; refusing to publish an empty list ❌');
  }

  if (outcome.dropped.length > 0) {
    info(`Filtered ${outcome.dropped.length} entr(y/ies) from the allow-list ✅`);
    // Earlier writes described the unfiltered list. GITHUB_OUTPUT is
    // read in order, so these later lines win.
    setOutput('allowed_endpoints', outcome.tokens.join(' '));
    setOutput('count', String(outcome.tokens.length));
  }

  return outcome.tokens;
}
