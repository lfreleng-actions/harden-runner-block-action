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
//
// This is also where the job's one egress policy is published. The
// central egress override (egress-override.mjs) is read first and
// arrives as inputs.egressOverride; while it is active the policy is
// 'audit', and neither outcome that would end the step here ('error'
// mode with invalid entries, or a list that filters to nothing) does:
// both are reported, and the job goes on in audit mode.

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
// once and have 'warning' mode, or the central override, switch the
// job to audit.
export const EGRESS_POLICY_ENV = 'HARDEN_RUNNER_EGRESS_POLICY';

const TITLE_INDETERMINATE = 'Allow-list entries could not be validated';
const UNDER_OVERRIDE = 'continuing because the central egress override is active';
const TITLE_RESTORED = 'Allow-list published unfiltered';
const RESTORED =
  'Every allow-list entry failed DNS validation; publishing the ' +
  `unfiltered list rather than an empty one, ${UNDER_OVERRIDE}`;

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
  // 'error' mode while the central override holds the job in audit.
  errorOverridden: {
    level: 'warning',
    title: 'Unresolvable allow-list entries',
    text: `found; not failing although invalid_records is 'error', ${UNDER_OVERRIDE}`,
  },
  ignore: {
    level: 'warning',
    title: 'Unresolvable allow-list entries: harden-runner fails open',
    text:
      'found; harden-runner will fail open and permit ALL outbound ' +
      "network connections (invalid_records is 'ignore')",
  },
};

function consequence(mode, count, override = false) {
  const key = override && mode === 'error' ? 'errorOverridden' : mode;
  const { level, title, text } = CONSEQUENCES[key];
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

function writeSummary(mode, result, published) {
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
    `- Egress policy published: \`${published.egressPolicy}\``,
    '',
    '| Entry | Verdict | Detail |',
    '| ----- | ------- | ------ |',
    ...summaryTable(result.invalid, '❌ invalid'),
    ...summaryTable(result.indeterminate, '⚠️ indeterminate'),
    '',
  );
  if (result.invalid.length > 0) {
    lines.push(`${consequence(mode, result.invalid.length, published.override).text}.`, '');
  }
  if (published.restored) {
    lines.push(`${RESTORED}.`, '');
  }
  if (result.indeterminate.length > 0) {
    lines.push(`Indeterminate entries: ${indeterminateNote(mode, result)}.`, '');
  }
  stepSummary(lines.join('\n'));
}

function annotateFindings(mode, result, override) {
  if (result.invalid.length > 0 && (mode !== 'error' || override)) {
    const c = consequence(mode, result.invalid.length, override);
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
// publish the results, the job's egress policy among them. Returns the
// tokens the job should enforce.
export async function enforceInvalidRecordsPolicy(inputs, tokens, validate = validateAllowList) {
  const mode = inputs.invalidRecords;
  const override = inputs.egressOverride === true;
  const result = await validate(tokens);
  const outcome = applyMode(mode, tokens, result);

  // A list that filters to nothing is refused, except under the
  // override, where the unfiltered list goes out instead: harden-runner
  // in audit mode never resolves it, and an empty list in block mode
  // would cut off every connection the job makes.
  const restored = override && outcome.tokens.length === 0 && tokens.length > 0;
  const enforced = restored ? tokens : outcome.tokens;
  const published = {
    egressPolicy: override ? 'audit' : outcome.egressPolicy,
    override,
    restored,
  };

  logFindings(result);

  setOutput('invalid_records', result.invalid.map((r) => r.token).join(' '));
  setOutput('invalid_count', String(result.invalid.length));
  setOutput(
    'indeterminate_records',
    result.indeterminate.map((r) => r.token).join(' '),
  );
  setOutput('indeterminate_count', String(result.indeterminate.length));
  setOutput('egress_policy', published.egressPolicy);
  exportEnv(EGRESS_POLICY_ENV, published.egressPolicy);

  if (inputs.summary) {
    if (mode !== 'ignore') writeSummary(mode, result, published);
    annotateFindings(mode, result, override);
    if (restored) annotate('warning', TITLE_RESTORED, RESTORED);
  }

  if (outcome.fail) {
    const c = consequence(mode, result.invalid.length, override);
    if (!override) fail(`${c.text}: ${listEntries(result.invalid)} ❌`);
    info(`${c.text}: ${listEntries(result.invalid)} ⚠️`);
  }

  if (enforced.length === 0) {
    // Block mode with nothing allowed would break every connection the
    // job makes; that is a broken allow-list, not one to enforce.
    fail('Every allow-list entry failed DNS validation; refusing to publish an empty list ❌');
  }
  if (restored) info(`${RESTORED} ⚠️`);

  if (!restored && outcome.dropped.length > 0) {
    info(`Filtered ${outcome.dropped.length} entr(y/ies) from the allow-list ✅`);
    // Earlier writes described the unfiltered list. GITHUB_OUTPUT is
    // read in order, so these later lines win.
    setOutput('allowed_endpoints', enforced.join(' '));
    setOutput('count', String(enforced.length));
  }

  return enforced;
}
