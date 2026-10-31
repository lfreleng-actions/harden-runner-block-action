// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// The 'extra_endpoints' input: host[:port] tokens written inline in the
// calling workflow and merged into whichever allow-list the action
// loaded, after any supplemental list.
//
// Meant for emergencies and short-lived fixes, so every invocation logs
// what the input contributed, and the reporting invocation also writes
// a step-summary block and a notice: a band-aid nobody can see is a
// band-aid nobody removes.
//
// The value may span lines, unlike the other source inputs. Nothing is
// ever written from the raw text: only tokens that pass the sanitiser's
// grammar, joined with spaces, reach $GITHUB_ENV, $GITHUB_OUTPUT or the
// step summary.

import { annotate, info, setOutput, stepSummary } from './actions-io.mjs';
import { normalise, tokenProblem } from './sanitise.mjs';
import { mergeAllowLists } from './supplemental.mjs';

export const INPUT_NAME = 'extra_endpoints';

const SUMMARY_TITLE = '🛡️ Harden Runner Allow-list (extra endpoints)';
const NOTICE_TITLE = 'Allow-list extended by extra_endpoints';

// Parse the input in the allow-list file format.
//
// Returns { tokens } holding the distinct entries in first-seen order,
// or { error } naming the first token the grammar refuses. Pure, so
// input validation decides how to fail. A value holding no tokens once
// comments and whitespace are gone parses to an empty list, which the
// caller treats as unset: commenting out the last band-aid turns the
// feature off rather than failing the job.
export function parseExtraEndpoints(raw) {
  const text = normalise(String(raw));
  if (text === '') return { tokens: [] };
  const tokens = [];
  for (const token of text.split(' ')) {
    const problem = tokenProblem(token);
    if (problem) {
      return {
        error: `Input '${INPUT_NAME}' rejected token '${token}' (${problem})`,
      };
    }
    if (!tokens.includes(token)) tokens.push(token);
  }
  return { tokens };
}

// Merge the extra entries into the loaded list, and split them into
// those the merge added and those the loaded list already carried.
//
// 'redundant' is what shows a band-aid can come out: once the
// supplemental list or the shared baseline carries an entry, the inline
// copy does nothing.
export function mergeExtraEndpoints(loaded, extra) {
  const present = new Set(loaded);
  const merge = mergeAllowLists(loaded, extra);
  return {
    tokens: merge.tokens,
    added: extra.filter((token) => !present.has(token)),
    redundant: extra.filter((token) => present.has(token)),
    baselineDuplicates: merge.baselineDuplicates,
  };
}

function logMerge({ added, redundant }) {
  info(
    `${INPUT_NAME}: ${added.length} entr(y/ies) added, ` +
    `${redundant.length} already allowed ✅`,
  );
  for (const token of added) {
    info(`  ➕ added: ${token}`);
  }
  for (const token of redundant) {
    info(`  ↩️ already allowed (redundant): ${token}`);
  }
}

function summarise({ added, redundant, tokens }) {
  // Leading blank line: this block follows another one directly, and a
  // heading needs one to render as a heading.
  const lines = [
    '',
    `### ${SUMMARY_TITLE}`,
    '',
    '| Entry | Result |',
    '| ----- | ------ |',
    ...added.map((token) => `| \`${token}\` | ➕ added |`),
    ...redundant.map(
      (token) => `| \`${token}\` | ↩️ redundant: already allowed |`,
    ),
    '',
    `- Endpoints after merge: **${tokens.length}**`,
    '',
  ];
  stepSummary(lines.join('\n'));
}

// A notice rather than a warning: the input is a deliberate choice, and
// this action's warnings already mean a broken list.
function notify({ added, redundant }) {
  const parts = [];
  if (added.length > 0) {
    parts.push(
      `${added.length} endpoint(s) allowed only through ${INPUT_NAME}: ` +
      added.join(', '),
    );
  } else {
    parts.push(
      `Every ${INPUT_NAME} entry is already allowed, so the input can ` +
      'be removed',
    );
  }
  if (redundant.length > 0) {
    parts.push(`already allowed (redundant): ${redundant.join(', ')}`);
  }
  annotate('notice', NOTICE_TITLE, parts.join('; '));
}

// Merge the input's entries into the loaded tokens and report the
// result. Returns the tokens the job should enforce; the DNS check runs
// on them next, so an extra entry meets 'invalid_records' like any
// other.
export function applyExtraEndpoints(inputs, loaded) {
  const extra = inputs.extraEndpoints;
  if (extra.length === 0) return loaded;

  const merge = mergeExtraEndpoints(loaded, extra);
  logMerge(merge);

  // The earlier writes described the list before the merge. Publish
  // both again so they describe what is enforced: GITHUB_OUTPUT is read
  // in order, so the later line for a key wins.
  if (merge.added.length > 0 || merge.baselineDuplicates > 0) {
    setOutput('allowed_endpoints', merge.tokens.join(' '));
    setOutput('count', String(merge.tokens.length));
  }
  setOutput('extra_count', String(extra.length));
  setOutput('extra_added', merge.added.join(' '));

  if (inputs.summary) {
    summarise(merge);
    notify(merge);
  }

  return merge.tokens;
}
