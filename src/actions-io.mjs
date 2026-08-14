// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// GitHub Actions runner protocol helpers.
//
// The action carries no npm dependencies: it talks to the runner
// through the documented file/env-var protocol (GITHUB_ENV,
// GITHUB_OUTPUT, GITHUB_STEP_SUMMARY) and the '::' workflow commands.
// Everything that touches that protocol lives here.

import * as fs from 'node:fs';
import * as crypto from 'node:crypto';
import { URL } from 'node:url';

// Workflow commands (lines starting with '::') decode %25 -> %,
// %0A -> newline, %0D -> carriage return. A raw newline in a
// workflow-command argument would let a hostile input inject
// additional commands. Escape the three characters that need it, in
// the order GitHub itself documents.
export function escapeWorkflowCommand(s) {
  return String(s)
    .replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A');
}

// Strip credentials (userinfo) and query/fragment before logging or
// publishing as a step output. Keeps scheme + host + path so the
// resulting string is still useful for debugging without leaking
// secrets a caller may have included in `url`.
export function redactUrl(u) {
  if (!u) return '';
  try {
    const parsed = new URL(u);
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return '<unparsable URL>';
  }
}

// Workflow commands and log lines go to stdout, which is what the
// runner parses. process.stdout.write is used in preference to
// console.* so the log surface stays an explicit part of the runner
// protocol rather than incidental debug output.
function emit(line) {
  process.stdout.write(`${line}\n`);
}

export function info(msg) {
  emit(msg);
}

// Emit a GitHub Actions error annotation AND echo to stderr so the raw
// step log carries the same string even when annotations are
// suppressed. Escape the annotation payload so user-controlled values
// cannot inject additional workflow commands.
export function err(msg) {
  emit(`::error::${escapeWorkflowCommand(msg)}`);
  process.stderr.write(`${msg}\n`);
}

export function fail(msg) {
  err(msg);
  process.exit(1);
}

// Register a value for redaction in the runner's log scrubber. The
// value is escaped so a secret containing %, CR or LF cannot break the
// command or inject additional ones.
export function maskSecret(value) {
  if (!value) return;
  emit(`::add-mask::${escapeWorkflowCommand(value)}`);
}

// Append `name=value`, or the documented heredoc form when the value
// spans lines, to one of the runner's key/value files.
function appendKeyValue(file, name, value) {
  if (/[\r\n]/.test(value)) {
    const delim = `EOF_${crypto.randomBytes(8).toString('hex')}`;
    fs.appendFileSync(file, `${name}<<${delim}\n${value}\n${delim}\n`);
  } else {
    fs.appendFileSync(file, `${name}=${value}\n`);
  }
}

export function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) {
    fail('GITHUB_OUTPUT not set; cannot publish step outputs ❌');
  }
  if (/[\r\n]/.test(name)) {
    fail(`Refusing to publish output with newline in name: ${JSON.stringify(name)} ❌`);
  }
  appendKeyValue(file, name, value);
}

// Mirrors @actions/core.exportVariable: writes to GITHUB_ENV in the
// delimited-or-plain form GitHub Actions accepts, AND updates the
// current process env so the rest of this pre script sees the value.
export function exportEnv(name, value) {
  const file = process.env.GITHUB_ENV;
  if (!file) {
    fail('GITHUB_ENV not set; cannot publish environment variable ❌');
  }
  appendKeyValue(file, name, value);
  process.env[name] = value;
}

export function stepSummary(markdown) {
  const file = process.env.GITHUB_STEP_SUMMARY;
  if (!file) return; // step summary is optional, do not fail without it
  fs.appendFileSync(file, markdown);
}

// GitHub Actions passes inputs to JS actions as INPUT_<NAME>, with
// hyphens converted to underscores and uppercased.
export function getInput(name, defaultValue = '') {
  const key = `INPUT_${name.toUpperCase().replace(/-/g, '_')}`;
  const value = process.env[key];
  return value === undefined ? defaultValue : value;
}
