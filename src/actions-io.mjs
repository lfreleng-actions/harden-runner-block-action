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
import * as os from 'node:os';
import * as path from 'node:path';
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

// Annotation properties (e.g. title=...) are additionally delimited by
// ':' and ',', so those must be escaped too.
function escapeProperty(s) {
  return escapeWorkflowCommand(s)
    .replace(/:/g, '%3A')
    .replace(/,/g, '%2C');
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

// Emit a titled annotation ('warning' or 'error'). Unlike err(), this
// does not echo to stderr: callers log the detail separately, and an
// annotation is the summary of it.
export function annotate(level, title, msg) {
  emit(`::${level} title=${escapeProperty(title)}::${escapeWorkflowCommand(msg)}`);
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

// Parse a runner key/value file (GITHUB_OUTPUT and friends) in both
// the plain 'name=value' and the 'name<<DELIM ... DELIM' forms. A later
// line for a key wins, as it does when the runner reads the file.
export function parseKeyValueFile(text) {
  const values = {};
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const heredoc = /^([^=<]+)<<(.+)$/.exec(line);
    if (heredoc) {
      const [, name, delim] = heredoc;
      const body = [];
      for (i++; i < lines.length && lines[i] !== delim; i++) body.push(lines[i]);
      values[name] = body.join('\n');
      continue;
    }
    const eq = line.indexOf('=');
    if (eq > 0) values[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return values;
}

// Outputs written during the pre phase are discarded: the runner gives
// pre steps no context name, and ExecutionContext.SetOutput ignores
// any step without one, so 'steps.<id>.outputs' never sees them. State
// saved in pre IS carried to the same action's main step, so pre
// hands its outputs over and main publishes them again.
//
// State reaches main as an environment variable, and Linux caps a
// single environment string at 128 KiB (MAX_ARG_STRLEN) while an
// allow-list may be up to 1 MiB, so the outputs travel in a private
// file under RUNNER_TEMP and the state carries only its path.
const OUTPUTS_STATE = 'outputs_file';

export function handOverOutputs() {
  const stateFile = process.env.GITHUB_STATE;
  const outputFile = process.env.GITHUB_OUTPUT;
  if (!stateFile || !outputFile || !fs.existsSync(outputFile)) return;
  const dir = process.env.RUNNER_TEMP || os.tmpdir();
  const handover = path.join(
    dir,
    `harden-runner-block-action-outputs-${crypto.randomBytes(8).toString('hex')}`,
  );
  // The file already uses the runner's key/value format, so main can
  // append it verbatim; the runner then applies the same
  // later-line-wins rule it would have applied in pre.
  fs.copyFileSync(outputFile, handover, fs.constants.COPYFILE_EXCL);
  fs.chmodSync(handover, 0o600);
  appendKeyValue(stateFile, OUTPUTS_STATE, handover);
}

// The runner exposes pre's saved state to main as STATE_<name>.
// Returns the number of distinct outputs published.
export function republishOutputs() {
  const handover = process.env[`STATE_${OUTPUTS_STATE}`];
  if (!handover || !fs.existsSync(handover)) return 0;
  const outputFile = process.env.GITHUB_OUTPUT;
  if (!outputFile) {
    fail('GITHUB_OUTPUT not set; cannot publish step outputs ❌');
  }
  const text = fs.readFileSync(handover, 'utf8');
  fs.appendFileSync(outputFile, text);
  fs.rmSync(handover, { force: true });
  return Object.keys(parseKeyValueFile(text)).length;
}

// GitHub Actions passes inputs to JS actions as INPUT_<NAME>, with
// hyphens converted to underscores and uppercased.
export function getInput(name, defaultValue = '') {
  const key = `INPUT_${name.toUpperCase().replace(/-/g, '_')}`;
  const value = process.env[key];
  return value === undefined ? defaultValue : value;
}
