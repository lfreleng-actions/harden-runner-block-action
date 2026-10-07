// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Unit tests for the pre-to-main output handover.
//
// The runner discards outputs written in the pre phase, so pre hands
// them to main through a private file under RUNNER_TEMP (the saved
// state carries only its path) and main publishes them again. These
// tests pin that round trip, including the heredoc form multi-line
// values use, the "later line wins" rule the filtered outputs rely on,
// and a payload larger than one environment string may hold.
//
// Run with: node --test tests/test_actions_io.mjs

import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  handOverOutputs,
  parseKeyValueFile,
  republishOutputs,
  setOutput,
} from '../src/actions-io.mjs';

test('parseKeyValueFile reads plain and heredoc entries', () => {
  const text = [
    'source=config',
    'note<<EOF_abc',
    'line one',
    'line=two',
    'EOF_abc',
    'empty=',
    '',
  ].join('\n');
  assert.deepEqual(parseKeyValueFile(text), {
    source: 'config',
    note: 'line one\nline=two',
    empty: '',
  });
});

test('parseKeyValueFile keeps the last value for a repeated key', () => {
  const text = 'count=81\ninvalid_count=1\ncount=80\n';
  assert.deepEqual(parseKeyValueFile(text), { count: '80', invalid_count: '1' });
});

// Run fn with fresh runner files, restoring the environment afterwards.
function withRunnerFiles(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hrba-io-'));
  const keys = ['GITHUB_OUTPUT', 'GITHUB_STATE', 'RUNNER_TEMP', 'STATE_outputs_file'];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  process.env.RUNNER_TEMP = dir;
  try {
    return fn(dir);
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// pre: write outputs, hand them over, and expose the saved state to
// main the way the runner does (as STATE_<name>).
function runPre(dir, writeOutputs) {
  process.env.GITHUB_OUTPUT = path.join(dir, 'pre_output');
  process.env.GITHUB_STATE = path.join(dir, 'state');
  fs.writeFileSync(process.env.GITHUB_OUTPUT, '');
  fs.writeFileSync(process.env.GITHUB_STATE, '');
  writeOutputs();
  handOverOutputs();
  const state = parseKeyValueFile(fs.readFileSync(process.env.GITHUB_STATE, 'utf8'));
  process.env.STATE_outputs_file = state.outputs_file;
  return state;
}

// main: a fresh output file, as the runner gives each step.
function runMain(dir) {
  process.env.GITHUB_OUTPUT = path.join(dir, 'main_output');
  fs.writeFileSync(process.env.GITHUB_OUTPUT, '');
  const count = republishOutputs();
  return {
    count,
    outputs: parseKeyValueFile(fs.readFileSync(process.env.GITHUB_OUTPUT, 'utf8')),
  };
}

test('outputs written in pre are published again by main', () => {
  withRunnerFiles((dir) => {
    // Outputs from the action and from the resolver subprocess land in
    // the same file; a filtered list supersedes the first.
    const state = runPre(dir, () => {
      fs.appendFileSync(process.env.GITHUB_OUTPUT, 'resolved_sha=abc123\n');
      setOutput('allowed_endpoints', 'a.example:443 gone.example:443');
      setOutput('invalid_records', 'gone.example:443');
      setOutput('allowed_endpoints', 'a.example:443');
      setOutput('note', 'line one\nline two');
    });
    const handover = state.outputs_file;
    assert.ok(handover.startsWith(dir), 'handover file lives under RUNNER_TEMP');
    assert.equal(fs.statSync(handover).mode & 0o777, 0o600);

    const { count, outputs } = runMain(dir);
    assert.equal(count, 4);
    assert.deepEqual(outputs, {
      resolved_sha: 'abc123',
      allowed_endpoints: 'a.example:443',
      invalid_records: 'gone.example:443',
      note: 'line one\nline two',
    });
    assert.equal(fs.existsSync(handover), false, 'main removes the handover file');
  });
});

// State reaches main as an environment variable, which Linux caps at
// 128 KiB per string. The handover must carry a path, not the values.
test('a payload far above the environment limit is handed over intact', () => {
  withRunnerFiles((dir) => {
    const big = Array.from({ length: 40000 }, (_, i) => `host${i}.example.org:443`).join(' ');
    assert.ok(big.length > 512 * 1024);
    const state = runPre(dir, () => setOutput('allowed_endpoints', big));
    assert.ok(state.outputs_file.length < 4096, 'state holds a path, not the payload');
    const { outputs } = runMain(dir);
    assert.equal(outputs.allowed_endpoints, big);
  });
});

test('main publishes nothing when pre handed nothing over', () => {
  withRunnerFiles((dir) => {
    delete process.env.STATE_outputs_file;
    const { count, outputs } = runMain(dir);
    assert.equal(count, 0);
    assert.deepEqual(outputs, {});
  });
});
