// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Unit tests for the 'extra_endpoints' helpers.
//
// Run with: node --test tests/test_extra_endpoints.mjs
//
// Named explicitly, not 'node --test tests/': this directory also
// holds the mirrored Python suite, which node would try to execute.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  mergeExtraEndpoints,
  parseExtraEndpoints,
} from '../src/extra-endpoints.mjs';

test('parses tokens separated by spaces and newlines', () => {
  assert.deepEqual(
    parseExtraEndpoints('a.example.com:443 b.example.com\n*.c.example.com:80'),
    { tokens: ['a.example.com:443', 'b.example.com', '*.c.example.com:80'] },
  );
});

test('strips full-line and inline comments, and CRLF', () => {
  const raw =
    '# DuckDB extensions, until our list carries them\r\n' +
    'extensions.duckdb.org:80  # inline note\r\n' +
    '\tregistry.nordix.org:443\r\n';
  assert.deepEqual(parseExtraEndpoints(raw), {
    tokens: ['extensions.duckdb.org:80', 'registry.nordix.org:443'],
  });
});

test('collapses repeats, keeping first-seen order', () => {
  assert.deepEqual(
    parseExtraEndpoints('b.example.com:443\na.example.com:443\nb.example.com:443'),
    { tokens: ['b.example.com:443', 'a.example.com:443'] },
  );
});

test('empty, blank and comment-only values parse to no tokens', () => {
  for (const raw of ['', '   ', '\n\r\n', '# all fixed upstream\n', '  # x\n# y']) {
    assert.deepEqual(parseExtraEndpoints(raw), { tokens: [] }, JSON.stringify(raw));
  }
});

test('refuses tokens outside the allow-list grammar, naming the input', () => {
  const refused = [
    'evil.com:443;whoami',
    '*',
    '*:443',
    'a.example.com:443\nFOO=bar',
    '"quoted.example.com"',
  ];
  for (const raw of refused) {
    const r = parseExtraEndpoints(raw);
    assert.equal(r.tokens, undefined, JSON.stringify(raw));
    assert.match(r.error, /^Input 'extra_endpoints' rejected token '/);
    assert.match(r.error, /must be host\[:port\] or \*\.host\[:port\]/);
  }
  assert.match(parseExtraEndpoints('a.example.com:443\nFOO=bar').error, /'FOO=bar'/);
});

test('refuses ports outside 1-65535', () => {
  for (const raw of ['evil.com:99999', 'evil.com:0', 'evil.com:00000']) {
    const r = parseExtraEndpoints(raw);
    assert.match(r.error, /'extra_endpoints'.*port out of range 1-65535/, raw);
  }
  assert.deepEqual(parseExtraEndpoints('ok.example.com:65535'), {
    tokens: ['ok.example.com:65535'],
  });
});

test('splits the extra entries into added and redundant', () => {
  const loaded = ['github.com:443', 'api.github.com:443'];
  const r = mergeExtraEndpoints(loaded, ['registry.nordix.org:443', 'github.com:443']);
  assert.deepEqual(r.tokens, [
    'github.com:443',
    'api.github.com:443',
    'registry.nordix.org:443',
  ]);
  assert.deepEqual(r.added, ['registry.nordix.org:443']);
  assert.deepEqual(r.redundant, ['github.com:443']);
  assert.equal(r.baselineDuplicates, 0);
});

test('every entry redundant leaves the loaded list as it was', () => {
  const loaded = ['github.com:443', 'api.github.com:443'];
  const r = mergeExtraEndpoints(loaded, ['api.github.com:443']);
  assert.deepEqual(r.tokens, loaded);
  assert.deepEqual(r.added, []);
  assert.deepEqual(r.redundant, ['api.github.com:443']);
});

test('reports duplicates collapsed out of the loaded list', () => {
  const r = mergeExtraEndpoints(
    ['github.com:443', 'github.com:443'],
    ['github.com:443'],
  );
  assert.deepEqual(r.tokens, ['github.com:443']);
  assert.equal(r.baselineDuplicates, 1);
  assert.deepEqual(r.redundant, ['github.com:443']);
});
