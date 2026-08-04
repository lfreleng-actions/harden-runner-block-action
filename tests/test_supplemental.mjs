// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Unit tests for the supplemental allow-list helpers.
//
// NOT a synchronised file: this logic belongs to harden-runner-block-action
// alone and is deliberately absent from the mirrored resolver.
//
// Run with: node --test tests/test_supplemental.mjs
//
// Named explicitly, not 'node --test tests/': this directory also
// holds the mirrored Python suite, which node would try to execute.

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  specOrgAndRef,
  checkSupplementalTrust,
  mergeTokens,
} from '../src/supplemental.mjs';

test('specOrgAndRef splits org and ref', () => {
  assert.deepEqual(specOrgAndRef('onap/.github@main'), { org: 'onap', ref: 'main' });
  assert.deepEqual(specOrgAndRef('onap//'), { org: 'onap', ref: '' });
  assert.deepEqual(specOrgAndRef('onap'), { org: 'onap', ref: '' });
  // A bare subpath derives the org from the workflow.
  assert.deepEqual(specOrgAndRef('//custom/list.txt'), { org: '', ref: '' });
});

test('a pinned supplemental is allowed from any org', () => {
  for (const unpinned of [true, false]) {
    const r = checkSupplementalTrust('lfreleng-actions/.github@v0.12.2', unpinned, 'onap');
    assert.equal(r.ok, true, `pinned cross-org should pass (unpinned=${unpinned})`);
  }
});

test('an unpinned supplemental is refused unless explicitly permitted', () => {
  const r = checkSupplementalTrust('onap/.github//', false, 'onap');
  assert.equal(r.ok, false);
  assert.match(r.reason, /no '@ref'/);
});

test('an unpinned supplemental is allowed within the workflow org', () => {
  for (const spec of ['onap//', 'onap/.github//', '//custom/list.txt']) {
    const r = checkSupplementalTrust(spec, true, 'onap');
    assert.equal(r.ok, true, `${spec} should be allowed for its own org`);
  }
});

// The central rule: mutability is confined to the org that already
// controls the workflow. Cross-org unpinned would let a third party
// widen egress with no review here and nothing in a pin to audit.
test('an unpinned supplemental is refused across orgs', () => {
  const r = checkSupplementalTrust('lfreleng-actions/.github//', true, 'onap');
  assert.equal(r.ok, false);
  assert.match(r.reason, /permitted only within/);
  assert.match(r.reason, /lfreleng-actions/);
});

test('a lookalike org does not satisfy the same-org rule', () => {
  // Guards against a prefix/substring comparison creeping in.
  for (const spec of ['onap-evil//', 'not-onap//', 'ona//']) {
    const r = checkSupplementalTrust(spec, true, 'onap');
    assert.equal(r.ok, false, `${spec} must not be treated as 'onap'`);
  }
});

test('mergeTokens de-duplicates and keeps first-seen order', () => {
  const merged = mergeTokens(
    ['github.com:443', 'api.github.com:443', 'nexus.onap.org:443'],
    ['registry.nordix.org:443', 'nexus.onap.org:443', 'nexus3.onap.org:10001'],
  );
  assert.deepEqual(merged, [
    'github.com:443',
    'api.github.com:443',
    'nexus.onap.org:443',
    'registry.nordix.org:443',
    'nexus3.onap.org:10001',
  ]);
});

// The migration path the de-duplication exists to support: an entry may
// sit in both lists while it moves from one to the other.
test('a fully overlapping supplemental changes nothing', () => {
  const baseline = ['a:443', 'b:443'];
  assert.deepEqual(mergeTokens(baseline, ['b:443', 'a:443']), baseline);
});

test('mergeTokens handles empty inputs on either side', () => {
  assert.deepEqual(mergeTokens([], ['a:443']), ['a:443']);
  assert.deepEqual(mergeTokens(['a:443'], []), ['a:443']);
  assert.deepEqual(mergeTokens([], []), []);
});
