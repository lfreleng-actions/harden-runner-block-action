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
  checkResolvedTrust,
  describeSource,
  mergeAllowLists,
} from '../src/supplemental.mjs';

test('specOrgAndRef splits org and ref', () => {
  assert.deepEqual(specOrgAndRef('onap/.github@main'), { org: 'onap', ref: 'main' });
  assert.deepEqual(specOrgAndRef('onap//'), { org: 'onap', ref: '' });
  assert.deepEqual(specOrgAndRef('onap'), { org: 'onap', ref: '' });
  // A bare subpath derives the org from the workflow.
  assert.deepEqual(specOrgAndRef('//custom/list.txt'), { org: '', ref: '' });
});

// The resolver strips a trailing ' #...' comment before it splits on
// '@'. Anything here that did not would read '42' as a ref, call an
// unpinned spec pinned, and skip the trust rule entirely.
test('specOrgAndRef strips a trailing comment before reading the ref', () => {
  assert.deepEqual(
    specOrgAndRef('onap//  # see ticket ABC@42'),
    { org: 'onap', ref: '' },
  );
  assert.deepEqual(
    specOrgAndRef('  onap/.github@v1.2.3\t# pinned deliberately  '),
    { org: 'onap', ref: 'v1.2.3' },
  );
  // A '#' without leading whitespace is part of the spec, not a comment,
  // which is also how the resolver reads it.
  assert.equal(specOrgAndRef('onap//list#1.txt').ref, '');
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

// Writing '@HEAD' by hand is exactly as unpinned as writing no ref, and
// it is the value the resolver reports back for both.
test('an explicit @HEAD counts as unpinned', () => {
  assert.equal(checkSupplementalTrust('onap//@HEAD', false, 'onap').ok, false);
  assert.equal(checkSupplementalTrust('onap//@HEAD', true, 'onap').ok, true);
  assert.equal(
    checkSupplementalTrust('lfreleng-actions//@HEAD', true, 'onap').ok,
    false,
  );
});

// A comment that smuggles an '@' must not be able to buy trust that the
// bare spec would not have been granted.
test('a comment cannot disguise an unpinned cross-org supplemental', () => {
  const spec = 'lfreleng-actions//  # rotated by ops@example.com';
  assert.equal(checkSupplementalTrust(spec, false, 'onap').ok, false);
  const r = checkSupplementalTrust(spec, true, 'onap');
  assert.equal(r.ok, false);
  assert.match(r.reason, /permitted only within/);
});

// The authoritative check: the resolver reports the org it validated and
// the ref it fetched, so the trust rule no longer rests on two parsers
// agreeing with one another.
test('checkResolvedTrust applies the rule to the resolver output', () => {
  const pinned = { hostOrg: 'lfreleng-actions', ref: 'v0.12.2' };
  assert.equal(checkResolvedTrust(pinned, false, 'onap').ok, true);

  const sameOrgHead = { hostOrg: 'onap', ref: 'HEAD' };
  assert.equal(checkResolvedTrust(sameOrgHead, true, 'onap').ok, true);
  assert.equal(checkResolvedTrust(sameOrgHead, false, 'onap').ok, false);

  const crossOrgHead = { hostOrg: 'lfreleng-actions', ref: 'HEAD' };
  const r = checkResolvedTrust(crossOrgHead, true, 'onap');
  assert.equal(r.ok, false);
  assert.match(r.reason, /permitted only within/);
});

test('describeSource names the file, not the search chain', () => {
  assert.equal(
    describeSource({
      host_org: 'onap',
      repo: '.github',
      ref: 'main',
      matched_path: '.github/harden-runner/onap/allow_list.txt',
    }),
    'onap/.github//.github/harden-runner/onap/allow_list.txt@main',
  );
  // Nothing matched: there is no file to name.
  assert.equal(describeSource({ host_org: 'onap', matched_path: '' }), '');
});

// The grammar is '<source>//<subpath>@<ref>', so the subpath precedes
// the ref. Getting that backwards yields a ref of '<ref>//<path>', and
// because REF_RE permits '/' the mistake survives validation and only
// surfaces at the git fetch. A coordinate nobody can paste back into
// supplemental_config is not worth reporting, so assert the order
// directly rather than relying on the string comparison above.
test('describeSource emits a coordinate that round-trips', () => {
  const source = describeSource({
    host_org: 'onap',
    repo: '.github',
    ref: 'v1.4.0',
    matched_path: 'configs/list.txt',
  });
  const { org, ref } = specOrgAndRef(source);
  assert.equal(org, 'onap');
  assert.equal(ref, 'v1.4.0', 'the ref must survive a re-parse intact');
  assert.ok(
    source.indexOf('//') < source.indexOf('@'),
    `'//' must precede '@' in ${source}`,
  );
});

test('mergeAllowLists de-duplicates and keeps first-seen order', () => {
  const merge = mergeAllowLists(
    ['github.com:443', 'api.github.com:443', 'nexus.onap.org:443'],
    ['registry.nordix.org:443', 'nexus.onap.org:443', 'nexus3.onap.org:10001'],
  );
  assert.deepEqual(merge.tokens, [
    'github.com:443',
    'api.github.com:443',
    'nexus.onap.org:443',
    'registry.nordix.org:443',
    'nexus3.onap.org:10001',
  ]);
  assert.equal(merge.added, 2);
  assert.equal(merge.overlap, 1);
  assert.equal(merge.supplementalUnique, 3);
  assert.equal(merge.baselineDuplicates, 0);
});

// The migration path the de-duplication exists to support: an entry may
// sit in both lists while it moves from one to the other.
test('a fully overlapping supplemental changes nothing', () => {
  const baseline = ['a:443', 'b:443'];
  const merge = mergeAllowLists(baseline, ['b:443', 'a:443']);
  assert.deepEqual(merge.tokens, baseline);
  assert.equal(merge.added, 0);
  assert.equal(merge.overlap, 2);
});

test('mergeAllowLists handles empty inputs on either side', () => {
  assert.deepEqual(mergeAllowLists([], ['a:443']).tokens, ['a:443']);
  assert.deepEqual(mergeAllowLists(['a:443'], []).tokens, ['a:443']);
  assert.deepEqual(mergeAllowLists([], []).tokens, []);
  assert.equal(mergeAllowLists(['a:443'], []).added, 0);
});

// The resolver validates tokens without de-duplicating them, so either
// list may repeat an entry. These two cases are why the counts come from
// set membership rather than from subtracting array lengths.
test('a duplicate inside the baseline does not hide a real addition', () => {
  // Length arithmetic reports 3 - 3 = 0 added here, and the merged list
  // would then never be re-published, leaving the outputs describing a
  // list the job is not enforcing.
  const merge = mergeAllowLists(['a:443', 'b:443', 'a:443'], ['c:443']);
  assert.deepEqual(merge.tokens, ['a:443', 'b:443', 'c:443']);
  assert.equal(merge.added, 1, 'c:443 is genuinely new');
  assert.equal(merge.baselineDuplicates, 1);
  assert.equal(merge.overlap, 0);
});

test('duplicates inside the supplemental do not inflate the overlap', () => {
  const merge = mergeAllowLists(['a:443'], ['b:443', 'b:443', 'a:443']);
  assert.deepEqual(merge.tokens, ['a:443', 'b:443']);
  assert.equal(merge.added, 1);
  assert.equal(merge.overlap, 1, 'only a:443 was already present');
  assert.equal(merge.supplementalUnique, 2);
  // The figures reported to a reader must account for each other.
  assert.equal(merge.added + merge.overlap, merge.supplementalUnique);
});

test('a baseline of only duplicates still collapses', () => {
  const merge = mergeAllowLists(['a:443', 'a:443', 'a:443'], []);
  assert.deepEqual(merge.tokens, ['a:443']);
  assert.equal(merge.baselineDuplicates, 2);
  assert.equal(merge.added, 0);
});
