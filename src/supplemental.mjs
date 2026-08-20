// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Pure helpers for the supplemental allow-list feature.
//
// Kept out of config-flow.mjs so they can be unit-tested without
// executing the action or spawning the resolver, and deliberately NOT
// placed in resolve_config_source.py: that module is mirrored
// byte-for-byte into python-audit-action and any change there needs
// paired pull requests. Merging two resolved lists is this action's
// concern alone, so it does not belong in the shared resolver.

// A trailing ' #...' comment, exactly as resolve_config_source.py's
// split_comment() defines it: one or more spaces/tabs, '#', to end of
// line. Newlines are deliberately not consumed here either.
const TRAILING_COMMENT_RE = /[ \t]+#[^\r\n]*$/;

// A ref of 'HEAD' is what the resolver substitutes when the caller
// pinned nothing, and writing '@HEAD' explicitly is equally unpinned.
function isUnpinnedRef(ref) {
  return ref === '' || ref === 'HEAD';
}

// Parse the org and ref out of a `config` spec.
//
// Deliberately minimal: the resolver owns the real grammar and
// re-validates everything it fetches. This only answers two questions --
// which org does the spec name, and did the caller pin a ref.
//
// The comment must be stripped first, and for a reason worth stating.
// The resolver strips it before splitting on '@', so a spec such as
// 'lfreleng-actions//  # ticket@42' resolves as unpinned. Splitting on
// '@' without stripping would read '42' as the ref and call the same
// spec pinned -- waving a cross-org, branch-following list straight
// past the rule below. The two parsers have to agree about where the
// spec ends.
export function specOrgAndRef(spec) {
  const bare = String(spec).trim().replace(TRAILING_COMMENT_RE, '');
  const at = bare.indexOf('@');
  const source = at === -1 ? bare : bare.slice(0, at);
  const ref = at === -1 ? '' : bare.slice(at + 1);
  const repospec = source.split('//')[0].replace(/^\/+|\/+$/g, '');
  const org = repospec === '' ? '' : repospec.split('/')[0];
  return { org, ref };
}

// The shared refusal messages, so the pre-flight check and the
// authoritative post-resolution check cannot drift apart in wording.
function refuseUnpinned() {
  return {
    ok: false,
    reason:
      "supplemental_config has no '@ref'; pin it, or set " +
      'supplemental_unpinned: true to follow the default branch',
  };
}

function refuseCrossOrg(org, workflowOrg) {
  return {
    ok: false,
    reason:
      'unpinned supplemental lists are permitted only within the ' +
      `workflow's own org: '${org}' is not '${workflowOrg}'. Pin the ` +
      `supplemental to a ref, or host it in '${workflowOrg}'`,
  };
}

// Decide whether a supplemental spec may be used.
//
// Returns { ok: true } or { ok: false, reason }. The caller turns a
// refusal into a workflow failure; keeping the decision pure makes the
// trust rule testable in isolation.
//
// Pinning is half of this action's trust posture: the resolver treats a
// single non-conforming token as a hard error precisely so untrusted
// remote content cannot widen what a downstream tool accepts. An
// unrestricted unpinned list would let anyone able to merge to another
// org's default branch widen the egress allow-list of these workflows,
// with no review here and nothing in the pin to audit -- inverting the
// threat model of a control that exists to constrain egress.
//
// Same-org is self-trust rather than cross-org trust: onap/* workflows
// may follow onap/.github@main, because an actor who can merge there can
// already alter those workflows directly. Anything cross-org must pin.
//
// This runs before the resolver, so a refusal costs no network fetch and
// names the offending spec. It is not the last word: checkResolvedTrust
// re-applies the same rule to the coordinates the resolver actually
// used.
export function checkSupplementalTrust(spec, unpinned, workflowOrg) {
  const { org, ref } = specOrgAndRef(spec);

  if (!isUnpinnedRef(ref)) {
    return { ok: true };
  }
  if (!unpinned) {
    return refuseUnpinned();
  }
  // An empty org means "derive from the workflow org", same-org by
  // construction.
  if (org !== '' && org !== workflowOrg) {
    return refuseCrossOrg(org, workflowOrg);
  }
  return { ok: true };
}

// Re-apply the trust rule to the coordinates the resolver reported, and
// do it before the tokens are merged.
//
// checkSupplementalTrust parses the spec a second time, in a second
// language, which is precisely how a divergence like the comment bug
// above comes about. This check reads host_org and ref straight out of
// the resolver's own JSON -- the org it validated, and the ref it
// actually fetched -- so agreement between the two parsers stops being
// something the trust rule depends on.
export function checkResolvedTrust({ hostOrg, ref }, unpinned, workflowOrg) {
  if (!isUnpinnedRef(ref)) {
    return { ok: true };
  }
  if (!unpinned) {
    return refuseUnpinned();
  }
  if (hostOrg !== workflowOrg) {
    return refuseCrossOrg(hostOrg, workflowOrg);
  }
  return { ok: true };
}

// Merge baseline and supplemental tokens, keeping first-seen order, and
// report what the merge actually did.
//
// Overlap between the two lists is expected rather than exceptional, and
// de-duplicating is what makes an incremental migration possible: a
// project can copy an entry into its supplemental list, confirm nothing
// breaks, and have it removed from the shared baseline later, without
// either list changing in lockstep.
//
// The counts come from set membership rather than from subtracting array
// lengths, because the resolver validates tokens without de-duplicating
// them and either list may repeat an entry. Length arithmetic gets that
// wrong in both directions: a baseline holding one duplicate makes
// 'merged.length - baseline.length' report nothing added even when the
// supplemental contributed something new, and a supplemental repeating
// an entry inflates any "already in the baseline" figure derived by
// subtraction. Both misreport exactly when someone is reading the log to
// find out what a job allowed.
//
// Returns the merged tokens plus:
//   added               unique supplemental entries not already present
//   overlap             unique supplemental entries already present
//   supplementalUnique  distinct entries in the supplemental (added +
//                       overlap)
//   baselineDuplicates  repeats collapsed out of the baseline itself
export function mergeAllowLists(baseline, supplemental) {
  const seen = new Set();
  const tokens = [];
  for (const token of baseline) {
    if (seen.has(token)) continue;
    seen.add(token);
    tokens.push(token);
  }
  const baselineDuplicates = baseline.length - tokens.length;

  const distinct = new Set(supplemental);
  let added = 0;
  for (const token of distinct) {
    if (seen.has(token)) continue;
    seen.add(token);
    tokens.push(token);
    added += 1;
  }

  return {
    tokens,
    added,
    overlap: distinct.size - added,
    supplementalUnique: distinct.size,
    baselineDuplicates,
  };
}

// Describe where a resolved supplemental came from, in the same grammar
// the 'config' input accepts.
//
// Composed from the resolver's own fields rather than echoing the
// caller's spec. A spec such as 'onap//' names a search chain, not a
// file, so repeating it answers none of the questions worth asking after
// the fact: which repository, which ref, which of the candidate paths
// matched. The form here can be pasted back as an explicit, pinned spec.
//
// Order matters, and it is the reverse of how one would naturally write
// it. The grammar is '<source>//<subpath>@<ref>', so the subpath comes
// before the ref. Emitting '<org>/<repo>@<ref>//<path>' instead parses
// as a ref of '<ref>//<path>' -- and REF_RE permits '/', so that form
// survives validation and fails only later, at the git fetch, with an
// invalid refspec. A coordinate nobody can paste back is not worth
// reporting, so this is built to match the grammar.
export function describeSource(resolved) {
  if (!resolved.matched_path) return '';
  return `${resolved.host_org}/${resolved.repo}` +
    `//${resolved.matched_path}@${resolved.ref || 'HEAD'}`;
}
