// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Linux Foundation
//
// Pure helpers for the supplemental allow-list feature.
//
// Kept out of pre.mjs so they can be unit-tested without executing the
// action, and deliberately NOT placed in resolve_config_source.py: that
// module is mirrored byte-for-byte into python-audit-action and any
// change there needs paired pull requests. Merging two resolved lists
// is this action's concern alone, so it does not belong in the shared
// resolver.

// Parse the org and ref out of a `config` spec.
//
// Deliberately minimal: the resolver owns the real grammar and
// re-validates everything it fetches. This only answers two questions --
// which org does the spec name, and did the caller pin a ref.
export function specOrgAndRef(spec) {
  const [source, ref = ''] = spec.split('@');
  const repospec = source.split('//')[0].replace(/^\/+|\/+$/g, '');
  const org = repospec === '' ? '' : repospec.split('/')[0];
  return { org, ref };
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
export function checkSupplementalTrust(spec, unpinned, workflowOrg) {
  const { org, ref } = specOrgAndRef(spec);

  if (ref !== '') {
    return { ok: true };
  }
  if (!unpinned) {
    return {
      ok: false,
      reason:
        "supplemental_config has no '@ref'; pin it, or set " +
        'supplemental_unpinned: true to follow the default branch',
    };
  }
  // An empty org means "derive from the workflow org", same-org by
  // construction.
  if (org !== '' && org !== workflowOrg) {
    return {
      ok: false,
      reason:
        'unpinned supplemental lists are permitted only within the ' +
        `workflow's own org: '${org}' is not '${workflowOrg}'. Pin the ` +
        `supplemental to a ref, or host it in '${workflowOrg}'`,
    };
  }
  return { ok: true };
}

// Merge baseline and supplemental tokens, keeping first-seen order.
//
// Overlap between the two lists is expected rather than exceptional, and
// de-duplicating is what makes an incremental migration possible: a
// project can copy an entry into its supplemental list, confirm nothing
// breaks, and have it removed from the shared baseline later, without
// either list changing in lockstep.
export function mergeTokens(baseline, supplemental) {
  const seen = new Set();
  const merged = [];
  for (const token of [...baseline, ...supplemental]) {
    if (seen.has(token)) continue;
    seen.add(token);
    merged.push(token);
  }
  return merged;
}
