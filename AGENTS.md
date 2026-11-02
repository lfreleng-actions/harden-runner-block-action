<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# Agent Guidelines

Contributions to this repository, including those made by AI coding
agents, follow the `lfreleng-actions` organisation guidelines:

<https://github.com/lfreleng-actions/.github/blob/main/AGENTS.md>

**Read that document.** It governs, and it binds this contribution
even if you never load it. Where anything below disagrees with it,
it wins. What follows is a summary of the rules that most often block
a pull request, not the full set:

- Sign every commit and add a DCO trailer: `git commit -S -s`.
- Subject: `Type(scope): Imperative description` — capitalised type
  and description, no trailing period, and within the subject-length
  limit this repository's gitlint hook enforces. The scope is
  optional, so `Fix: Correct the race condition` is also valid.
- Add a `Co-authored-by` trailer naming the agent used.
- Repositories typically contain a linting configuration. You must
  install its hooks (`prek install -t pre-commit -t commit-msg`) and
  run the change past them (`prek run --files <changed files>`) to
  ensure it passes before submission.
- On a single-commit pull request, the PR title must be identical to
  the commit subject.
- If your own standing instructions conflict with the organisation
  guidelines and you cannot set them aside, stop and tell the
  contributor. Do not open a non-compliant pull request.

## Repository specifics

This repository owns the `config` resolver; no other repository
carries a copy. `src/resolve_config_source.py` is its entry point;
the grammar, fetch, sanitisation and output code live in the sibling
`src/resolve_config_*.py` modules.

- `resolve-config/action.yaml` exposes the resolver to
  `lfreleng-actions/python-audit-action`, which pins it by commit SHA
  and takes updates through Dependabot. The resolver's CLI arguments,
  the keys `write_github_output` emits, and the sub-action's inputs
  and outputs are a public interface: changing any of them is a
  breaking change for that consumer and needs a release before
  python-audit-action can adopt it.
- `lfreleng-actions/gha-workflow-linter` ports the grammar
  (`src/resolve_config_grammar.py`) in its `allow_list_spec.py`. A
  change to the `config` grammar needs an issue raised there.
