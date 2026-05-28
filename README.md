<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# 🛡️ Harden Runner Block Action

<!-- prettier-ignore-start -->
<!-- markdownlint-disable-next-line MD013 -->
[![Linux Foundation](https://img.shields.io/badge/Linux-Foundation-blue)](https://linuxfoundation.org/) [![Source Code](https://img.shields.io/badge/GitHub-100000?logo=github&logoColor=white&color=blue)](https://github.com/lfreleng-actions/harden-runner-block-action) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![pre-commit.ci status badge]][pre-commit.ci results page] [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lfreleng-actions/harden-runner-block-action/badge)](https://scorecard.dev/viewer/?uri=github.com/lfreleng-actions/harden-runner-block-action)
<!-- prettier-ignore-end -->

A Node.js GitHub Action that loads an allowed-endpoints egress
allow-list from a local file or remote URL, sanitises it, and
publishes it as an environment variable (default
`CONNECTION_ALLOW_LIST`) that a sibling
[step-security/harden-runner](https://github.com/step-security/harden-runner)
step can consume in `block` egress mode.

## Why this action exists

We deploy `step-security/harden-runner` across all repositories in
the `lfreleng-actions` GitHub organisation and want to flip its
policy from `audit` to `block` everywhere using a shared allow-list.

Organisation-level GitHub variables (such as
`CONNECTION_ALLOW_LIST`) do **not** reach workflows running on PRs
from forks — they behave like secrets in that context. When the
variable holds no value, harden-runner falls back to a closed
default policy and breaks every workflow that needs network access.

This action sidesteps that limitation by loading the allow-list
out-of-band, from a file already checked into the repository, from
an explicit URL, or from a default URL constructed from the
resolved org name. **No org secret/variable context needed.**

## Why a Node.js action

`step-security/harden-runner` is a JS action with a `pre:` lifecycle
hook that configures the network filter from `allowed-endpoints`
**before any main step runs**. The GitHub Actions runner executes
**every** `pre:` hook upfront, in declaration order, before
**any** `main` step. The env var that harden-runner consumes must
exist before any other action's `pre` runs — which means the step
that publishes it must itself be a Node.js (or Docker) action with
its own `pre:` hook, since composite actions cannot use `pre:` and
their `main` runs in the main phase.

This action publishes `$CONNECTION_ALLOW_LIST` from its `pre:` hook
to meet that ordering constraint.

## How to use this action

The canonical workflow is two steps: this action loads the
allow-list, then `step-security/harden-runner` consumes it in
`block` mode.

<!-- markdownlint-disable MD046 MD013 -->

```yaml
steps:
  - uses: lfreleng-actions/harden-runner-block-action@main
    with:
      org: 'lfreleng-actions'

  - uses: step-security/harden-runner@ab7a9404c0f3da075243ca237b5fac12c98deaa5  # v2.19.3
    with:
      egress-policy: block
      allowed-endpoints: ${{ env.CONNECTION_ALLOW_LIST }}
```

With no `allow_list_path`/`url` inputs, the action fetches the allow-list from:

`https://raw.githubusercontent.com/<repository_owner>/.github/HEAD/.github/harden-runner/<repository_owner>/allow_list.txt`

### Local file path (highest precedence)

If you set `allow_list_path`, the action ignores `url` and `org`.
The layout below mirrors the default URL structure
(`.github/harden-runner/<owner>/allow_list.txt`), so the same file
can serve both the local `allow_list_path:` consumer in the
repository and the canonical URL fetched by other repositories in
the same organisation:

> [!WARNING]
> When the workflow runs on `pull_request` (or `pull_request_target`
> with the PR head checked out), `allow_list_path` resolves against
> the PR's tree. A fork PR can widen the allow-list by editing the
> file. For untrusted PR contexts prefer the default URL mode
> (fetched from a trusted org's `.github` repository), or
> explicitly check out the base ref before referencing the file.

```yaml
steps:
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
  - uses: lfreleng-actions/harden-runner-block-action@main
    with:
      allow_list_path: ".github/harden-runner/${{ github.repository_owner }}/allow_list.txt"
  - uses: step-security/harden-runner@ab7a9404c0f3da075243ca237b5fac12c98deaa5  # v2.19.3
    with:
      egress-policy: block
      allowed-endpoints: ${{ env.CONNECTION_ALLOW_LIST }}
```

<!-- markdownlint-enable MD046 MD013 -->

## Inputs

<!-- markdownlint-disable MD013 -->

| Name              | Required | Default                 | Description                                                                                                                                                      |
| ----------------- | -------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allow_list_path` | No       | _empty_                 | Local filesystem path to an allow-list file. Takes precedence over `url` and `org`. Must not contain newline characters.                                         |
| `url`             | No       | _empty_                 | Remote URL to download. Ignored when `allow_list_path` has a value. Must not contain newline characters.                                                         |
| `org`             | No       | _empty_                 | GitHub org used to construct the default URL when you supply neither `allow_list_path` nor `url`. Defaults at runtime to `github.repository_owner` when omitted. |
| `env_var_name`    | No       | `CONNECTION_ALLOW_LIST` | Name of the environment variable published to later steps. Must match `^[A-Z_][A-Z0-9_]*$` (uppercase letters, digits, underscores).                             |

<!-- markdownlint-enable MD013 -->

## Outputs

<!-- markdownlint-disable MD013 -->

| Name                | Description                                                                       |
| ------------------- | --------------------------------------------------------------------------------- |
| `allowed_endpoints` | The sanitised, space-separated allowed-endpoints allow-list string.               |
| `source`            | One of `path`, `url`, `default-url`.                                              |
| `resolved_url`      | The URL the action used when fetching remotely. Empty when source was `path`.     |

<!-- markdownlint-enable MD013 -->

## Allow-list file format

The allow-list must consist of `host[:port]` tokens separated by
whitespace. Tokens may span more than one line. The parser strips
comments introduced by `#`, whether they appear as a full-line
comment or as a trailing/inline comment after whitespace on a
non-comment line: the parser strips everything from the `#` to
end-of-line.

Allowed token characters:

- A bare host of `[A-Za-z0-9]` followed by zero or more
  `[A-Za-z0-9.-]` characters.
- A subdomain wildcard of the form `*.<host>` (e.g.
  `*.githubusercontent.com`). A bare `*` or `*:<port>` is
  **rejected** — a single-asterisk wildcard would let
  harden-runner allow every host on the internet and defeat
  block mode.
- Optional `:<port>` suffix where `<port>` is 1–5 digits AND a
  real TCP/UDP port value in the range 1–65535. The sanitiser
  rejects tokens such as `evil.com:0`, `evil.com:00000` or
  `evil.com:99999` rather than passing them through to
  harden-runner.

The action rejects any token containing other characters (shell
metacharacters, quotes, backticks, semicolons, etc.) and fails. The
strict allow-list guards against passing untrusted content from a
remote file into the workflow environment.

Example:

<!-- markdownlint-disable MD046 -->

```text
# lfreleng-actions allow-list
github.com:443
api.github.com:443
*.githubusercontent.com:443
pypi.org:443
files.pythonhosted.org:443
```

<!-- markdownlint-enable MD046 -->

## Implementation details

The action is a Node.js (`node20`) action with a `pre:` hook and a
near-empty `main:` hook:

1. **`pre:` (src/pre.mjs)** does all the real work, in the pre
   lifecycle phase:
   - **Resolve** the source: `allow_list_path` → `url` → constructed
     default URL. The action rejects newline characters in
     `allow_list_path`/`url` inputs to keep `$GITHUB_OUTPUT` and
     `$GITHUB_ENV` writes safe from injection.
   - **Read or fetch** the allow-list (file read for
     `allow_list_path`, `https.request` with redirect handling and
     a 15s timeout for URL/default-url).
   - **Sanitise** the content (drop BOM/comments, collapse
     whitespace, check every token against a strict allow-list and
     port range).
   - **Publish** the result as `$<env_var_name>` (via
     `$GITHUB_ENV`) and as a step output, plus a step-summary
     line.
2. **`main:` (src/main.mjs)** is a near-no-op: it prints a single
   confirmation line so users glancing at the log can see the
   loader has done its work. The pre step keeps the HTTPS
   response in memory and writes no temp file, so `main` has
   nothing to clean up.

The script has **no npm dependencies**: it uses Node's built-in
modules (`fs`, `crypto`, `https`, `url`) and talks to the runner via
the documented `$GITHUB_ENV` / `$GITHUB_OUTPUT` /
`$GITHUB_STEP_SUMMARY` files and `::error::` workflow commands. No
build pipeline, no bundling, no `dist/` directory.

## Notes

- This action needs **no** organisation secret or variable to work
  — that is the whole point. It behaves the same way for PRs raised
  from forks as it does for direct branches.
- If you customise `env_var_name`, make sure the downstream
  harden-runner step reads `${{ env.<that-name> }}` to match.

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/harden-runner-block-action/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/harden-runner-block-action/main.svg
