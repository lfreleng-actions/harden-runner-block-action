<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation
-->

# 🛡️ Harden Runner Block Action

<!-- prettier-ignore-start -->
<!-- markdownlint-disable-next-line MD013 -->
[![Linux Foundation](https://img.shields.io/badge/Linux-Foundation-blue)](https://linuxfoundation.org/) [![Source Code](https://img.shields.io/badge/GitHub-100000?logo=github&logoColor=white&color=blue)](https://github.com/lfreleng-actions/harden-runner-block-action) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![pre-commit.ci status badge]][pre-commit.ci results page] [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lfreleng-actions/harden-runner-block-action/badge)](https://scorecard.dev/viewer/?uri=github.com/lfreleng-actions/harden-runner-block-action)
<!-- prettier-ignore-end -->

Loads an allowed-endpoints connection allow-list from a local file or remote
URL (with sensible defaults), sanitises it, and publishes it as an
environment variable that a downstream
[step-security/harden-runner](https://github.com/step-security/harden-runner)
step can consume in `block` egress mode.

## Why this action exists

We deploy `step-security/harden-runner` across all repositories in the
`lfreleng-actions` GitHub organisation in the default `audit` mode.
We want to flip the policy to `block` everywhere using a shared
allow-list.

Organisation-level GitHub variables (such as `CONNECTION_ALLOW_LIST`)
do **not** reach workflows running on PRs from forks — they behave
like secrets in that context. When the variable holds no value,
harden-runner falls back to a default closed policy and breaks every
workflow that needs network access.

This action sidesteps that limitation by loading the allow-list
out-of-band, either from a file already checked into the repository
(or downloaded on the runner) or from a public URL that needs no
secret context to access.

## How to use this action

The action is a **composite** that loads, sanitises, and exports the
allow-list as an environment variable (by default
`CONNECTION_ALLOW_LIST`). The calling workflow then invokes
`step-security/harden-runner` directly as a sibling step and passes
the env var as `allowed-endpoints`.

This split exists because GitHub Actions does **not** run the
`pre`/`post` lifecycle hooks of nested actions inside a composite,
and harden-runner relies on its `pre` hook to install the
network-monitoring agent. Calling harden-runner from inside a
composite would bypass that hook, leaving the runner unprotected.
The action stays focused on allow-list loading and leaves
harden-runner invocation to the calling workflow.

<!-- markdownlint-disable MD046 MD013 -->

```yaml
steps:
  - name: "Load connection allow-list"
    # yamllint disable-line rule:line-length
    uses: lfreleng-actions/harden-runner-block-action@main

  - name: "Harden runner (block)"
    # yamllint disable-line rule:line-length
    uses: step-security/harden-runner@ab7a9404c0f3da075243ca237b5fac12c98deaa5  # v2.19.3
    with:
      egress-policy: block
      allowed-endpoints: >
        ${{ env.CONNECTION_ALLOW_LIST }}
```

With defaults, the action fetches the allow-list from:

`https://raw.githubusercontent.com/<repository_owner>/.github/HEAD/.github/harden-runner/<repository_owner>/allow_list.txt`

### Local file path (highest precedence)

When you supply `path`, the action ignores both `url` and `org`. The
layout below mirrors the default URL structure (`.github/harden-runner/
<owner>/allow_list.txt`), so the same file can serve both the local
`path:` consumer in this repository and the canonical URL fetched
by other repositories in the same organisation:

```yaml
steps:
  - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2
  - uses: lfreleng-actions/harden-runner-block-action@main
    with:
      path: ".github/harden-runner/${{ github.repository_owner }}/allow_list.txt"
  - uses: step-security/harden-runner@ab7a9404c0f3da075243ca237b5fac12c98deaa5  # v2.19.3
    with:
      egress-policy: block
      allowed-endpoints: >
        ${{ env.CONNECTION_ALLOW_LIST }}
```

<!-- markdownlint-enable MD046 MD013 -->

## Inputs

<!-- markdownlint-disable MD013 -->

| Name           | Required | Default                 | Description                                                                                                                                           |
| -------------- | -------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `path`         | No       | _empty_                 | Local filesystem path to a allow-list file. Takes precedence over `url` and `org`. Must not contain newline characters.                               |
| `url`          | No       | _empty_                 | Remote URL to download. The action ignores this input when `path` has a value. Must not contain newline characters.                                   |
| `org`          | No       | _empty_                 | GitHub org used to construct the default URL when you supply neither `path` nor `url`. Defaults at runtime to `github.repository_owner` when omitted. |
| `env_var_name` | No       | `CONNECTION_ALLOW_LIST` | Name of the environment variable published to later steps. Must match `^[A-Z_][A-Z0-9_]*$` (uppercase letters, digits, underscores).                  |

<!-- markdownlint-enable MD013 -->

## Outputs

<!-- markdownlint-disable MD013 -->

| Name                | Description                                                         |
| ------------------- | ------------------------------------------------------------------- |
| `allowed_endpoints` | The sanitised, space-separated allowed-endpoints allow-list string. |
| `source`            | One of `path`, `url`, `default-url`.                                |
| `resolved_url`      | The URL the action used when fetching remotely.                     |

<!-- markdownlint-enable MD013 -->

## Allow-list file format

The allow-list must consist of `host[:port]` tokens separated by
whitespace. Tokens may span more than one line. The parser strips
comments introduced by `#`, whether they appear as a full-line
comment or as a trailing/inline comment after whitespace on a
non-comment line: the parser strips everything from the `#` to
end-of-line.

Allowed token characters:

- Letters, digits, dot (`.`), hyphen (`-`)
- Asterisk (`*`) — used by harden-runner for subdomain wildcards, e.g.
  `*.githubusercontent.com:443`
- Optional `:<port>` suffix where `<port>` is 1–5 digits AND a
  real TCP/UDP port value in the range 1–65535. The sanitiser
  rejects tokens such as `evil.com:0`, `evil.com:00000` or
  `evil.com:99999` rather than passing them through to harden-runner.

The action rejects any token containing other characters (shell
metacharacters, quotes, backticks, semicolons, etc.) and fails. This
guards against passing untrusted content from a remote file into the
workflow environment.

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

The action is composite and runs four logical steps:

1. **Resolve** the source: `path` → `url` → constructed default URL.
   The action rejects newline characters in `path`/`url` inputs to
   keep `$GITHUB_OUTPUT` writes safe from injection.
2. **Download** via
   [`lfreleng-actions/url-download-action`](https://github.com/lfreleng-actions/url-download-action)
   when the source is a URL. The action invokes `mktemp` under
   `$RUNNER_TEMP` to pick the download target, so concurrent
   invocations never share a file.
3. **Sanitise** the content (drop BOM/comments, collapse whitespace,
   check every token against a strict allow-list) and publish the
   result as an env var and step output.
4. **Cleanup** — after a URL download, the action removes the
   temporary file from the runner (the sanitised value lives on as an
   env var and step output). The action leaves user-supplied local
   `path` files alone.

The calling workflow is then responsible for invoking
`step-security/harden-runner` as a sibling step (see the usage
example above).

## Notes

- This action needs **no** organisation secret or variable to work —
  that is the whole point. It behaves the same way for PRs raised
  from forks as it does for direct branches.
- If you customise `env_var_name`, make sure the downstream
  harden-runner step reads `${{ env.<that-name> }}` to match.

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/harden-runner-block-action/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/harden-runner-block-action/main.svg
