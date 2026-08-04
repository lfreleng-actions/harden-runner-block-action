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

| Name                    | Required | Default                 | Description                                                                                                                                                      |
| ----------------------- | -------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allow_list_path`       | No       | _empty_                 | Local filesystem path to an allow-list file. Takes precedence over `url` and `org`. Must not contain newline characters.                                         |
| `url`                   | No       | _empty_                 | Remote URL to download. Ignored when `allow_list_path` has a value. Must not contain newline characters.                                                         |
| `org`                   | No       | _empty_                 | GitHub org used to construct the default URL when you supply neither `allow_list_path` nor `url`. Defaults at runtime to `github.repository_owner` when omitted. |
| `env_var_name`          | No       | `CONNECTION_ALLOW_LIST` | Name of the environment variable published to later steps. Must match `^[A-Z_][A-Z0-9_]*$` (uppercase letters, digits, underscores).                             |
| `config`                | No       | _empty_                 | `uses:`-style coordinate for a git-fetched, SHA-pinnable allow-list. Mutually exclusive with `allow_list_path`, `url` and `org`. See below.                      |
| `token`                 | No       | _empty_                 | Token with `contents:read` for fetching a private host repo via `config`. Leave empty for public repos.                                                          |
| `allow_list_summary`    | No       | `true`                  | Write the allow-list/config block to the job step summary. Set `false` to suppress (e.g. on matrix legs other than the first). See note below.                   |
| `disable_gh_telemetry`  | No       | `true`                  | Publish `GH_TELEMETRY=false` to later steps, turning off GitHub CLI telemetry for the rest of the job. A value the caller set already wins. See note below.      |
| `supplemental_config`   | No       | _empty_                 | A second allow-list, same grammar as `config`. The action merges its endpoints with the baseline instead of replacing them. Requires `config`. See below.        |
| `supplemental_unpinned` | No       | `false`                 | Permit `supplemental_config` to omit `@ref` and follow the default branch. Restricted to the workflow's own org. See below.                                      |
| `supplemental_required` | No       | `false`                 | Treat a missing supplemental list as fatal. The default tolerates absence and continues with the baseline alone.                                                 |

<!-- markdownlint-enable MD013 -->

## Outputs

<!-- markdownlint-disable MD013 -->

| Name                  | Description                                                                                                                                  |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `allowed_endpoints`   | The sanitised, space-separated allowed-endpoints allow-list string. Carries the merged set when a supplemental list contributed endpoints.   |
| `source`              | One of `path`, `url`, `default-url`, `config`.                                                                                               |
| `resolved_url`        | The URL the action used when fetching remotely. Empty for `path` and `config` sources (`config` populates the `resolved_*` outputs instead). |
| `resolved_host_org`   | Host org that supplied the allow-list (`config` mode).                                                                                       |
| `resolved_repo`       | Repository that supplied the allow-list (`config` mode).                                                                                     |
| `resolved_ref`        | Git ref requested for the `config` fetch.                                                                                                    |
| `resolved_sha`        | Exact commit SHA the `config` ref resolved to.                                                                                               |
| `resolved_path`       | In-repo path of the matched `config` file.                                                                                                   |
| `matched_candidate`   | Search candidate that matched: `org-specific`, `family-default`, `sole-org-fallback` or `explicit`.                                          |
| `supplemental_source` | The supplemental list as an explicit, pinnable coordinate: `<org>/<repo>//<path>@<ref>`. Empty when unused or absent.                        |
| `supplemental_count`  | Endpoints read from the supplemental list, before de-duplication against the baseline. Zero when absent; empty when unused.                  |
| `supplemental_sha`    | Commit the action read the supplemental list from. For an unpinned list, the sole audit trail.                                               |

<!-- markdownlint-enable MD013 -->

## Pinned allow-list via `config` (git, SHA-pinnable)

The `config` input is a GitHub-Actions `uses:`-style coordinate that
identifies a remote allow-list file and fetches it with a shallow,
ref-pinned **git** fetch (rather than an unpinned HTTP download). It
supports branches, tags and commit SHAs, so you can pin the
allow-list to an immutable commit, much like an action pin.

> [!IMPORTANT]
> `config` is **mutually exclusive** with `allow_list_path`, `url`
> and `org`. Supplying any of them together with `config` is an
> error.

<!-- markdownlint-disable MD013 -->

```yaml
steps:
  - uses: lfreleng-actions/harden-runner-block-action@main
    with:
      config: 'lfreleng-actions@main'

  - uses: step-security/harden-runner@ab7a9404c0f3da075243ca237b5fac12c98deaa5  # v2.19.3
    with:
      egress-policy: block
      allowed-endpoints: ${{ env.CONNECTION_ALLOW_LIST }}
```

<!-- markdownlint-enable MD013 -->

### `config` grammar

```text
<config> ::= <source> [ "@" <ref> ] [ <ws>+ "#" <comment> ]
<source> ::= [ <host-org> [ "/" <repo> ] ] [ "//" <subpath> ]
```

Defaults applied to anything you omit:

<!-- markdownlint-disable MD013 -->

| Element   | Default                                                               |
| --------- | --------------------------------------------------------------------- |
| host-org  | `github.repository_owner` (when you omit the org)                     |
| repo      | `.github`                                                             |
| directory | `.github/harden-runner/<workflow-org>/` then `.github/harden-runner/` |
| filename  | `allow_list.txt`                                                      |
| ref       | the host repo's default branch (`HEAD`)                               |

<!-- markdownlint-enable MD013 -->

- The `//` separator splits the repository from the in-repo path
  (the same convention Terraform/go-getter use). Text after `//`:
  - **empty** (or no `//`) — default directory search + default
    filename.
  - **bare filename** (no `/`) — overrides the filename, keeps the
    default directory search.
  - **contains a `/`** — an explicit in-repo path; the action skips
    the search and that exact path must exist.
- A `#` preceded by at least one space or tab starts a trailing
  comment; the parser drops everything from that `#` to end of line.
  A `#` with no preceding whitespace forms part of a token
  (so `foo#bar` is a single token, not a comment).
- The output `resolved_sha` always reports the commit the ref
  resolved to, even when you pin a branch or tag.

### Search / fallback chain

When the directory is auto-derived (you did not give an explicit
directory after `//`), the action tries, in order:

1. `.github/harden-runner/<workflow-org>/<filename>` (org-specific)
2. `.github/harden-runner/<filename>` (host-wide family default)
3. `.github/harden-runner/<org>/<filename>` when a **single** org
   directory in the fetched tree carries the file (sole-org fallback)

The first file that exists wins. The sole-org fallback covers forks:
a fork's `.github` repository carries the upstream org's allow-list
at the pinned ref, but the workflow org resolves to the fork owner,
which prevents the org-specific candidate from matching there. With
a single org directory present the choice is unambiguous and the
ref-pinned content is byte-identical to upstream; two or more org
directories keep the miss (the choice would be ambiguous). Explicit
paths never fall back.

Because an empty allow-list would
break egress under block mode, this action treats "no file found"
as a hard error (unlike the sibling `python-audit-action`, which
treats a default-path miss as a soft no-op).

### `config` examples

Assuming the workflow runs in org `onap`:

<!-- markdownlint-disable MD013 -->

| `config` value                         | Fetched from                    | In-repo path (search chain)                                                |
| -------------------------------------- | ------------------------------- | -------------------------------------------------------------------------- |
| `lfreleng-actions@main`                | `lfreleng-actions/.github@main` | `…/harden-runner/onap/allow_list.txt` → `…/harden-runner/allow_list.txt`   |
| `lfit@v1.1.0`                          | `lfit/.github@v1.1.0`           | same chain                                                                 |
| `lfit@ab7a940… # v1.0.0`               | `lfit/.github@<sha>`            | same chain; comment ignored                                                |
| `lfit//custom_list.txt@v1.1.0  # ONAP` | `lfit/.github@v1.1.0`           | `…/harden-runner/onap/custom_list.txt` → `…/harden-runner/custom_list.txt` |
| `lfit//@ab7a940…`                      | `lfit/.github@<sha>`            | default chain + `allow_list.txt`                                           |
| `lfit//configs/onap/list.txt@main`     | `lfit/.github@main`             | `configs/onap/list.txt` (explicit; no search)                              |
| `//team_list.txt@main`                 | `onap/.github@main`             | `…/harden-runner/onap/team_list.txt` → `…/harden-runner/team_list.txt`     |

<!-- markdownlint-enable MD013 -->

### Private host repositories

For a private host-org `.github` repo, pass a token with
`contents:read` on that repo. `GITHUB_TOKEN` grants access to the
current repository alone, so pass a PAT or GitHub App token here:

```yaml
    with:
      config: 'my-private-org@v2.0.0'
      token: ${{ secrets.CONFIG_READ_TOKEN }}
```

> [!NOTE]
> `config` resolution uses the runner's preinstalled `python3` (the
> resolver needs no third-party packages) and shells out to `git` for
> the fetch. GitHub-hosted runners ship both; on self-hosted runners
> `python3` and `git` must sit on `PATH`. Both repositories mirror the
> shared parser `src/resolve_config_source.py`, and changes must land
> as paired pull requests across `harden-runner-block-action` and
> `python-audit-action`.

### Suppressing the step summary on matrix jobs

Each matrix leg is a separate job with its own step summary, so the
allow-list block repeats once per leg. An action cannot detect the
matrix context itself, but the calling workflow can. Set
`allow_list_summary` so a single leg emits the block:

```yaml
    with:
      config: 'lfreleng-actions@main'
      # Emit the allow-list summary from the first matrix leg.
      allow_list_summary: ${{ strategy.job-index == 0 }}
```

Outside a matrix, `strategy.job-index` is empty; use
`${{ !strategy.job-total || strategy.job-index == 0 }}` if a single
template must cover both matrix and non-matrix jobs.

### GitHub CLI telemetry

The action publishes `GH_TELEMETRY=false` to later steps by default.
The `gh` CLI otherwise posts usage events to `cafe.github.com`:

```go
// cli/cli — pkg/cmd/send-telemetry/send_telemetry.go
const defaultTelemetryEndpointURL = "https://cafe.github.com"
```

That endpoint belongs in neither the job nor the allow-list:

- No job needs it. The CLI sends telemetry from a separate hidden
  `gh send-telemetry` subcommand on a two-second timeout, so `gh`
  behaves the same whether the endpoint answers, gets blocked, or
  stays disabled.
- Under `egress-policy: block` the call surfaces as a blocked
  connection, and that noise competes with genuine findings in the run
  insights.
- Allow-listing `cafe.github.com` instead would widen egress across
  every repository sharing the list, so a whole organisation carries
  analytics traffic to quiet one warning.

`GH_TELEMETRY` takes precedence over `DO_NOT_TRACK` in the CLI, so the
one variable covers both opt-outs.

A value the caller set already wins, which keeps `GH_TELEMETRY=log`
usable for debugging:

```yaml
    env:
      GH_TELEMETRY: 'log'   # survives; the action leaves it alone
```

To opt out of the behaviour altogether:

```yaml
    with:
      config: 'lfreleng-actions@main'
      disable_gh_telemetry: false
```

## Supplemental per-org allow-lists

A single shared allow-list grants every endpoint it carries to every
consumer. ONAP needs `registry.nordix.org:443` for its Testcontainers
pulls; adding that to the shared baseline would hand a Nordix registry
to Akraino, O-RAN-SC and everyone else with no use for it.

`supplemental_config` names a second list, in the same grammar as
`config`, whose endpoints are **concatenated** with the baseline rather
than replacing it:

```yaml
    with:
      config: 'lfreleng-actions@v0.11.1'
      supplemental_config: 'onap//@v1.4.0'
```

The action fetches and sanitises each list separately, so a rejected
token names the list it came from. It then merges the results and
de-duplicates them, keeping first-seen order with the baseline first.

The feature stays off unless you name a source. There is no automatic
discovery: reading a security-relevant file nobody asked for makes a
poor default, and naming it costs one line.

> [!NOTE]
> `supplemental_config` requires `config`. It extends the baseline, so
> there has to be a baseline to extend, and the legacy `allow_list_path`
> / `url` sources have no resolver for it to reuse.

### Overlap between the two lists

De-duplication is not tidiness; it buys a migration path. An entry can
sit in both lists while it moves from one to the other: copy it into the
supplemental list, confirm nothing breaks, and drop it from the shared
baseline later. The two lists never have to change in lockstep.

### Unpinned supplements stay inside one org

Pinning is half of this action's trust posture. The resolver treats a
single non-conforming token as a hard error precisely so that remote
content cannot widen what a downstream tool accepts.

Requiring a pin everywhere is nonetheless a real cost: adding one
endpoint would mean bumping a ref in every consuming workflow.
`supplemental_unpinned: true` lifts that, but **restricts the
supplemental list to the workflow's own org**:

<!-- markdownlint-disable MD013 -->

| `supplemental_config`              | `supplemental_unpinned` | Workflow org | Result                  |
| ---------------------------------- | ----------------------- | ------------ | ----------------------- |
| `lfreleng-actions/.github@v0.11.1` | either                  | `onap`       | Allowed: pinned         |
| `onap//`                           | `true`                  | `onap`       | Allowed: same org       |
| `onap/.github//`                   | `false`                 | `onap`       | Refused: needs the flag |
| `lfreleng-actions/.github//`       | `true`                  | `onap`       | Refused: cross-org      |
| `onap-evil//`                      | `true`                  | `onap`       | Refused: lookalike org  |

<!-- markdownlint-enable MD013 -->

Cross-org and unpinned together would mean anyone able to merge to
another org's default branch could widen the egress allow-list of your
workflows, with no review in your repository and nothing in a pin to
audit. For a control whose whole purpose is constraining egress, that
inverts the threat model.

Same-org grants no new trust: whoever can merge to `onap/.github` can
already alter ONAP's workflows directly. The rule is an exact match on
the org, not a prefix, so `onap-evil` is not `onap`.

The action applies the rule twice. First to the spec, before any network
access, which keeps a refusal cheap and names the offending input.
Then to the coordinates the resolver reports back, before the merge
touches a single token. That second check carries the authority, because
it reads the org and ref the resolver actually used rather than a second
parse of the spec.

### When the supplemental list is missing

The action tolerates absence by default, which is what a project that
has not created its list yet needs: it logs the miss and continues with
the baseline alone. Set `supplemental_required: true` where the
supplemental carries endpoints the job genuinely cannot run without, so
its absence fails at once rather than at the first blocked connection.

### Telling the two lists apart afterwards

During an incident, "which list granted this endpoint" is the first
question, so the action reports the supplemental distinctly rather than
folding it into the baseline's figures:

```yaml
    - name: 'Report allow-list provenance'
      run: |
        echo "baseline:     ${{ steps.allow.outputs.resolved_path }}"
        echo "supplemental: ${{ steps.allow.outputs.supplemental_source }}"
        echo "commit:       ${{ steps.allow.outputs.supplemental_sha }}"
```

The action composes `supplemental_source` from the resolved coordinates
rather than echoing the input back: a spec such as `onap//` names a
search chain rather than a file, so repeating it would answer none of
the questions worth asking. The reported form follows the `config`
grammar — `<org>/<repo>//<path>@<ref>`, subpath before ref — so it
pastes straight back into `supplemental_config`.

`supplemental_sha` matters most for an unpinned list, where it forms the
sole audit trail: the spec names a branch, and the branch moves. The
step summary carries the same detail in its own block.

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

The action is a Node.js (`node24`) action with a `pre:` hook and a
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

The pre step spans seven single-purpose ES modules, which the runner
loads directly (relative imports, no resolution step):

<!-- markdownlint-disable MD013 -->

| Module                 | Responsibility                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------ |
| `src/pre.mjs`          | Entrypoint: orchestrates the steps above and publishes outputs.                      |
| `src/inputs.mjs`       | Reads and validates inputs, resolves which source to use.                            |
| `src/fetch.mjs`        | Size-capped HTTPS fetch (redirects, timeout) and local file read.                    |
| `src/sanitise.mjs`     | Token parsing and strict host/port validation.                                       |
| `src/config-flow.mjs`  | Drives the shared Python resolver for the `config` input, and merges a supplemental. |
| `src/supplemental.mjs` | Pure helpers for the supplemental list: spec parsing, the trust rule, the merge.     |
| `src/actions-io.mjs`   | The runner protocol: workflow commands, outputs, env vars, step summary.             |

<!-- markdownlint-enable MD013 -->

## Notes

- This action needs **no** organisation secret or variable to work
  — that is the whole point. It behaves the same way for PRs raised
  from forks as it does for direct branches.
- If you customise `env_var_name`, make sure the downstream
  harden-runner step reads `${{ env.<that-name> }}` to match.

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/harden-runner-block-action/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/harden-runner-block-action/main.svg
