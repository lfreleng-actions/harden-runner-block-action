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

| Name                    | Required | Default                 | Description                                                                                                                                                                                                                              |
| ----------------------- | -------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `allow_list_path`       | No       | _empty_                 | Local filesystem path to an allow-list file. Takes precedence over `url` and `org`. Must not contain newline characters.                                                                                                                 |
| `url`                   | No       | _empty_                 | Remote URL to download. Ignored when `allow_list_path` has a value. Must not contain newline characters.                                                                                                                                 |
| `org`                   | No       | _empty_                 | GitHub org used to construct the default URL when you supply neither `allow_list_path` nor `url`. Defaults at runtime to `github.repository_owner` when omitted.                                                                         |
| `env_var_name`          | No       | `CONNECTION_ALLOW_LIST` | Name of the environment variable published to later steps. Must match `^[A-Z_][A-Z0-9_]*$` (uppercase letters, digits, underscores), and must not be `HARDEN_RUNNER_EGRESS_POLICY` or `GH_TELEMETRY`, which the action publishes itself. |
| `config`                | No       | _empty_                 | `uses:`-style coordinate for a git-fetched, SHA-pinnable allow-list. Mutually exclusive with `allow_list_path`, `url` and `org`. See below.                                                                                              |
| `token`                 | No       | _empty_                 | Token with `contents:read` for fetching a private host repo via `config`. Leave empty for public repos.                                                                                                                                  |
| `allow_list_summary`    | No       | `true`                  | Write the allow-list/config block to the job step summary. Set `false` to suppress (e.g. on matrix legs other than the first). See note below.                                                                                           |
| `disable_gh_telemetry`  | No       | `true`                  | Publish `GH_TELEMETRY=false` to later steps, turning off GitHub CLI telemetry for the rest of the job. A value the caller set already wins. See note below.                                                                              |
| `supplemental_config`   | No       | _empty_                 | A second allow-list, same grammar as `config`. The action merges its endpoints with the baseline instead of replacing them. Requires `config`. See below.                                                                                |
| `supplemental_unpinned` | No       | `false`                 | Permit `supplemental_config` to omit `@ref` and follow the default branch. Restricted to the workflow's own org. See below.                                                                                                              |
| `supplemental_required` | No       | `false`                 | Treat a missing supplemental list as fatal. The default tolerates absence and continues with the baseline alone.                                                                                                                         |
| `invalid_records`       | No       | `filter`                | What to do with entries whose hostname does not resolve: `filter`, `warning`, `error` or `ignore`. See [DNS validation of the allow-list](#dns-checks-on-the-allow-list).                                                                |

<!-- markdownlint-enable MD013 -->

## Outputs

<!-- markdownlint-disable MD013 -->

| Name                    | Description                                                                                                                                  |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `allowed_endpoints`     | The sanitised, space-separated allowed-endpoints allow-list string. Carries the merged set when a supplemental list contributed endpoints.   |
| `source`                | One of `path`, `url`, `default-url`, `config`.                                                                                               |
| `resolved_url`          | The URL the action used when fetching remotely. Empty for `path` and `config` sources (`config` populates the `resolved_*` outputs instead). |
| `resolved_host_org`     | Host org that supplied the allow-list (`config` mode).                                                                                       |
| `resolved_repo`         | Repository that supplied the allow-list (`config` mode).                                                                                     |
| `resolved_ref`          | Git ref requested for the `config` fetch.                                                                                                    |
| `resolved_sha`          | Exact commit SHA the `config` ref resolved to.                                                                                               |
| `resolved_path`         | In-repo path of the matched `config` file.                                                                                                   |
| `matched_candidate`     | Search candidate that matched: `org-specific`, `family-default`, `sole-org-fallback` or `explicit`.                                          |
| `supplemental_source`   | The supplemental list as an explicit, pinnable coordinate: `<org>/<repo>//<path>@<ref>`. Empty when unused or absent.                        |
| `supplemental_count`    | Endpoints read from the supplemental list, before de-duplication against the baseline. Zero when absent; empty when unused.                  |
| `supplemental_sha`      | Commit the action read the supplemental list from. For an unpinned list, the sole audit trail.                                               |
| `invalid_records`       | Space-separated entries whose hostname definitively failed DNS validation. Empty when none did.                                              |
| `invalid_count`         | Number of entries in `invalid_records`.                                                                                                      |
| `indeterminate_records` | Space-separated entries that reached no DNS verdict after retries.                                                                           |
| `indeterminate_count`   | Number of entries in `indeterminate_records`.                                                                                                |
| `egress_policy`         | `audit` when `invalid_records: warning` found invalid entries, otherwise `block`. Also published as `HARDEN_RUNNER_EGRESS_POLICY`.           |

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

## DNS checks on the allow-list

Before enabling block mode, harden-runner's agent resolves every
non-wildcard entry in `allowed-endpoints`. When **any** of them fails
to resolve, the agent reverts its firewall and DNS changes and the job
continues with **no egress filtering and no egress monitoring**, while
the harden-runner step still reports success. One stale hostname in a
shared allow-list disables block mode in every job that consumes it,
and the log carries nothing more than this:

```text
Error resolving allowed domain ... unable to resolve domain jenkins.example.org.
Reverted changes
```

So the action resolves every hostname in the allow-list first, the
same way the agent will, and applies the `invalid_records` policy:

<!-- markdownlint-disable MD013 -->

| Mode               | Allow-list published    | Egress policy | Step   | Reporting (first invocation)                     |
| ------------------ | ----------------------- | ------------- | ------ | ------------------------------------------------ |
| `filter` (default) | Invalid entries removed | `block`       | passes | Warning annotation and step summary              |
| `warning`          | Unchanged               | `audit`       | passes | Warning annotation and step summary              |
| `error`            | Not published           | `block`       | fails  | Step summary; the failure itself annotates       |
| `ignore`           | Unchanged               | `block`       | passes | Warning annotation that harden-runner fails open |

<!-- markdownlint-enable MD013 -->

`filter` is the default because it costs nothing: no job can reach a
hostname without an A record, so removing one takes nothing away from
the job, and block mode stays enforced without any change to the
calling workflow. The one exception: when every entry fails, `filter`
fails the step rather than publishing an empty list, which would
block every connection the job makes.

### Check everywhere, report once

The check runs in **every** invocation. Each job starts its own
harden-runner agent, and each agent resolves the list for itself, so a
check confined to the first job would leave every other job free to
fail open. The check is cheap: around 300 ms for the 155 hostnames in
the `lfreleng-actions` list, measured on cold processes, against the
ten seconds or so that harden-runner's own pre step takes. The
`DNS validation: benchmark` job in `testing.yaml` measures it again on
a GitHub-hosted runner for every change.

Reporting differs. The step summary and the annotations follow
`allow_list_summary`, which a workflow already sets `true` on one
invocation (and `false` everywhere else) so that the allow-list block
appears once per run. The action reports a stale hostname once per
workflow run, not once per job. Every invocation still logs its
findings to the console, and in `error` mode every job fails, because
a failing job must say why.

### How the action checks a hostname

The check mirrors the agent rather than the runner's own resolver,
because the two can disagree:

- The action asks Google's DNS-over-HTTPS JSON API (`dns.google`) for
  an A record, falling back to Cloudflare's (`cloudflare-dns.com`) when
  the request fails in transport, as the agent does. An HTTP error or
  unreadable response is not a transport failure: the agent never
  falls back on one, so the action retries the same provider.
- A hostname is **valid** when the answer carries an A record. NXDOMAIN,
  and a NOERROR answer with no A record, are **invalid**: that includes
  hosts with AAAA records and no A record, and CNAMEs whose target has
  no A record. Names under `.internal`, which the agent refuses in
  block mode, are invalid too.
- The action skips wildcard (`*.`) entries; the agent never
  pre-resolves them.
- The action retries failures that say nothing about the record
  (SERVFAIL, REFUSED, HTTP errors, timeouts) with jittered exponential
  backoff: three attempts, three seconds each. An entry still without
  an answer is **indeterminate**. The action annotates it in every mode
  and removes it in `filter` mode alone. It never fails the step in
  `error` mode, which keeps a DNS blip from turning CI red.
- Lookups run 32 at a time, under a 15-second deadline for the whole
  list. When more than a quarter of them reach no verdict, the fault
  most probably lies with the providers, so `filter` leaves the
  indeterminate entries in place rather than stripping the allow-list
  wholesale.

DNS-over-HTTPS travels over TCP and TLS, so it needs no separate
UDP-to-TCP fallback: TCP retransmits lost packets and never truncates
a response.

### Switching to audit mode on invalid entries

`warning` mode publishes `HARDEN_RUNNER_EGRESS_POLICY=audit` when it
finds invalid entries (and `block` otherwise). Audit mode keeps
harden-runner's monitoring, which a failed-open agent loses too. The
variable takes effect where the harden-runner step reads it:

```yaml
  - uses: step-security/harden-runner@<sha>
    with:
      egress-policy: ${{ env.HARDEN_RUNNER_EGRESS_POLICY }}
      allowed-endpoints: ${{ env.CONNECTION_ALLOW_LIST }}
```

### What the check does not cover

The agent also resolves endpoints it adds itself, never present in the
allow-list: GitHub hosts such as `codeload.github.com` and
`actions-results-receiver-production.githubapp.com`, StepSecurity's
`agent.api.stepsecurity.io` and `prod.app-api.stepsecurity.io`, and
the GitHub Actions domains it fetches from the GitHub Meta API on each
run. The action leaves these alone. It cannot remove them, so
`filter` would have nothing to act on, and copying the agent's set
would drift with each harden-runner release. One of them failing to
resolve would still make the agent fail open; the check removes the
risk that the allow-list itself carries, which is the part a caller
controls.

### Checking a list without enforcing it

The outputs report the findings whenever the step succeeds, so a
scheduled job can check a list (for example, the shared allow-list at
its default branch and at its latest release) with `invalid_records:
filter`, the default, or `warning`, and notify on `invalid_count`, with
no harden-runner step involved. A failing step publishes no outputs:
that is `error` mode with invalid entries, and `filter` mode when every
entry is invalid. Both stop in the pre phase on purpose, before
harden-runner can start, so their findings appear in the step summary,
the annotation and the log instead.

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
small `main:` hook:

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
   - **Check** every allow-list hostname over DNS-over-HTTPS and
     apply the `invalid_records` policy.
   - **Publish** the result as `$<env_var_name>` (via
     `$GITHUB_ENV`), plus a step-summary line, and hand the step
     outputs to `main` through a private file under `$RUNNER_TEMP`.
2. **`main:` (src/main.mjs)** publishes the step outputs. The runner
   discards outputs written during the pre phase, because it gives
   pre steps no context name, so `steps.<id>.outputs` would
   otherwise stay empty; state saved in `pre` does reach `main`, and
   carries the handover file's path. The path, rather than the
   values, travels in state because state reaches `main` as an
   environment variable, which Linux caps at 128 KiB. `main`
   deletes the file once it has published the outputs.

The script has **no npm dependencies**: it uses Node's built-in
modules (`fs`, `crypto`, `https`, `url`) and `fetch`, and talks to the
runner via the documented `$GITHUB_ENV` / `$GITHUB_OUTPUT` /
`$GITHUB_STEP_SUMMARY` files and `::error::` workflow commands. No
build pipeline, no bundling, no `dist/` directory.

The action spans ten single-purpose ES modules, which the runner
loads directly (relative imports, no resolution step):

<!-- markdownlint-disable MD013 -->

| Module                 | Responsibility                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------ |
| `src/pre.mjs`          | Pre entrypoint: orchestrates the steps above and hands the outputs over to `main`.   |
| `src/main.mjs`         | Main entrypoint: publishes the outputs `pre` handed over.                            |
| `src/inputs.mjs`       | Reads and validates inputs, resolves which source to use.                            |
| `src/fetch.mjs`        | Size-capped HTTPS fetch (redirects, timeout) and local file read.                    |
| `src/sanitise.mjs`     | Token parsing and strict host/port validation.                                       |
| `src/config-flow.mjs`  | Drives the shared Python resolver for the `config` input, and merges a supplemental. |
| `src/supplemental.mjs` | Pure helpers for the supplemental list: spec parsing, the trust rule, the merge.     |
| `src/dns-validate.mjs` | DoH lookups, retries and verdicts, and the per-mode decision. Pure apart from fetch. |
| `src/dns-policy.mjs`   | Applies `invalid_records`: outputs, env vars, annotations and step summary.          |
| `src/actions-io.mjs`   | The runner protocol: workflow commands, outputs and their pre-to-main handover.      |

<!-- markdownlint-enable MD013 -->

## Notes

- This action needs **no** organisation secret or variable to work
  — that is the whole point. It behaves the same way for PRs raised
  from forks as it does for direct branches.
- If you customise `env_var_name`, make sure the downstream
  harden-runner step reads `${{ env.<that-name> }}` to match.

[pre-commit.ci results page]: https://results.pre-commit.ci/latest/github/lfreleng-actions/harden-runner-block-action/main
[pre-commit.ci status badge]: https://results.pre-commit.ci/badge/github/lfreleng-actions/harden-runner-block-action/main.svg
