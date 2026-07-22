# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Regression tests: the ingress allow-list file format MUST NOT change
# the sanitised output the action hands to step-security/harden-runner.
#
# Context: lfreleng-actions/.github#99 reformats the egress
# allow_list.txt from a single, long, whitespace-separated line into a
# human-readable file with one host[:port] per line and '#' comments
# recording why entries exist. harden-runner enforces exactly the
# tokens this action publishes, so if the reformat perturbed even one
# token it could silently break block-mode egress in production CI.
#
# These tests pin the invariant directly against the sanitiser:
# whatever superficial layout the file uses -- one line or many, with
# or without comments, LF or CRLF, with or without a BOM -- the
# resulting token list (and the space-joined string harden-runner
# consumes) is byte-for-byte identical.

# pyright: basic, reportMissingImports=false

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import resolve_config_source as rcs  # noqa: E402


# ---------------------------------------------------------------------
# Canonical endpoint list
#
# A representative slice of a real lfreleng-actions allow-list, kept in
# LC_ALL=C sort order. It deliberately exercises every token shape the
# grammar allows: subdomain wildcards, a bare host with no port, and
# the full spread of ports actually in production use (22, 80, 443 and
# the Gerrit SSH port 29418).
# ---------------------------------------------------------------------

CANONICAL_ENDPOINTS = [
    "*.githubapp.com:443",
    "*.githubusercontent.com:443",
    "api.github.com:443",
    "astral.sh",
    "azure.archive.ubuntu.com:80",
    "deb.debian.org:80",
    "gerrit.o-ran-sc.org:29418",
    "github.com:22",
    "github.com:443",
    "pypi.org:443",
]


# ---------------------------------------------------------------------
# Renderers: the same endpoint list expressed in different on-disk
# layouts. Each returns the raw file bytes-as-str a user might commit.
# ---------------------------------------------------------------------


def _single_line(endpoints):
    """Legacy format: one long, space-separated line."""
    return " ".join(endpoints) + "\n"


def _multi_line_plain(endpoints):
    """New format, no comments: one host[:port] per line."""
    return "\n".join(endpoints) + "\n"


def _multi_line_commented(endpoints):
    """New format with a header block, full-line and inline comments.

    Mirrors the shape of the reformatted production file: an SPDX/why
    header, a per-entry rationale comment above every third entry, and
    a trailing inline comment on every fourth entry.
    """
    lines = [
        # REUSE-IgnoreStart
        "# SPDX-License-Identifier: Apache-2.0",
        "# SPDX-FileCopyrightText: 2026 The Linux Foundation",
        # REUSE-IgnoreEnd
        "#",
        "# egress allow-list (one host[:port] per line)",
        "",
    ]
    for i, endpoint in enumerate(endpoints):
        if i % 3 == 0:
            lines.append(f"# rationale for {endpoint}")
        if i % 4 == 0:
            lines.append(f"{endpoint}  # inline note")
        else:
            lines.append(endpoint)
    return "\n".join(lines) + "\n"


def _multi_line_messy(endpoints):
    """New format with irregular but legal whitespace.

    Blank lines, leading indentation, tab-separated inline comments and
    a trailing blank line -- all of which the sanitiser must normalise
    away without affecting the token set.
    """
    lines = ["", "\t# leading comment", ""]
    for endpoint in endpoints:
        lines.append(f"  {endpoint}\t# note")
        lines.append("")
    return "\n".join(lines) + "\n"


ALL_RENDERERS = [
    _single_line,
    _multi_line_plain,
    _multi_line_commented,
    _multi_line_messy,
]


# ---------------------------------------------------------------------
# Core invariant: every layout sanitises to the canonical token list
# ---------------------------------------------------------------------


@pytest.mark.parametrize("render", ALL_RENDERERS, ids=lambda f: f.__name__)
def test_layout_sanitises_to_canonical_tokens(render):
    assert rcs.sanitise(render(CANONICAL_ENDPOINTS), "endpoints") == (
        CANONICAL_ENDPOINTS
    )


@pytest.mark.parametrize("render", ALL_RENDERERS, ids=lambda f: f.__name__)
def test_layout_matches_single_line_baseline(render):
    baseline = rcs.sanitise(_single_line(CANONICAL_ENDPOINTS), "endpoints")
    assert rcs.sanitise(render(CANONICAL_ENDPOINTS), "endpoints") == baseline


def test_joined_output_string_is_identical_across_layouts():
    # harden-runner consumes the space-joined string, so pin that exact
    # byte sequence, not merely the token list, across every layout.
    baseline = " ".join(rcs.sanitise(_single_line(CANONICAL_ENDPOINTS), "endpoints"))
    for render in ALL_RENDERERS:
        joined = " ".join(rcs.sanitise(render(CANONICAL_ENDPOINTS), "endpoints"))
        assert joined == baseline


# ---------------------------------------------------------------------
# Encoding / line-ending robustness
# ---------------------------------------------------------------------


def test_crlf_line_endings_match_lf():
    lf = _multi_line_commented(CANONICAL_ENDPOINTS)
    crlf = lf.replace("\n", "\r\n")
    assert rcs.sanitise(crlf, "endpoints") == rcs.sanitise(lf, "endpoints")


def test_leading_bom_does_not_change_output():
    plain = _single_line(CANONICAL_ENDPOINTS)
    with_bom = "\ufeff" + _multi_line_commented(CANONICAL_ENDPOINTS)
    assert rcs.sanitise(with_bom, "endpoints") == rcs.sanitise(plain, "endpoints")


# ---------------------------------------------------------------------
# Comments carry no tokens through to harden-runner
# ---------------------------------------------------------------------


def test_comments_are_never_emitted_as_endpoints():
    tokens = rcs.sanitise(_multi_line_commented(CANONICAL_ENDPOINTS), "endpoints")
    # No comment word (e.g. 'rationale', 'inline', 'note') may survive,
    # and no token may retain a '#'.
    assert not any("#" in token for token in tokens)
    for leaked in ("rationale", "inline", "note", "SPDX-License-Identifier"):
        assert leaked not in tokens


def test_comment_only_file_between_entries_is_ignored():
    raw = (
        "# only comments and blank lines around a single entry\n"
        "\n"
        "# why we need it\n"
        "github.com:443  # trailing\n"
        "\n"
        "# trailing comment block\n"
    )
    assert rcs.sanitise(raw, "endpoints") == ["github.com:443"]


# ---------------------------------------------------------------------
# End-to-end: the exact single-line -> multi-line reformat of the real
# production list produces zero output variance.
# ---------------------------------------------------------------------

# The full 81-entry lfreleng-actions egress list as the single line it
# was before lfreleng-actions/.github#99, verbatim.
PRODUCTION_SINGLE_LINE = (
    "*.githubapp.com:443 *.githubusercontent.com:443 *.sigstore.dev:443 "
    "api.azul.com:443 api.deps.dev:443 api.github.com:443 api.osv.dev:443 "
    "api.scorecard.dev:443 app-updates.agilebits.com:443 astral.sh:443 "
    "auth.docker.io:443 azure.archive.ubuntu.com:80 "
    "build.automotivelinux.org:443 cache.agilebits.com:443 cdn.azul.com:443 "
    "deb.debian.org:80 dl-cdn.alpinelinux.org:443 dl.google.com:443 "
    "endoflife.date:443 esm.ubuntu.com:443 eu.i.posthog.com:443 "
    "files.pythonhosted.org:443 ftp.mozilla.org:443 "
    "gerrit.automotivelinux.org:443 gerrit.fd.io:443 gerrit.lfbroadband.org:443 "
    "gerrit.linuxfoundation.org:443 gerrit.o-ran-sc.org:29418 "
    "gerrit.o-ran-sc.org:443 gerrit.onap.org:443 get.anchore.io:443 "
    "get.helm.sh:443 ghcr.io:443 git.opendaylight.org:443 github.com:22 "
    "github.com:443 grype.anchore.io:443 jenkins.fd.io:443 "
    "jenkins.lfbroadband.org:443 jenkins.o-ran-sc.org:443 jenkins.onap.org:443 "
    "jenkins.opendaylight.org:443 jira.linuxfoundation.org:443 "
    "jira.o-ran-sc.org:443 jira.onap.org:443 jira.opendaylight.org:443 "
    "lf-o-ran-sc.atlassian.net:443 lf-onap.atlassian.net:443 "
    "lf-opendaylight.atlassian.net:443 linuxfoundation.1password.com:443 "
    "linuxfoundation.org:443 motd.ubuntu.com:443 nexus.onap.org:443 "
    "nexus3.o-ran-sc.org:443 o-ran-sc.1password.com:443 "
    "oss-fuzz-build-logs.storage.googleapis.com:443 packages.microsoft.com:443 "
    "prod.app-api.stepsecurity.io:443 production.cloudflare.docker.com:443 "
    "production.cloudfront.docker.com:443 proxy.golang.org:443 pypi.org:443 "
    "registry-1.docker.io:443 registry.npmjs.org:443 releases.astral.sh:443 "
    "repo.maven.apache.org:443 repo1.maven.org:443 slack.com:443 "
    "static.rust-lang.org:443 storage.googleapis.com:443 sum.golang.org:443 "
    "support.linuxfoundation.org:443 test.pypi.org:443 "
    "tmaproduction.blob.core.windows.net:443 tuf-repo.github.com:443 "
    "upload.pypi.org:443 uploads.github.com:443 vuln.go.dev:443 "
    "www.bestpractices.dev:443 www.google.com:443 www.linuxfoundation.org:443\n"
)


def test_production_reformat_is_lossless():
    baseline = rcs.sanitise(PRODUCTION_SINGLE_LINE, "endpoints")
    # Reconstruct the reformatted (multi-line + commented) file from the
    # very same tokens and prove the sanitiser collapses it back to an
    # identical list -- the guarantee lfreleng-actions/.github#99 relies
    # on to avoid touching production egress behaviour.
    reformatted = _multi_line_commented(baseline)
    assert rcs.sanitise(reformatted, "endpoints") == baseline
    assert len(baseline) == 81
