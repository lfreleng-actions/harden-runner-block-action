# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║  SYNCHRONISED FILE — DO NOT EDIT IN ISOLATION                      ║
# ║                                                                    ║
# ║  Mirrored across:                                                  ║
# ║    - lfreleng-actions/python-audit-action       : tests/...        ║
# ║    - lfreleng-actions/harden-runner-block-action: tests/...        ║
# ║                                                                    ║
# ║  These tests pin the shared `config` grammar. Changes must land    ║
# ║  as paired PRs in both repositories together with the module.      ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Unit tests for resolve_config_source: parsing, resolution defaults,
# the search-candidate chain, and the mode-selected sanitisers. These
# tests do not touch the network; fetch_file() is exercised separately
# by an integration smoke test in CI.

# pyright: basic, reportMissingImports=false

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import resolve_config_source as rcs  # noqa: E402


# ---------------------------------------------------------------------
# Comment splitting
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected_spec,expected_comment",
    [
        ("lfit@v1.1.0", "lfit@v1.1.0", ""),
        ("lfit@v1.1.0 # hello", "lfit@v1.1.0", "hello"),
        ("lfit@v1.1.0  # two spaces", "lfit@v1.1.0", "two spaces"),
        ("lfit@v1.1.0\t# tab", "lfit@v1.1.0", "tab"),
        ("lfit//f.txt@v1 # many words here", "lfit//f.txt@v1", "many words here"),
    ],
)
def test_split_comment(value, expected_spec, expected_comment):
    spec, comment = rcs.split_comment(value)
    assert spec == expected_spec
    assert comment == expected_comment


# ---------------------------------------------------------------------
# Resolution + search candidates
# ---------------------------------------------------------------------


def _resolve(spec, org="onap", family="python-audit"):
    return rcs.resolve(spec, workflow_org=org, family=family)


def test_org_only_default_branch():
    r = _resolve("lfreleng-actions@main")
    assert r["host_org"] == "lfreleng-actions"
    assert r["repo"] == ".github"
    assert r["ref"] == "main"
    assert r["candidates"] == [
        ".github/python-audit/onap/allow_list.txt",
        ".github/python-audit/allow_list.txt",
    ]
    assert r["path_explicit"] is False


def test_no_ref_defaults_to_head():
    r = _resolve("lfit")
    assert r["ref"] == "HEAD"


def test_sha_ref_with_comment():
    r = _resolve("lfit@ab7a9404c0f3da075243ca237b5fac12c98deaa5 # v1.0.0")
    assert r["host_org"] == "lfit"
    assert r["ref"] == "ab7a9404c0f3da075243ca237b5fac12c98deaa5"
    assert r["comment"] == "v1.0.0"


def test_filename_only_keeps_default_dir_search():
    r = _resolve("lfit//custom_list.txt@v1.1.0")
    assert r["candidates"] == [
        ".github/python-audit/onap/custom_list.txt",
        ".github/python-audit/custom_list.txt",
    ]
    assert r["path_explicit"] is False


def test_bare_double_slash_uses_defaults():
    r = _resolve("lfit//@ab7a9404c0f3da075243ca237b5fac12c98deaa5  # note")
    assert r["candidates"] == [
        ".github/python-audit/onap/allow_list.txt",
        ".github/python-audit/allow_list.txt",
    ]
    assert r["ref"] == "ab7a9404c0f3da075243ca237b5fac12c98deaa5"


def test_explicit_directory_disables_search():
    r = _resolve("lfit//configs/onap/list.txt@main")
    assert r["candidates"] == ["configs/onap/list.txt"]
    assert r["path_explicit"] is True


def test_explicit_repo_override():
    r = _resolve("lfit/special-repo//list.txt@main")
    assert r["host_org"] == "lfit"
    assert r["repo"] == "special-repo"


def test_empty_host_org_defaults_to_workflow_org():
    r = _resolve("//team_list.txt@main", org="onap")
    assert r["host_org"] == "onap"
    assert r["candidates"][0] == ".github/python-audit/onap/team_list.txt"


def test_family_appears_in_default_path():
    r = _resolve("lfit@main", family="harden-runner")
    assert r["candidates"] == [
        ".github/harden-runner/onap/allow_list.txt",
        ".github/harden-runner/allow_list.txt",
    ]


# ---------------------------------------------------------------------
# Rejections
# ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "lfit@",
        "lfit@a@b",
        "lfit//a//b@main",
        "lfit/repo/extra@main",
        "bad org@main",
        "lfit//../escape.txt@main",
        "lfit///abs/path.txt@main",
        "lfit//a\\b.txt@main",
        "lfit@-badref",
        "lfit@ref..with..dots",
        "lfit@ref@{0}",
        "lfit//evil;rm.txt@main",
    ],
)
def test_invalid_specs_raise(spec):
    with pytest.raises(rcs.ResolveError):
        _resolve(spec)


def test_newline_in_config_rejected():
    with pytest.raises(rcs.ResolveError):
        _resolve("lfit@main\nevil")


# ---------------------------------------------------------------------
# Sanitisers
# ---------------------------------------------------------------------


def test_sanitise_vulns_accepts_valid_ids():
    raw = (
        "# comment\n"
        "GHSA-4xh5-x5gv-qwph\n"
        "PYSEC-2025-183  # disputed\n"
        "CVE-2024-12345\n"
        "OSV-2023-1 PVE-2021-99\n"
    )
    assert rcs.sanitise(raw, "vulns") == [
        "GHSA-4xh5-x5gv-qwph",
        "PYSEC-2025-183",
        "CVE-2024-12345",
        "OSV-2023-1",
        "PVE-2021-99",
    ]


@pytest.mark.parametrize(
    "token",
    ["evil;rm -rf /", "CVE-2024-1", "GHSA-XXXX-xxxx-xxxx", "not-an-id"],
)
def test_sanitise_vulns_rejects_bad_tokens(token):
    with pytest.raises(rcs.ResolveError):
        rcs.sanitise(token, "vulns")


def test_sanitise_endpoints_accepts_valid():
    raw = "github.com:443 *.githubusercontent.com:443 pypi.org # ok"
    assert rcs.sanitise(raw, "endpoints") == [
        "github.com:443",
        "*.githubusercontent.com:443",
        "pypi.org",
    ]


@pytest.mark.parametrize(
    "token",
    ["evil.com:0", "evil.com:99999", "*", "*:443", "ev|l.com", "a b;c"],
)
def test_sanitise_endpoints_rejects_bad(token):
    with pytest.raises(rcs.ResolveError):
        rcs.sanitise(token, "endpoints")


def test_sanitise_empty_after_comments_raises():
    with pytest.raises(rcs.ResolveError):
        rcs.sanitise("# only a comment\n\n", "vulns")


def test_unknown_mode_raises():
    with pytest.raises(rcs.ResolveError):
        rcs.sanitise("github.com", "bogus")
