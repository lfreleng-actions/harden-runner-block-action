# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# ╔══════════════════════════════════════════════════════════════════╗
# ║  SYNCHRONISED FILE — DO NOT EDIT IN ISOLATION                      ║
# ║                                                                    ║
# ║  This file is mirrored, byte-for-byte, across two repositories:    ║
# ║    - lfreleng-actions/python-audit-action       : src/...          ║
# ║    - lfreleng-actions/harden-runner-block-action: src/...          ║
# ║                                                                    ║
# ║  The `config` input grammar and its resolution/fetch/sanitise      ║
# ║  behaviour MUST stay identical in both actions. Any change here    ║
# ║  has to be raised as PAIRED pull requests in BOTH repositories.    ║
# ║  A CI check in each repo diffs this file against the other repo's  ║
# ║  copy and fails the build if they diverge.                         ║
# ║                                                                    ║
# ║  The only action-specific behaviour is selected at call time via   ║
# ║  the --mode flag (endpoints | vulns); the module itself carries    ║
# ║  no per-action constants.                                          ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# resolve_config_source.py
#
# Resolves the `config` input (a GitHub-Actions `uses:`-style coordinate)
# into a concrete (host-org, repo, ref, in-repo path) tuple, fetches the
# referenced file from GitHub using a shallow, ref-pinned git fetch, and
# sanitises the content against a strict, mode-selected token grammar.
#
# The module performs NO publishing of its own: it prints results to the
# destinations its caller selects (JSON to stdout, key=value lines to a
# GITHUB_OUTPUT file, a markdown block to a GITHUB_STEP_SUMMARY file).
# Diagnostics and errors go to stderr. Workflow commands (::error::,
# ::add-mask::) are intentionally NOT emitted here so that stdout stays
# clean JSON for the Node.js consumer; the calling wrapper is responsible
# for masking the token and surfacing errors as workflow annotations.
#
# Exit codes:
#   0  success (file found and sanitised) OR a "soft" not-found at an
#      auto-derived path (the JSON carries found=false; the caller
#      decides whether that is fatal for its action)
#   1  hard error (bad input, validation failure, network/git failure)

# pyright: basic

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile

# Hard ceiling on the file size we will read out of the fetched tree, to
# stop a misconfigured or hostile repo from exhausting runner memory.
MAX_FILE_BYTES = 1_048_576  # 1 MiB

# GitHub org/user names: 1-39 chars, alphanumerics and single hyphens,
# no leading/trailing hyphen, no consecutive hyphens.
ORG_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")

# Repository names: alphanumerics plus '.', '_', '-'. The canonical host
# repo is the special '.github' repo, so a leading dot must be allowed.
REPO_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# A single in-repo path segment. No empty segments, no '..', no slashes
# (the path is split on '/' before validation), no shell metacharacters.
SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# Git ref: branch name, tag name, or commit SHA. Conservative subset of
# the characters git permits, sufficient for our use and safe to hand to
# the git CLI as a positional argument.
REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


class ResolveError(Exception):
    """A hard error that must fail the action."""


# ---------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------

def split_comment(value: str) -> tuple[str, str]:
    """Split a trailing ' #...' comment (one or more spaces before '#').

    Returns (spec, comment). The comment (without the leading whitespace
    and '#') is informational only and never affects resolution.
    """
    # Match the first run of whitespace followed by '#', to end of string.
    m = re.search(r"\s+#(.*)$", value)
    if m:
        return value[: m.start()], m.group(1).strip()
    return value, ""


def parse_config(spec: str) -> dict:
    """Parse a `config` spec into its raw components.

    Grammar:
        <spec>     ::= <source> [ "@" <ref> ]
        <source>   ::= <repospec> [ "//" <subpath> ]
        <repospec> ::= [ <host-org> [ "/" <repo> ] ]
        <subpath>  ::= [ <dir> "/" ]... [ <filename> ]
    """
    if "\n" in spec or "\r" in spec:
        raise ResolveError("config must not contain newline characters")

    # Separate an optional '@<ref>'. '@' may appear at most once.
    ref = ""
    if "@" in spec:
        source, _, ref = spec.partition("@")
        if "@" in ref:
            raise ResolveError("config contains more than one '@' separator")
        if ref == "":
            raise ResolveError("config has an empty ref after '@'")
    else:
        source = spec

    # Separate repospec from subpath on '//'. '//' may appear at most once.
    subpath = ""
    has_subpath = False
    if "//" in source:
        repospec, _, subpath = source.partition("//")
        has_subpath = True
        if "//" in subpath:
            raise ResolveError("config contains more than one '//' separator")
    else:
        repospec = source

    return {
        "repospec": repospec,
        "subpath": subpath,
        "has_subpath": has_subpath,
        "ref": ref,
    }


def resolve(
    spec: str,
    *,
    workflow_org: str,
    family: str,
    default_repo: str = ".github",
    default_filename: str = "allow_list.txt",
) -> dict:
    """Resolve a parsed config spec into concrete fetch coordinates.

    Returns a dict with: host_org, repo, ref, candidates (ordered list of
    in-repo paths to try), path_explicit (bool), comment.
    """
    spec, comment = split_comment(spec.strip())
    if spec == "":
        raise ResolveError("config is empty")

    parts = parse_config(spec)

    # --- host-org and repo (the part before '//') ---
    repospec = parts["repospec"].strip("/")
    if repospec == "":
        host_org = workflow_org
        repo = default_repo
    else:
        segs = repospec.split("/")
        if len(segs) == 1:
            host_org, repo = segs[0], default_repo
        elif len(segs) == 2:
            host_org, repo = segs[0], segs[1]
        else:
            raise ResolveError(
                "config repository part accepts at most '<org>/<repo>'; "
                "put any in-repo path after '//'"
            )

    if host_org == "":
        host_org = workflow_org
    if not ORG_RE.match(host_org):
        raise ResolveError(f"invalid host org in config: '{host_org}'")
    if repo == "":
        repo = default_repo
    if repo in ("..", ".") or not REPO_RE.match(repo):
        raise ResolveError(f"invalid repository in config: '{repo}'")

    # --- ref ---
    ref = parts["ref"] or "HEAD"
    if ref != "HEAD":
        if ref.startswith("-") or ref.startswith("/") or ".." in ref \
                or "@{" in ref or len(ref) > 255 or not REF_RE.match(ref):
            raise ResolveError(f"invalid git ref in config: '{ref}'")

    # --- subpath -> filename + directory + search candidates ---
    default_dir_specific = f".github/{family}/{workflow_org}"
    default_dir_family = f".github/{family}"

    subpath = parts["subpath"]
    path_explicit = False

    if not parts["has_subpath"] or subpath == "":
        # No subpath, or a bare '//': default dir search chain + default file.
        filename = default_filename
        candidates = [
            f"{default_dir_specific}/{filename}",
            f"{default_dir_family}/{filename}",
        ]
    elif "/" not in subpath:
        # Filename only: override the filename, keep the default dir search.
        filename = subpath
        candidates = [
            f"{default_dir_specific}/{filename}",
            f"{default_dir_family}/{filename}",
        ]
    else:
        # Explicit directory present: use exactly this path, no search.
        path_explicit = True
        candidates = [subpath]

    # Validate every candidate path segment.
    for cand in candidates:
        if cand.startswith("/") or "\\" in cand or ".." in cand.split("/"):
            raise ResolveError(f"invalid in-repo path in config: '{cand}'")
        segs = cand.split("/")
        if not segs or any(seg == "" for seg in segs):
            raise ResolveError(f"invalid in-repo path in config: '{cand}'")
        for seg in segs:
            if not SEGMENT_RE.match(seg):
                raise ResolveError(
                    f"invalid path segment '{seg}' in config path '{cand}'"
                )

    if workflow_org != "" and not ORG_RE.match(workflow_org):
        raise ResolveError(f"invalid workflow org: '{workflow_org}'")

    return {
        "host_org": host_org,
        "repo": repo,
        "ref": ref,
        "candidates": candidates,
        "path_explicit": path_explicit,
        "comment": comment,
    }


# ---------------------------------------------------------------------
# Fetch (shallow, ref-pinned, git over HTTPS)
# ---------------------------------------------------------------------

def _run_git(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def fetch_file(
    *,
    host_org: str,
    repo: str,
    ref: str,
    candidates: list[str],
    token: str = "",
    timeout: int = 30,
) -> dict:
    """Shallow-fetch `ref` and return the first existing candidate file.

    Works uniformly for branches, tags and commit SHAs: GitHub honours
    `git fetch --depth 1 <sha>` for reachable commits. Returns a dict with
    found (bool), resolved_sha, matched_path, content (str | None).
    """
    url = f"https://github.com/{host_org}/{repo}.git"
    with tempfile.TemporaryDirectory() as tmp:
        def git(args: list[str]) -> subprocess.CompletedProcess:
            return _run_git(["-C", tmp, *args], timeout)

        if git(["init", "-q"]).returncode != 0:
            raise ResolveError("git init failed")
        if git(["remote", "add", "origin", url]).returncode != 0:
            raise ResolveError("git remote add failed")

        if token:
            # Inject auth as a config header (never on the command line or
            # in the URL, so it cannot leak via process listings or logs).
            basic = base64.b64encode(
                f"x-access-token:{token}".encode()
            ).decode()
            cfg = git([
                "config", "--local",
                "http.https://github.com/.extraheader",
                f"AUTHORIZATION: basic {basic}",
            ])
            if cfg.returncode != 0:
                raise ResolveError("git auth header configuration failed")

        fetched = git([
            "-c", "protocol.version=2",
            "fetch", "-q", "--depth", "1", "origin", ref,
        ])
        if fetched.returncode != 0:
            raise ResolveError(
                f"git fetch of '{ref}' from {host_org}/{repo} failed: "
                f"{fetched.stderr.strip()}"
            )

        rev = git(["rev-parse", "FETCH_HEAD"])
        if rev.returncode != 0:
            raise ResolveError("could not resolve FETCH_HEAD to a commit SHA")
        resolved_sha = rev.stdout.strip()

        for cand in candidates:
            exists = git(["cat-file", "-e", f"FETCH_HEAD:{cand}"])
            if exists.returncode != 0:
                continue
            size = git(["cat-file", "-s", f"FETCH_HEAD:{cand}"])
            try:
                if size.returncode == 0 and int(size.stdout.strip()) > MAX_FILE_BYTES:
                    raise ResolveError(
                        f"config file '{cand}' exceeds {MAX_FILE_BYTES}-byte limit"
                    )
            except ValueError:
                pass
            shown = git(["show", f"FETCH_HEAD:{cand}"])
            if shown.returncode != 0:
                continue
            return {
                "found": True,
                "resolved_sha": resolved_sha,
                "matched_path": cand,
                "content": shown.stdout,
            }

        return {
            "found": False,
            "resolved_sha": resolved_sha,
            "matched_path": "",
            "content": None,
        }


# ---------------------------------------------------------------------
# Sanitisation (mode-selected)
# ---------------------------------------------------------------------

def _strip_comments_and_split(raw: str) -> list[str]:
    text = raw.lstrip("\ufeff")
    # Remove '#' comments (full-line and trailing-after-whitespace).
    text = re.sub(r"(^|[ \t])#[^\r\n]*", r"\1", text, flags=re.MULTILINE)
    text = re.sub(r"\s+", " ", text).strip()
    if text == "":
        return []
    return text.split(" ")


_HOST_BARE = r"[A-Za-z0-9][A-Za-z0-9.-]*"
_HOST_WILD = r"\*\.[A-Za-z0-9][A-Za-z0-9.-]*"
_ENDPOINT_RE = re.compile(
    rf"^(?:{_HOST_BARE}|{_HOST_WILD})(?::[0-9]{{1,5}})?$"
)

_VULN_RE = re.compile(
    r"^(?:"
    r"CVE-[0-9]{4}-[0-9]{4,}"
    r"|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"
    r"|PYSEC-[0-9]{4}-[0-9]+"
    r"|OSV-[0-9]{4}-[0-9]+"
    r"|PVE-[0-9]+(?:-[0-9]+)?"
    r")$"
)


def sanitise(raw: str, mode: str) -> list[str]:
    """Validate every token in the file against the mode's grammar.

    A single non-conforming token is a hard error rather than being
    silently dropped, so untrusted remote content cannot smuggle
    unexpected values into a downstream tool.
    """
    tokens = _strip_comments_and_split(raw)
    if not tokens:
        raise ResolveError("config file is empty after parsing")

    for token in tokens:
        if mode == "endpoints":
            if not _ENDPOINT_RE.match(token):
                raise ResolveError(
                    f"rejected endpoint token '{token}' "
                    "(must be host[:port] or *.host[:port])"
                )
            if ":" in token:
                port = token.rsplit(":", 1)[1]
                if not port.isdigit() or not (1 <= int(port) <= 65535):
                    raise ResolveError(
                        f"rejected endpoint token '{token}' "
                        "(port out of range 1-65535)"
                    )
        elif mode == "vulns":
            if not _VULN_RE.match(token):
                raise ResolveError(
                    f"rejected vulnerability token '{token}' "
                    "(not a recognised CVE/GHSA/PYSEC/OSV/PVE ID)"
                )
        else:
            raise ResolveError(f"unknown mode: '{mode}'")

    return tokens


# ---------------------------------------------------------------------
# Emit helpers
# ---------------------------------------------------------------------

def _append(path: str, text: str) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(text)


def write_github_output(path: str, content_key: str, result: dict) -> None:
    if not path:
        return
    sep = " "
    pairs = {
        content_key: sep.join(result["tokens"]),
        "count": str(result["count"]),
        "found": "true" if result["found"] else "false",
        "path_explicit": "true" if result["path_explicit"] else "false",
        "host_org": result["host_org"],
        "repo": result["repo"],
        "ref": result["ref"],
        "resolved_sha": result["resolved_sha"],
        "resolved_path": result["matched_path"],
        "matched_candidate": result["matched_candidate"],
        "source": "config",
    }
    lines = []
    for key, value in pairs.items():
        if "\n" in value or "\r" in value:
            raise ResolveError(f"refusing to write multi-line output '{key}'")
        lines.append(f"{key}={value}\n")
    _append(path, "".join(lines))


def write_step_summary(path: str, title: str, unit: str, result: dict) -> None:
    if not path or not title:
        return
    expanded = (
        f"{result['host_org']}/{result['repo']}/"
        f"{result['matched_path']}@{result['ref']}"
        if result["found"] else "(none found)"
    )
    lines = [
        f"### {title}",
        "",
        "- Source: `config`",
        f"- Resolved: `{expanded}`",
        f"- Commit SHA: `{result['resolved_sha'] or '(n/a)'}`",
        f"- Matched candidate: {result['matched_candidate'] or '(none)'}",
        f"- {unit} loaded: **{result['count']}**",
        "",
    ]
    _append(path, "\n".join(lines))


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Resolve and fetch a `config` allow-list source."
    )
    parser.add_argument("--config", required=True)
    parser.add_argument("--workflow-org", required=True)
    parser.add_argument("--family", required=True)
    parser.add_argument("--mode", required=True, choices=["endpoints", "vulns"])
    parser.add_argument("--token", default="")
    parser.add_argument(
        "--token-env",
        default="",
        help=(
            "Name of an environment variable holding the token. Preferred "
            "over --token so the secret never appears in the process "
            "argument list. Takes precedence over --token when set."
        ),
    )
    parser.add_argument("--default-repo", default=".github")
    parser.add_argument("--default-filename", default="allow_list.txt")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--content-key", default="ids")
    parser.add_argument("--github-output", default=os.environ.get("GITHUB_OUTPUT", ""))
    parser.add_argument("--step-summary", default=os.environ.get("GITHUB_STEP_SUMMARY", ""))
    parser.add_argument("--summary-title", default="")
    parser.add_argument("--summary-unit", default="Entries")
    parser.add_argument("--json-stdout", action="store_true")
    args = parser.parse_args(argv)

    token = args.token
    if args.token_env:
        token = os.environ.get(args.token_env, "")

    try:
        resolved = resolve(
            args.config,
            workflow_org=args.workflow_org,
            family=args.family,
            default_repo=args.default_repo,
            default_filename=args.default_filename,
        )
        fetched = fetch_file(
            host_org=resolved["host_org"],
            repo=resolved["repo"],
            ref=resolved["ref"],
            candidates=resolved["candidates"],
            token=token,
            timeout=args.timeout,
        )

        tokens: list[str] = []
        matched_candidate = ""
        if fetched["found"]:
            tokens = sanitise(fetched["content"], args.mode)
            if fetched["matched_path"] == resolved["candidates"][0]:
                matched_candidate = (
                    "explicit" if resolved["path_explicit"] else "org-specific"
                )
            else:
                matched_candidate = "family-default"
        elif resolved["path_explicit"]:
            # An explicitly-named file that is missing is always a hard
            # error: the caller asked for that exact path. Only a miss at
            # an auto-derived (searched) path is "soft" and left for the
            # calling action to interpret via the found=false result.
            raise ResolveError(
                "config file not found at explicit path "
                f"'{resolved['candidates'][0]}' in "
                f"{resolved['host_org']}/{resolved['repo']}@{resolved['ref']}"
            )

        result = {
            "found": fetched["found"],
            "path_explicit": resolved["path_explicit"],
            "host_org": resolved["host_org"],
            "repo": resolved["repo"],
            "ref": resolved["ref"],
            "resolved_sha": fetched["resolved_sha"],
            "matched_path": fetched["matched_path"],
            "matched_candidate": matched_candidate,
            "comment": resolved["comment"],
            "tokens": tokens,
            "count": len(tokens),
        }

        write_github_output(args.github_output, args.content_key, result)
        write_step_summary(
            args.step_summary, args.summary_title, args.summary_unit, result
        )
        if args.json_stdout:
            print(json.dumps(result))
        return 0
    except ResolveError as exc:
        print(f"config resolution error: {exc}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("config resolution error: git operation timed out", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
