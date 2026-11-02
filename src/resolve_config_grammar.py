# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# The `config` grammar for resolve_config_source.py: the input
# validation patterns, ResolveError, and the parser that turns a
# `config` value into fetch coordinates and search candidates.

# pyright: basic

from __future__ import annotations

import re

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


def split_comment(value: str) -> tuple[str, str]:
    """Split a trailing ' #...' comment (one or more spaces/tabs before '#').

    Returns (spec, comment). The comment (without the leading whitespace
    and '#') is informational only and never affects resolution.

    Only spaces and tabs are treated as the separator before '#': a
    newline must NOT be consumed here, otherwise a value such as
    'lfit@main\n# hidden' would be split into a bare spec plus a
    'comment' and slip past the newline rejection in parse_config().
    """
    # Match the first run of spaces/tabs followed by '#', to end of line.
    m = re.search(r"[ \t]+#[^\r\n]*$", value)
    if m:
        comment = value[m.start() :].lstrip(" \t")[1:].strip()
        return value[: m.start()], comment
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

    # host-org and repo (the part before '//')
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

    # ref
    ref = parts["ref"] or "HEAD"
    if ref != "HEAD":
        if (
            ref.startswith("-")
            or ref.startswith("/")
            or ".." in ref
            or "@{" in ref
            or len(ref) > 255
            or not REF_RE.match(ref)
        ):
            raise ResolveError(f"invalid git ref in config: '{ref}'")

    # subpath -> filename + directory + search candidates
    default_dir_specific = f".github/{family}/{workflow_org}"
    default_dir_family = f".github/{family}"

    subpath = parts["subpath"]
    path_explicit = False
    fallback_dir = ""
    fallback_filename = ""

    if not parts["has_subpath"] or subpath == "":
        # No subpath, or a bare '//': default dir search chain + default file.
        filename = default_filename
        candidates = [
            f"{default_dir_specific}/{filename}",
            f"{default_dir_family}/{filename}",
        ]
        fallback_dir = default_dir_family
        fallback_filename = filename
    elif "/" not in subpath:
        # Filename only: override the filename, keep the default dir search.
        filename = subpath
        candidates = [
            f"{default_dir_specific}/{filename}",
            f"{default_dir_family}/{filename}",
        ]
        fallback_dir = default_dir_family
        fallback_filename = filename
    else:
        # Explicit directory present: use exactly this path, no search.
        path_explicit = True
        candidates = [subpath]

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
        "fallback_dir": fallback_dir,
        "fallback_filename": fallback_filename,
        "comment": comment,
    }
