# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# This repository owns the config resolver; no other repository carries
# a copy. It has two callers:
#   - src/config-flow.mjs, this action's own code path (--mode endpoints)
#   - the resolve-config sub-action (resolve-config/action.yaml), which
#     python-audit-action pins by commit SHA (--mode vulns)
#
# The CLI arguments and the keys write_github_output() emits form the
# sub-action's contract: changing either is a breaking change for
# python-audit-action.
#
# The only caller-specific behaviour is selected at call time via the
# --mode flag (endpoints | vulns); the module itself carries no
# per-action constants.
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
import json
import os
import subprocess
import sys

# Both callers run this file as `python3 -I -S`, and isolated mode
# leaves the script's own directory off sys.path. Put it back so the
# sibling resolve_config_* modules below can be imported.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from resolve_config_emit import write_github_output, write_step_summary  # noqa: E402
from resolve_config_fetch import (  # noqa: E402
    MAX_FILE_BYTES,
    _run_git,
    _transient_fetch_failure,
    fetch_file,
)
from resolve_config_grammar import (  # noqa: E402
    ResolveError,
    parse_config,
    resolve,
    split_comment,
)
from resolve_config_sanitise import sanitise  # noqa: E402

# The names callers and tests import from this module.
__all__ = [
    "MAX_FILE_BYTES",
    "ResolveError",
    "_run_git",
    "_transient_fetch_failure",
    "fetch_file",
    "main",
    "parse_config",
    "resolve",
    "sanitise",
    "split_comment",
    "write_github_output",
    "write_step_summary",
]


def _build_parser() -> argparse.ArgumentParser:
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
    parser.add_argument(
        "--step-summary", default=os.environ.get("GITHUB_STEP_SUMMARY", "")
    )
    parser.add_argument("--summary-title", default="")
    parser.add_argument("--summary-unit", default="Entries")
    parser.add_argument("--json-stdout", action="store_true")
    return parser


def _read_token(args: argparse.Namespace) -> str:
    token = args.token
    if args.token_env:
        token = os.environ.get(args.token_env, "")
        # Drop the secret from the environment immediately after reading
        # it, so the git subprocesses spawned below (which inherit
        # os.environ) do not carry the token in their environment. The
        # credential reaches git only via the repo-local config header.
        os.environ.pop(args.token_env, None)
    return token


def _matched_candidate(resolved: dict, fetched: dict) -> str:
    if fetched["fallback_used"]:
        return "sole-org-fallback"
    if fetched["matched_path"] == resolved["candidates"][0]:
        return "explicit" if resolved["path_explicit"] else "org-specific"
    return "family-default"


def _run(args: argparse.Namespace, token: str) -> int:
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
        fallback_dir=resolved["fallback_dir"],
        fallback_filename=resolved["fallback_filename"],
    )

    tokens: list[str] = []
    matched_candidate = ""
    if fetched["found"]:
        tokens = sanitise(fetched["content"], args.mode)
        matched_candidate = _matched_candidate(resolved, fetched)
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
    write_step_summary(args.step_summary, args.summary_title, args.summary_unit, result)
    if args.json_stdout:
        print(json.dumps(result))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    token = _read_token(args)

    try:
        return _run(args, token)
    except ResolveError as exc:
        print(f"config resolution error: {exc}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("config resolution error: git operation timed out", file=sys.stderr)
        return 1
    except FileNotFoundError:
        # 'git' is not installed / not on PATH.
        print(
            "config resolution error: the 'git' executable was not found",
            file=sys.stderr,
        )
        return 1
    except UnicodeDecodeError:
        # A fetched blob (or git output) was not valid UTF-8.
        print(
            "config resolution error: fetched content is not valid UTF-8",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        # Any other failure spawning git or reading/writing files.
        print(f"config resolution error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
