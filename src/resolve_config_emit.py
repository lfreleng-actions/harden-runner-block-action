# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Output writers for resolve_config_source.py: the GITHUB_OUTPUT lines
# that form the resolve-config sub-action's contract, and the step
# summary block.

# pyright: basic

from __future__ import annotations

from resolve_config_grammar import ResolveError


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
        "resolved_host_org": result["host_org"],
        "resolved_repo": result["repo"],
        "resolved_ref": result["ref"],
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
        if result["found"]
        else "(none found)"
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
