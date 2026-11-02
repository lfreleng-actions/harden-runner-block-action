# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Mode-selected sanitisation for resolve_config_source.py: every token
# in a fetched file must match the grammar of the --mode in use.

# pyright: basic

from __future__ import annotations

import re

from resolve_config_grammar import ResolveError


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
_ENDPOINT_RE = re.compile(rf"^(?:{_HOST_BARE}|{_HOST_WILD})(?::[0-9]{{1,5}})?$")

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
                        f"rejected endpoint token '{token}' (port out of range 1-65535)"
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
