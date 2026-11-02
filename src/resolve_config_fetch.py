# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Fetching for resolve_config_source.py: a shallow, ref-pinned git
# fetch over HTTPS with bounded retries, the candidate lookup, the
# sole-org fallback and the blob size and type checks.

# pyright: basic

from __future__ import annotations

import base64
import functools
import os
import re
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable

from resolve_config_grammar import SEGMENT_RE, ResolveError

# Hard ceiling on the file size we will read out of the fetched tree, to
# stop a misconfigured or hostile repo from exhausting runner memory.
MAX_FILE_BYTES = 1_048_576  # 1 MiB

# Seconds to wait before each retry of a transiently refused fetch; one
# more attempt is made than there are entries here.
FETCH_BACKOFF_SECONDS = (2, 5)

# Fetch failures that no retry can fix: the ref, the repository or the
# credential is wrong.
_FATAL_FETCH_RE = re.compile(
    r"couldn't find remote ref|not our ref|Repository not found",
    re.IGNORECASE,
)

# The HTTP status git reports, in either of the shapes it uses:
# "The requested URL returned error: 403" or "RPC failed; HTTP 503".
_HTTP_STATUS_RE = re.compile(r"(?:returned error:|\bHTTP)\s*(\d{3})\b")

# Connection-level failures that a later attempt may not hit.
_TRANSIENT_FETCH_RE = re.compile(
    r"Could not resolve host|Failed to connect|Connection reset"
    r"|Operation timed out|early EOF|RPC failed",
    re.IGNORECASE,
)


def _run_git(args: list[str], timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _transient_fetch_failure(stderr: str) -> str:
    """Name a fetch failure worth retrying, or return '' when it is not.

    A refused or dropped request (HTTP 403, 408, 429, 5xx, or a
    connection-level error) may succeed on a later attempt. An unknown
    ref, a missing repository, HTTP 401 or 404, or anything unrecognised
    will not, so those return '' and fail at once.
    """
    if _FATAL_FETCH_RE.search(stderr):
        return ""
    status = _HTTP_STATUS_RE.search(stderr)
    if status:
        code = int(status.group(1))
        if code in (403, 408, 429) or 500 <= code <= 599:
            return f"HTTP {code}"
        return ""
    connection = _TRANSIENT_FETCH_RE.search(stderr)
    return connection.group(0) if connection else ""


_Git = Callable[[list[str]], subprocess.CompletedProcess]


def _init_repo(git: _Git, tmp: str, url: str, token: str) -> None:
    """Create the scratch repository, add the remote and any auth header."""
    if git(["init", "-q"]).returncode != 0:
        raise ResolveError("git init failed")
    if git(["remote", "add", "origin", url]).returncode != 0:
        raise ResolveError("git remote add failed")
    if not token:
        return
    # Inject auth as a git config header. We write it straight
    # into the repo's local config file rather than via
    # `git config <key> <value>`, because the latter would place
    # the credential in a child process's argv (visible in
    # process listings). Writing the file keeps the token off
    # the command line entirely; it is also never placed in the
    # remote URL.
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    config_path = os.path.join(tmp, ".git", "config")
    header_line = f"\textraheader = AUTHORIZATION: basic {basic}\n"
    try:
        with open(config_path, "a", encoding="utf-8") as fh:
            fh.write('[http "https://github.com/"]\n')
            fh.write(header_line)
    except OSError as exc:
        raise ResolveError(f"git auth header configuration failed: {exc}")


_Refusal = tuple[str, ResolveError]


def _log(message: str) -> None:
    sys.stderr.write(f"{message}\n")


def _fetch_once(
    tmp: str, ref: str, source: str, remaining: float, attempt: int
) -> _Refusal | None:
    """Run fetch attempt `attempt` of `ref` from `source` ('<org>/<repo>').

    Returns None on success and raises on a failure no retry can fix.
    A transient failure returns its name and the error to raise should
    no retry follow.
    """
    fetch_args = [
        "-c",
        "protocol.version=2",
        "fetch",
        "-q",
        "--depth",
        "1",
        "origin",
        ref,
    ]
    fetched = _run_git(["-C", tmp, *fetch_args], remaining)
    if fetched.returncode == 0:
        return None
    stderr = fetched.stderr.strip()
    message = f"git fetch of '{ref}' from {source} failed: {stderr}"
    transient = _transient_fetch_failure(stderr)
    if not transient:
        raise ResolveError(message)
    # Every earlier attempt was transient too, or the loop would
    # have stopped there, so the whole run was a refusal.
    times = "once" if attempt == 1 else f"{attempt} times"
    refused = ResolveError(
        f"{message}; GitHub refused the fetch {times} ({transient}); "
        "the ref may still be valid, see the retry log"
    )
    return transient, refused


def _fetch_with_retry(
    fetch_once: Callable[[float, int], _Refusal | None],
    timeout: int,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
) -> None:
    """Run `fetch_once`, retrying transient refusals inside the deadline.

    `fetch_once` takes the seconds left and the attempt number.
    """
    attempts = len(FETCH_BACKOFF_SECONDS) + 1
    deadline = clock() + timeout
    remaining = float(timeout)
    attempt = 1
    while True:
        failure = fetch_once(remaining, attempt)
        if failure is None:
            return
        transient, refused = failure
        delay = FETCH_BACKOFF_SECONDS[attempt - 1] if attempt < attempts else 0
        if attempt >= attempts or delay >= deadline - clock():
            raise refused
        _log(
            f"fetch attempt {attempt} of {attempts} failed ({transient}); "
            f"retrying in {delay} s"
        )
        sleep(delay)
        # The wait may overrun its delay; never start a fetch the
        # deadline has no time left for.
        remaining = deadline - clock()
        if remaining <= 0:
            raise refused
        attempt += 1


def _read_blob(git: _Git, resolved_sha: str, cand: str) -> str | None:
    """Return the content of `cand` at `resolved_sha`, or None.

    Raises when the blob exceeds MAX_FILE_BYTES.
    """
    # Use 'cat-file -t' (not '-e'): '-e' also succeeds for a
    # tree, and 'git show <commit>:<dir>' would then print a
    # directory listing that we'd mistake for file content.
    # Only accept a blob, matching the local-path mode's
    # regular-file requirement.
    typ = git(["cat-file", "-t", f"{resolved_sha}:{cand}"])
    if typ.returncode != 0 or typ.stdout.strip() != "blob":
        return None
    size = git(["cat-file", "-s", f"{resolved_sha}:{cand}"])
    size_text = size.stdout.strip() if size.returncode == 0 else ""
    if size_text.isdecimal() and int(size_text) > MAX_FILE_BYTES:
        raise ResolveError(f"config file '{cand}' exceeds {MAX_FILE_BYTES}-byte limit")
    shown = git(["show", f"{resolved_sha}:{cand}"])
    if shown.returncode != 0:
        return None
    return shown.stdout


def _is_sole_org_entry(
    line: str, fallback_dir: str, fallback_filename: str, candidates: list[str]
) -> bool:
    """Tell whether a listed path is `<fallback_dir>/<org>/<filename>`."""
    if not line.startswith(f"{fallback_dir}/"):
        return False
    rel = line[len(fallback_dir) + 1 :]
    segs = rel.split("/")
    # Exactly one org directory between the family dir
    # and the filename, with a safe path segment (never
    # '.' or '..', matching resolve()'s validation), and
    # not a candidate we already tried above.
    return bool(
        len(segs) == 2
        and segs[1] == fallback_filename
        and segs[0] not in (".", "..")
        and SEGMENT_RE.match(segs[0])
        and line not in candidates
    )


def _sole_org_match(
    git: _Git,
    resolved_sha: str,
    candidates: list[str],
    fallback_dir: str,
    fallback_filename: str,
) -> str:
    """Return the one org-specific file in the tree, or '' if not exactly one."""
    listed = git(["ls-tree", "-r", "--name-only", resolved_sha, fallback_dir])
    if listed.returncode != 0:
        return ""
    matches = []
    for line in listed.stdout.splitlines():
        line = line.strip()
        if _is_sole_org_entry(line, fallback_dir, fallback_filename, candidates):
            matches.append(line)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        _log(
            "sole-org fallback skipped: files named "
            f"'{fallback_filename}' exist under more than one "
            f"org directory in '{fallback_dir}/' "
            f"({len(matches)} matches); the choice would be "
            "ambiguous"
        )
    return ""


def _result(
    resolved_sha: str, matched_path: str, content: str | None, fallback_used: bool
) -> dict:
    return {
        "found": content is not None,
        "resolved_sha": resolved_sha,
        "matched_path": matched_path,
        "content": content,
        "fallback_used": fallback_used,
    }


def fetch_file(
    *,
    host_org: str,
    repo: str,
    ref: str,
    candidates: list[str],
    token: str = "",
    timeout: int = 30,
    fallback_dir: str = "",
    fallback_filename: str = "",
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> dict:
    """Shallow-fetch `ref` and return the first existing candidate file.

    Works uniformly for branches, tags and commit SHAs: GitHub honours
    `git fetch --depth 1 <sha>` for reachable commits. Returns a dict with
    found (bool), resolved_sha, matched_path, content (str | None) and
    fallback_used (bool).

    A fetch that fails transiently (GitHub refusing or dropping the
    request) is retried after each delay in FETCH_BACKOFF_SECONDS, so
    long as the retry fits inside `timeout`. Every fetch gets only the
    time left before that deadline, and no retry starts once it has
    passed. `sleep` performs the wait and `clock` reads the time; both
    exist so tests can skip real waiting. Each retry logs one line to
    stderr.

    When every candidate misses and `fallback_dir`/`fallback_filename`
    name an auto-derived search root, the fetched tree is scanned for
    `<fallback_dir>/<org>/<fallback_filename>` entries. A single match
    resolves as a "sole-org fallback": forks carry the upstream org's
    file at the pinned ref but derive a different workflow org, so the
    org-specific candidate can never match there even though exactly
    one (byte-identical, ref-pinned) list exists in the tree. Zero or
    several matches keep the miss (several would make the choice
    ambiguous).
    """
    url = f"https://github.com/{host_org}/{repo}.git"
    with tempfile.TemporaryDirectory() as tmp:

        def git(args: list[str]) -> subprocess.CompletedProcess:
            return _run_git(["-C", tmp, *args], timeout)

        _init_repo(git, tmp, url, token)
        fetch_once = functools.partial(_fetch_once, tmp, ref, f"{host_org}/{repo}")
        _fetch_with_retry(fetch_once, timeout, sleep, clock)

        # Peel to the underlying commit. For an annotated tag,
        # FETCH_HEAD can name the tag object rather than the commit it
        # points at; '^{commit}' dereferences it so resolved_sha is
        # always a commit SHA, consistent across branch, lightweight
        # tag, annotated tag and commit-SHA refs.
        rev = git(["rev-parse", "FETCH_HEAD^{commit}"])
        if rev.returncode != 0:
            raise ResolveError("could not resolve FETCH_HEAD to a commit SHA")
        resolved_sha = rev.stdout.strip()

        for cand in candidates:
            content = _read_blob(git, resolved_sha, cand)
            if content is not None:
                return _result(resolved_sha, cand, content, False)

        if fallback_dir and fallback_filename:
            cand = _sole_org_match(
                git, resolved_sha, candidates, fallback_dir, fallback_filename
            )
            content = _read_blob(git, resolved_sha, cand) if cand else None
            if content is not None:
                return _result(resolved_sha, cand, content, True)

        return _result(resolved_sha, "", None, False)
