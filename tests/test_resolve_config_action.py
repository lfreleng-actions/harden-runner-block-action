# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
#
# Contract tests for the resolve-config composite sub-action.
#
# python-audit-action consumes resolve-config/action.yaml as a public
# interface, so its declared outputs must track exactly what the
# resolver writes, and its run: script must keep every input out of
# expression interpolation. The action file is read as text: the suite
# carries no YAML library.

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import resolve_config_source as rcs  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION_FILE = REPO_ROOT / "resolve-config" / "action.yaml"

# The content key the sub-action passes to --content-key.
CONTENT_KEY = "entries"


def _action_text() -> str:
    return ACTION_FILE.read_text(encoding="utf-8")


def declared_outputs(text: str) -> set[str]:
    """Return the keys declared under the top-level 'outputs:' mapping."""
    keys: set[str] = set()
    inside = False
    for line in text.splitlines():
        if re.match(r"^outputs:\s*(#.*)?$", line):
            inside = True
            continue
        if not inside:
            continue
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$", line)
        if m:
            keys.add(m.group(1))
    return keys


def run_script(text: str) -> str:
    """Return the dedented 'run:' block script of the action's only step."""
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        m = re.match(r"^(\s*)run:\s*\|\s*$", line)
        if not m:
            continue
        key_indent = len(m.group(1))
        body: list[str] = []
        for nxt in lines[idx + 1 :]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip(" ")) <= key_indent:
                break
            body.append(nxt)
        while body and not body[-1].strip():
            body.pop()
        indents = [len(b) - len(b.lstrip(" ")) for b in body if b.strip()]
        cut = min(indents) if indents else 0
        return "\n".join(b[cut:] for b in body) + "\n"
    raise AssertionError(f"no 'run: |' block in {ACTION_FILE}")


def written_keys(tmp_path: Path) -> set[str]:
    """Collect the keys write_github_output emits for CONTENT_KEY."""
    out = tmp_path / "github_output"
    result = {
        "tokens": ["a", "b"],
        "count": 2,
        "found": True,
        "path_explicit": False,
        "host_org": "lfreleng-actions",
        "repo": ".github",
        "ref": "main",
        "resolved_sha": "0" * 40,
        "matched_path": ".github/x/allow_list.txt",
        "matched_candidate": "org-specific",
    }
    rcs.write_github_output(str(out), CONTENT_KEY, result)
    return {
        line.split("=", 1)[0]
        for line in out.read_text(encoding="utf-8").splitlines()
        if line
    }


@pytest.mark.xfail(strict=True, reason="resolve-config sub-action not yet added")
def test_outputs_match_resolver_keys(tmp_path: Path) -> None:
    keys = written_keys(tmp_path)
    assert CONTENT_KEY in keys
    assert declared_outputs(_action_text()) == keys


@pytest.mark.xfail(strict=True, reason="resolve-config sub-action not yet added")
def test_run_script_has_no_expressions() -> None:
    script = run_script(_action_text())
    assert "${{" not in script
    assert "--token-env" in script
    assert "--json-stdout" not in script
    assert "GITHUB_ENV" not in script


def test_declared_outputs_parser() -> None:
    text = (
        "name: x\n"
        "outputs:\n"
        "  # a comment\n"
        "  alpha:\n"
        "    description: 'one'\n"
        "    value: ${{ steps.s.outputs.alpha }}\n"
        "  beta:\n"
        "    value: b\n"
        "runs:\n"
        "  using: composite\n"
    )
    assert declared_outputs(text) == {"alpha", "beta"}


def test_run_script_parser() -> None:
    text = (
        "runs:\n"
        "  steps:\n"
        "    - shell: bash\n"
        "      run: |\n"
        "        echo one\n"
        "\n"
        "        if true; then\n"
        "          echo two\n"
        "        fi\n"
        "    - name: next\n"
    )
    assert run_script(text) == "echo one\n\nif true; then\n  echo two\nfi\n"


# ---------------------------------------------------------------------
# Token isolation
#
# The step runs the resolver as 'python3 -I -S', so neither PYTHON*
# variables nor site-packages can load code into the interpreter that
# holds the token. A hostile '.pth' file is the canonical attack: site
# executes any line of it that starts with 'import'.
# ---------------------------------------------------------------------

TOKEN_VAR = "RESOLVE_TOKEN"
SECRET = "isolation-test-secret"


def _hostile_venv(tmp_path: Path) -> tuple[Path, Path]:
    """Build a venv whose site-packages copies the token to a marker."""
    venv = tmp_path / "venv"
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(venv)],
        check=True,
    )
    marker = tmp_path / "marker"
    site = next(venv.glob("lib/python*/site-packages"))
    (site / "zz_steal_token.pth").write_text(
        "import os; v = os.environ.get("
        f"{TOKEN_VAR!r}); v and open({str(marker)!r}, 'w').write(v)\n",
        encoding="utf-8",
    )
    return venv / "bin", marker


def _failing_git(tmp_path: Path) -> Path:
    """Put a 'git' on a private bin directory that always fails."""
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir()
    stub = stub_dir / "git"
    stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    stub.chmod(0o755)
    return stub_dir


def test_pth_hook_fires_under_plain_python(tmp_path: Path) -> None:
    """Control case: the hostile venv does leak the token without -I -S."""
    venv_bin, marker = _hostile_venv(tmp_path)
    env = dict(os.environ, **{TOKEN_VAR: SECRET})
    subprocess.run([str(venv_bin / "python3"), "-c", "pass"], env=env, check=True)
    assert marker.read_text(encoding="utf-8") == SECRET


@pytest.mark.xfail(strict=True, reason="resolve-config sub-action not yet added")
def test_config_step_does_not_load_site_packages(tmp_path: Path) -> None:
    venv_bin, marker = _hostile_venv(tmp_path)
    stub_dir = _failing_git(tmp_path)
    script = tmp_path / "step.sh"
    script.write_text(run_script(_action_text()), encoding="utf-8")
    env = dict(
        os.environ,
        PATH=os.pathsep.join([str(venv_bin), str(stub_dir), os.environ["PATH"]]),
        GITHUB_ACTION_PATH=str(ACTION_FILE.parent),
        GITHUB_OUTPUT=str(tmp_path / "github_output"),
        GITHUB_STEP_SUMMARY=str(tmp_path / "step_summary"),
        RESOLVE_CONFIG="lfreleng-actions@main",
        RESOLVE_FAMILY="python-audit",
        RESOLVE_MODE="vulns",
        RESOLVE_WORKFLOW_ORG="lfreleng-actions",
        RESOLVE_DEFAULT_FILENAME="allow_list.txt",
        RESOLVE_TIMEOUT="5",
        RESOLVE_SUMMARY="true",
        RESOLVE_SUMMARY_TITLE="",
        RESOLVE_SUMMARY_UNIT="Entries",
        **{TOKEN_VAR: SECRET},
    )
    # The runner's own invocation for 'shell: bash'.
    proc = subprocess.run(
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # The stub git proves the script reached the resolver, which ran
    # under the hostile venv's python3 without loading its .pth file.
    assert proc.returncode != 0
    assert "git init failed" in proc.stderr, proc.stderr
    assert not marker.exists()
