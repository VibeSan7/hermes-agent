"""Multiline session values must be ignored, never serialized or executed."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.environments.local import _find_bash, _windows_to_msys_path
from tools.environments.safe_terminal_state import (
    SAFE_STATE_NAMES,
    build_safe_state_shell_scripts,
    decode_safe_state,
)


try:
    BASH = _find_bash()
except RuntimeError:
    BASH = None
PLATFORM = "msys" if sys.platform == "win32" else "posix"
pytestmark = pytest.mark.skipif(BASH is None, reason="Bash is required")


def _shell_path(path: Path) -> str:
    value = str(path)
    return _windows_to_msys_path(value) if PLATFORM == "msys" else value


def _run_capture_and_apply(
    *,
    tmp_path: Path,
    env_name: str,
    env_value: str,
    marker: Path,
):
    state_path = _shell_path(tmp_path / "state.v1")
    scripts = build_safe_state_shell_scripts(
        state_path,
        state_path + ".tmp.XXXXXXXXXX",
        platform=PLATFORM,
    )
    environment = os.environ.copy()
    environment["PATH"] = "/usr/bin:/bin"
    environment[env_name] = env_value
    captured = subprocess.run(
        [BASH, "-c", f"{scripts.probe}\n{scripts.capture}"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert captured.returncode == 0, captured.stderr

    payload = (tmp_path / "state.v1").read_bytes()
    state = decode_safe_state(payload, platform=PLATFORM)
    assert set(dict(state.records)) == set(SAFE_STATE_NAMES)
    assert env_name.encode() not in payload
    assert b"touch " not in payload

    applied = subprocess.run(
        [BASH, "-c", f"{scripts.probe}\n{scripts.apply}"],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert applied.returncode == 0, applied.stderr
    assert not marker.exists()


@pytest.mark.parametrize(
    ("env_name", "marker_name", "prefix"),
    [
        ("HERMES_SESSION_CHAT_NAME", "pwned_chat", "demo"),
        ("HERMES_SESSION_USER_NAME", "pwned_user", "alice"),
    ],
)
def test_multiline_session_value_is_ignored_and_never_executed(
    tmp_path,
    env_name,
    marker_name,
    prefix,
):
    marker = tmp_path / marker_name
    value = f"{prefix}\ntouch {marker} #"

    _run_capture_and_apply(
        tmp_path=tmp_path,
        env_name=env_name,
        env_value=value,
        marker=marker,
    )
