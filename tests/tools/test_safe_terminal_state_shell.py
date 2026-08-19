import os
import subprocess
import sys
from pathlib import Path

import pytest

from tools.environments.safe_terminal_state import (
    SAFE_STATE_NAMES,
    build_safe_state_shell_scripts,
    decode_safe_state,
)
from tools.environments.local import _find_bash, _windows_to_msys_path


try:
    BASH = _find_bash()
except RuntimeError:
    BASH = None
TEST_PLATFORM = "msys" if sys.platform == "win32" else "posix"
pytestmark = pytest.mark.skipif(BASH is None, reason="Bash is required")


def _scripts(tmp_path: Path):
    state_path = str(tmp_path / "state.v1")
    temp_template = str(tmp_path / "state.v1.tmp.XXXXXXXXXX")
    if TEST_PLATFORM == "msys":
        state_path = _windows_to_msys_path(state_path)
        temp_template = _windows_to_msys_path(temp_template)
    return build_safe_state_shell_scripts(
        state_path,
        temp_template,
        platform=TEST_PLATFORM,
    )


def _run(script: str, *, cwd: Path, env: dict[str, str] | None = None):
    return subprocess.run(
        [BASH, "-c", script],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
    )


def test_generated_scripts_never_execute_or_dump_environment(tmp_path):
    scripts = _scripts(tmp_path)
    joined = "\n".join((scripts.probe, scripts.apply, scripts.capture))

    for forbidden in ("source ", "eval ", "export -p", "declare -x", " env "):
        assert forbidden not in joined
    assert len(scripts.probe + "\n" + scripts.apply) < 8_000
    assert len(scripts.probe + "\n" + scripts.capture) < 8_000
    assert len("\n".join((scripts.probe, scripts.apply, scripts.capture))) < 6_000


def test_capture_and_apply_round_trip_drops_unknown_exports(tmp_path):
    scripts = _scripts(tmp_path)
    capture_env = os.environ.copy()
    capture_env.update(
        {
            "PATH": "/opt/app/.venv/bin:/usr/bin:/bin",
            "VIRTUAL_ENV": "/opt/app/.venv",
            "SERVICE_TOKEN": "synthetic-secret",
            "ORDINARY_SETTING": "drop-me",
        }
    )

    captured = _run(
        f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=capture_env
    )

    assert captured.returncode == 0, captured.stderr
    records = dict(
        decode_safe_state((tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM).records
    )
    assert records["PATH"].endswith("/opt/app/.venv/bin:/usr/bin:/bin")
    assert records["VIRTUAL_ENV"] == "/opt/app/.venv"
    assert set(records) == set(SAFE_STATE_NAMES)
    assert "SERVICE_TOKEN" not in records
    assert "ORDINARY_SETTING" not in records

    applied = _run(
        f"{scripts.probe}\n{scripts.apply}\n"
        "printf '%s|%s|%s' \"$VIRTUAL_ENV\" "
        "\"${SERVICE_TOKEN-unset}\" \"${ORDINARY_SETTING-unset}\"",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )

    assert applied.returncode == 0, applied.stderr
    assert applied.stdout == "/opt/app/.venv|unset|unset"


def test_apply_treats_encoded_value_as_data_not_shell_code(tmp_path):
    scripts = _scripts(tmp_path)
    marker = tmp_path / "pwned"
    payload = f"$(touch {marker})"
    capture_env = os.environ.copy()
    capture_env.update(
        {
            "PATH": "/usr/bin:/bin",
            "CONDA_DEFAULT_ENV": payload,
        }
    )
    captured = _run(
        f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=capture_env
    )
    assert captured.returncode == 0, captured.stderr

    applied = _run(
        f"{scripts.probe}\n{scripts.apply}\nprintf '%s' \"$CONDA_DEFAULT_ENV\"",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )

    assert applied.returncode == 0, applied.stderr
    assert applied.stdout == payload
    assert not marker.exists()


def test_second_capture_emits_unset_and_clears_stale_venv(tmp_path):
    scripts = _scripts(tmp_path)
    first_env = os.environ.copy()
    first_env.update(
        {"PATH": "/workspace/.venv/bin:/usr/bin:/bin", "VIRTUAL_ENV": "/workspace/.venv"}
    )
    assert _run(
        f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=first_env
    ).returncode == 0

    second_env = os.environ.copy()
    second_env.update({"PATH": "/usr/bin:/bin"})
    second_env.pop("VIRTUAL_ENV", None)
    assert _run(
        f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=second_env
    ).returncode == 0

    records = dict(
        decode_safe_state((tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM).records
    )
    assert records["PATH"].endswith("/usr/bin:/bin")
    assert records["VIRTUAL_ENV"] is None

    stale_env = {"PATH": "/workspace/.venv/bin:/usr/bin:/bin", "VIRTUAL_ENV": "/workspace/.venv"}
    applied = _run(
        f"{scripts.probe}\n{scripts.apply}\n"
        "printf '%s|%s' \"${VIRTUAL_ENV-unset}\" \"$PATH\"",
        cwd=tmp_path,
        env=stale_env,
    )
    assert applied.returncode == 0, applied.stderr
    assert applied.stdout == f"unset|{records['PATH']}"


def test_malformed_extra_line_rejects_whole_file_without_partial_apply(tmp_path):
    scripts = _scripts(tmp_path)
    env = os.environ.copy()
    env.update({"PATH": "/safe/bin:/usr/bin", "VIRTUAL_ENV": "/safe/.venv"})
    assert _run(f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=env).returncode == 0
    with (tmp_path / "state.v1").open("ab") as handle:
        handle.write(b"SET\tSERVICE_TOKEN\tc3ludGhldGlj\n")

    original_env = {"PATH": "/original/bin:/usr/bin", "VIRTUAL_ENV": "/original/.venv"}
    applied = _run(
        f"{scripts.probe}\n{scripts.apply}\n"
        "__rc=$?; printf '%s|%s|%s' \"$__rc\" \"$VIRTUAL_ENV\" \"$PATH\"",
        cwd=tmp_path,
        env=original_env,
    )

    status, venv, path_value = applied.stdout.split("|", 2)
    assert status == "93"
    assert venv == "/original/.venv"
    assert path_value.endswith("/original/bin:/usr/bin")


def test_codec_probe_failure_creates_no_state_file(tmp_path):
    scripts = _scripts(tmp_path)
    result = _run(
        "base64() { return 127; }\n"
        f"{scripts.probe}\n__probe=$?\n{scripts.capture}\n"
        "__capture=$?\nprintf '%s|%s' \"$__probe\" \"$__capture\"",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )

    assert result.stdout == "97|97"
    assert not (tmp_path / "state.v1").exists()


def test_failed_atomic_publish_keeps_previous_complete_state(tmp_path):
    scripts = _scripts(tmp_path)
    first_env = os.environ.copy()
    first_env.update({"PATH": "/first/bin:/usr/bin"})
    assert _run(f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=first_env).returncode == 0
    before = (tmp_path / "state.v1").read_bytes()

    second_env = os.environ.copy()
    second_env.update({"PATH": "/second/bin:/usr/bin"})
    failed = _run(
        f"{scripts.probe}\n"
        "mv() { return 1; }\n"
        f"{scripts.capture}",
        cwd=tmp_path,
        env=second_env,
    )

    assert failed.returncode != 0
    assert (tmp_path / "state.v1").read_bytes() == before
    assert list(tmp_path.glob("state.v1.tmp.*")) == []


def test_concurrent_writers_publish_only_complete_old_or_new_state(tmp_path):
    scripts = _scripts(tmp_path)
    expected_paths = {f"/writer-{index}/bin:/usr/bin" for index in range(8)}

    processes = []
    for path_value in sorted(expected_paths):
        env = os.environ.copy()
        env.update({"PATH": path_value})
        processes.append(
            subprocess.Popen(
                [BASH, "-c", f"{scripts.probe}\n{scripts.capture}"],
                cwd=tmp_path,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        )

    for process in processes:
        stdout, stderr = process.communicate(timeout=20)
        assert process.returncode == 0, (stdout, stderr)

    state = decode_safe_state((tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM)
    final_path = dict(state.records)["PATH"]
    assert any(final_path.endswith(path) for path in expected_paths)
    assert list(tmp_path.glob("state.v1.tmp.*")) == []
