import base64
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from tools.environments.safe_terminal_state import (
    SAFE_STATE_FRESH_NAMES_ENV,
    SAFE_STATE_NAMES,
    SAFE_STATE_PASSTHROUGH_ENV,
    build_safe_state_shell_scripts,
    decode_safe_state,
    encode_safe_state,
)
from tools.environments.local import _find_bash, _windows_to_msys_path


try:
    BASH = _find_bash()
except RuntimeError:
    BASH = None
TEST_PLATFORM = "msys" if sys.platform == "win32" else "posix"
pytestmark = pytest.mark.skipif(BASH is None, reason="Bash is required")


def _scripts(tmp_path: Path, platform: str = TEST_PLATFORM):
    state_path = str(tmp_path / "state.v1")
    if platform == "msys":
        state_path = _windows_to_msys_path(state_path)
    return build_safe_state_shell_scripts(
        state_path,
        state_path + ".tmp.XXXXXXXXXX",
        platform=platform,
        python_path=_windows_to_msys_path(sys.executable),
    )


def _run(script: str, *, cwd: Path, env: dict[str, str] | None = None):
    run_env = dict(env) if env is not None else None
    if run_env is not None:
        run_env.pop(SAFE_STATE_FRESH_NAMES_ENV, None)
        run_env.pop(SAFE_STATE_PASSTHROUGH_ENV, None)
    if sys.platform == "win32":
        loader = (
            "_hermes_script=; IFS= read -r -d '' _hermes_script || true; "
            "exec </dev/null; eval \"$_hermes_script\""
        )
        args = [BASH, "-c", loader]
        script_input = script
    else:
        args = [BASH, "-c", script]
        script_input = None
    return subprocess.run(
        args,
        cwd=cwd,
        env=run_env,
        input=script_input,
        text=True,
        capture_output=True,
    )


def _assert_captured_path(value: str, expected: str) -> None:
    """On msys Bash, PATH is transparently prefixed by runtime entries."""
    if TEST_PLATFORM == "msys":
        assert value.endswith(expected)
        return
    assert value == expected


def test_generated_scripts_never_execute_or_dump_environment(tmp_path):
    scripts = _scripts(tmp_path)
    joined = "\n".join((scripts.probe, scripts.apply, scripts.capture))

    for forbidden in ("source ", "eval ", "export -p", "declare -x", " env "):
        assert forbidden not in joined
    assert "readonly _hss_helper_code" in joined
    # Windows executes generated scripts through the stdin loader; POSIX has a
    # much larger ARG_MAX. Keep a bounded size guard without relying on MSYS's
    # legacy ~8 KiB `bash -c` limit.
    assert len(scripts.probe + "\n" + scripts.apply) < 12_000
    assert len(scripts.probe + "\n" + scripts.capture) < 12_000
    assert len(joined) < 14_000


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
    records = {
        r.name: r.value
        for r in decode_safe_state(
            (tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM
        ).records
    }
    _assert_captured_path(records["PATH"], "/opt/app/.venv/bin:/usr/bin:/bin")
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


def test_capture_framing_rejects_newline_tab_record_injection(tmp_path):
    scripts = _scripts(tmp_path)
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": "/usr/bin:/bin",
            "CONDA_DEFAULT_ENV": "safe-prefix\n_CE_M\tinjected-by-framing",
        }
    )

    captured = _run(
        f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=environment
    )
    records = dict(
        decode_safe_state(
            (tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM
        ).records
    )

    assert captured.returncode == 0, captured.stderr
    assert records["CONDA_DEFAULT_ENV"] is None
    assert records["_CE_M"] is None


def test_capture_flattens_exported_values_and_ignores_printf_shadow(tmp_path):
    scripts = _scripts(tmp_path)
    captured = _run(
        f"{scripts.probe}\n"
        "SYNTHETIC_SECRET=synthetic-review-secret\n"
        "declare -nx CONDA_DEFAULT_ENV=SYNTHETIC_SECRET\n"
        "declare -ax _CE_M=(array-secret)\n"
        "printf() { command printf fake > fake-printf-called; }\n"
        f"{scripts.capture}",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )
    records = dict(
        decode_safe_state(
            (tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM
        ).records
    )

    assert captured.returncode == 0, captured.stderr
    assert records["CONDA_DEFAULT_ENV"] == "SYNTHETIC_SECRET"
    assert records["_CE_M"] is None
    assert not (tmp_path / "fake-printf-called").exists()


def test_capture_uses_exported_value_when_declare_is_disabled(tmp_path):
    scripts = _scripts(tmp_path)
    captured = _run(
        f"{scripts.probe}\n"
        "declare -rx CONDA_DEFAULT_ENV=special-attribute-review-value\n"
        "enable -n declare\n"
        f"{scripts.capture}",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )
    records = dict(
        decode_safe_state(
            (tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM
        ).records
    )

    assert captured.returncode == 0, captured.stderr
    assert records["CONDA_DEFAULT_ENV"] == "special-attribute-review-value"


def test_capture_ignores_builtin_function_shadow(tmp_path):
    scripts = _scripts(tmp_path)
    captured = _run(
        f"{scripts.probe}\n"
        "declare -rx CONDA_DEFAULT_ENV=special-attribute-review-value\n"
        "builtin() { return 0; }\n"
        f"{scripts.capture}",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )
    records = dict(
        decode_safe_state(
            (tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM
        ).records
    )

    assert captured.returncode == 0, captured.stderr
    assert records["CONDA_DEFAULT_ENV"] == "special-attribute-review-value"


def test_capture_uses_exported_value_when_builtin_is_disabled(tmp_path):
    scripts = _scripts(tmp_path)
    captured = _run(
        f"{scripts.probe}\n"
        "declare -rx CONDA_DEFAULT_ENV=special-attribute-review-value\n"
        "enable -n builtin\n"
        f"{scripts.capture}",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )
    records = dict(
        decode_safe_state(
            (tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM
        ).records
    )

    assert captured.returncode == 0, captured.stderr
    assert records["CONDA_DEFAULT_ENV"] == "special-attribute-review-value"


def test_posix_runtime_round_trip_on_current_host(tmp_path):
    scripts = _scripts(tmp_path, platform="posix")
    capture_env = os.environ.copy()
    capture_env.update(
        {
            "PATH": "/workspace/.venv/bin:/usr/bin:/bin",
            "VIRTUAL_ENV": "/workspace/.venv",
        }
    )

    captured = _run(
        f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=capture_env
    )
    state = decode_safe_state(
        (tmp_path / "state.v1").read_bytes(), platform="posix"
    )
    records = dict(state.records)
    applied = _run(
        f"{scripts.probe}\n{scripts.apply}\n"
        "printf '%s|%s' \"$VIRTUAL_ENV\" \"$PATH\"",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )

    assert captured.returncode == 0, captured.stderr
    assert records["VIRTUAL_ENV"] == "/workspace/.venv"
    assert records["PATH"].endswith("/workspace/.venv/bin:/usr/bin:/bin")
    assert applied.returncode == 0, applied.stderr
    applied_venv, applied_path = applied.stdout.split("|", 1)
    assert applied_venv == "/workspace/.venv"
    assert applied_path.endswith("/workspace/.venv/bin:/usr/bin:/bin")


def test_apply_treats_encoded_value_as_data_not_shell_code(tmp_path):
    scripts = _scripts(tmp_path)
    marker = tmp_path / "marker.txt"
    payload = "$(touch %s)" % _windows_to_msys_path(str(marker))
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

    records = {
        r.name: r.value
        for r in decode_safe_state(
            (tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM
        ).records
    }
    _assert_captured_path(records["PATH"], "/usr/bin:/bin")
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
    if TEST_PLATFORM == "msys":
        # Bash adds runtime prefixes before env restoration; require target suffix only.
        assert path_value.endswith("/original/bin:/usr/bin")
    else:
        assert path_value == "/original/bin:/usr/bin"


def test_codec_probe_failure_creates_no_state_file(tmp_path):
    scripts = build_safe_state_shell_scripts(
        str(tmp_path / "state.v1"),
        str(tmp_path / "state.v1.tmp.XXXXXXXXXX"),
        platform=TEST_PLATFORM,
        python_path="__definitely_missing_interpreter__",
    )
    result = _run(
        f"{scripts.probe}\n__probe=$?\n{scripts.capture}\n"
        "__capture=$?\nprintf '%s|%s' \"$__probe\" \"$__capture\"",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )

    assert result.stdout == "97|97"
    assert not (tmp_path / "state.v1").exists()


def test_probe_ignores_python_shell_function_shadow(tmp_path):
    state_path = str(tmp_path / "state.v1")
    if TEST_PLATFORM == "msys":
        state_path = _windows_to_msys_path(state_path)
    scripts = build_safe_state_shell_scripts(
        state_path,
        state_path + ".tmp.XXXXXXXXXX",
        platform=TEST_PLATFORM,
        python_path=None,
    )
    result = _run(
        "python3() { printf fake > fake-python-called; return 1; }\n"
        "type() { printf fake > fake-type-called; builtin type \"$@\"; }\n"
        f"{scripts.probe}\n{scripts.capture}",
        cwd=tmp_path,
        env=os.environ.copy(),
    )

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "fake-python-called").exists()
    assert not (tmp_path / "fake-type-called").exists()
    assert (tmp_path / "state.v1").exists()


def test_probe_rejects_relative_interpreter_path_before_execution(tmp_path):
    relative_bin = tmp_path / "bin"
    relative_bin.mkdir()
    fake_python = relative_bin / "python3"
    fake_python.write_text(
        "#!/bin/sh\nprintf fake > fake-relative-python\nexit 0\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    state_path = str(tmp_path / "state.v1")
    if TEST_PLATFORM == "msys":
        state_path = _windows_to_msys_path(state_path)
    scripts = build_safe_state_shell_scripts(
        state_path,
        state_path + ".tmp.XXXXXXXXXX",
        platform=TEST_PLATFORM,
        python_path=None,
    )

    result = _run(
        f"{scripts.probe}\n__probe=$?\n{scripts.capture}\n"
        "__capture=$?; printf '%s|%s' \"$__probe\" \"$__capture\"",
        cwd=tmp_path,
        env={"PATH": "bin:/usr/bin:/bin"},
    )

    assert result.stdout == "97|97"
    assert not (tmp_path / "fake-relative-python").exists()
    assert not (tmp_path / "state.v1").exists()


def test_codec_isolated_from_cwd_python_modules(tmp_path):
    scripts = _scripts(tmp_path)
    (tmp_path / "base64.py").write_text(
        "from pathlib import Path\n"
        "Path('malicious-imported').write_text('executed', encoding='utf-8')\n"
        "raise RuntimeError('synthetic import hijack')\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["PATH"] = "/usr/bin:/bin"

    result = _run(
        f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=environment
    )

    assert result.returncode == 0, result.stderr
    assert not (tmp_path / "malicious-imported").exists()
    assert (tmp_path / "state.v1").exists()


def _write_fake_base64(path: Path, encode_body: str) -> None:
    path.write_text(
        "#!/bin/sh\n"
        "case \"${1-}\" in --decode|-d|-D) exec /usr/bin/base64 \"$@\" ;; esac\n"
        f"{encode_body}\n",
        encoding="utf-8",
    )
    path.chmod(0o755)


def test_capture_codec_cannot_read_credentials_from_persisted_path(tmp_path):
    scripts = _scripts(tmp_path)
    malicious_bin = tmp_path / "malicious-bin"
    malicious_bin.mkdir()
    _write_fake_base64(
        malicious_bin / "base64",
        "printf '%s' \"/leaked/$SYNTHETIC_TOKEN\" | /usr/bin/base64",
    )
    env = os.environ.copy()
    malicious_msys = _windows_to_msys_path(str(malicious_bin))
    env.update(
        {
            "PATH": f"{malicious_msys}:/usr/bin:/bin",
            "SYNTHETIC_TOKEN": "review-secret-marker",
        }
    )

    captured = _run(f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=env)

    assert captured.returncode == 0, captured.stderr
    records = {
        r.name: r.value
        for r in decode_safe_state(
            (tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM
        ).records
    }
    assert all("review-secret-marker" not in (value or "") for value in records.values())
    _assert_captured_path(records["PATH"], f"{malicious_msys}:/usr/bin:/bin")


def test_capture_failure_never_overwrites_previous_state(tmp_path):
    scripts = _scripts(tmp_path)
    initial_env = os.environ.copy()
    initial_env["PATH"] = "/initial/bin:/usr/bin:/bin"
    assert _run(
        f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=initial_env
    ).returncode == 0
    before = (tmp_path / "state.v1").read_bytes()

    # Make the canonical target an un-replaceable directory: helper's
    # os.replace(tmp, target) must fail, the canonical file must be left
    # intact, and the capture must report failure.
    (tmp_path / "state.v1").unlink()
    (tmp_path / "state.v1").mkdir()
    failed = _run(
        f"{scripts.probe}\n{scripts.capture}",
        cwd=tmp_path,
        env=initial_env,
    )

    assert failed.returncode != 0
    assert failed.stderr == ""
    assert (tmp_path / "state.v1").is_dir()
    assert list(tmp_path.glob("state.v1.tmp.*")) == []
    (tmp_path / "state.v1").rmdir()
    (tmp_path / "state.v1").write_bytes(before)
    assert (tmp_path / "state.v1").read_bytes() == before


def test_runtime_capture_rejects_aggregate_oversize_without_overwrite(tmp_path):
    scripts = _scripts(tmp_path)
    initial_env = os.environ.copy()
    initial_env["PATH"] = "/initial/bin:/usr/bin"
    assert _run(
        f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=initial_env
    ).returncode == 0
    before = (tmp_path / "state.v1").read_bytes()

    oversized_env = os.environ.copy()
    oversized_env.update(
        {
            "PATH": "/" + "p" * 32_767,
            "VIRTUAL_ENV": "/" + "v" * 4_095,
            "CONDA_PREFIX": "/" + "c" * 4_095,
            "CONDA_DEFAULT_ENV": "d" * 4_096,
            "CONDA_SHLVL": "99",
            "CONDA_EXE": "/" + "e" * 4_095,
            "CONDA_PYTHON_EXE": "/" + "y" * 4_095,
            "_CE_CONDA": "a" * 4_096,
            "_CE_M": "m" * 4_096,
        }
    )
    failed = _run(
        f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=oversized_env
    )

    assert failed.returncode != 0
    assert (tmp_path / "state.v1").read_bytes() == before
    assert list(tmp_path.glob("state.v1.tmp.*")) == []


@pytest.mark.parametrize(
    "mutation",
    (
        "header_trailing_tab",
        "unset_trailing_tab",
        "invalid_utf8",
        "missing_final_newline",
    ),
)
def test_runtime_parser_rejects_every_payload_rejected_by_python_oracle(
    tmp_path, mutation
):
    scripts = _scripts(tmp_path)
    payload = encode_safe_state(
        {"PATH": "/safe/bin:/usr/bin:/bin"}, platform=TEST_PLATFORM
    )
    if mutation == "header_trailing_tab":
        payload = payload.replace(b"HERMES_SAFE_TERMINAL_STATE\t1\n", b"HERMES_SAFE_TERMINAL_STATE\t1\t\n", 1)
    elif mutation == "unset_trailing_tab":
        payload = payload.replace(b"UNSET\tVIRTUAL_ENV\n", b"UNSET\tVIRTUAL_ENV\t\n", 1)
    elif mutation == "invalid_utf8":
        payload = payload.replace(
            b"UNSET\tCONDA_DEFAULT_ENV\n",
            b"SET\tCONDA_DEFAULT_ENV\tL/8=\n",
            1,
        )
    elif mutation == "missing_final_newline":
        payload = payload[:-1]
    (tmp_path / "state.v1").write_bytes(payload)

    with pytest.raises(Exception):
        decode_safe_state(payload, platform=TEST_PLATFORM)
    applied = _run(
        f"{scripts.probe}\n{scripts.apply}\nprintf '%s' \"$?\"",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )

    assert applied.stdout == "93"


@pytest.mark.windows_only
@pytest.mark.parametrize(
    "invalid_path",
    ("C:/safe:relative", "/usr/bin:relative;/bin", "É:/usr/bin:/bin"),
)
def test_runtime_parser_rejects_drive_prefixed_colon_path_list(tmp_path, invalid_path):
    scripts = _scripts(tmp_path)
    valid_path = "/safe/bin:/usr/bin:/bin"
    payload = encode_safe_state({"PATH": valid_path}, platform=TEST_PLATFORM)
    payload = payload.replace(
        b"SET\tPATH\t"
        + base64.b64encode(valid_path.encode("utf-8"))
        + b"\n",
        b"SET\tPATH\t"
        + base64.b64encode(invalid_path.encode("utf-8"))
        + b"\n",
        1,
    )
    (tmp_path / "state.v1").write_bytes(payload)

    with pytest.raises(Exception):
        decode_safe_state(payload, platform=TEST_PLATFORM)
    applied = _run(
        f"{scripts.probe}\n{scripts.apply}\nprintf '%s' \"$?\"",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )

    assert applied.stdout == "93"


def test_apply_assignment_failure_is_atomic(tmp_path):
    scripts = _scripts(tmp_path)
    (tmp_path / "state.v1").write_bytes(
        encode_safe_state(
            {
                "PATH": "/safe/bin:/usr/bin:/bin",
                "VIRTUAL_ENV": "/new/.venv",
                "CONDA_DEFAULT_ENV": "new-env",
            },
            platform=TEST_PLATFORM,
        )
    )
    applied = _run(
        "readonly VIRTUAL_ENV=/original/.venv\n"
        "unset CONDA_DEFAULT_ENV\n"
        f"{scripts.probe}\n{scripts.apply}\n"
        "__rc=$?; printf '%s|%s|%s|%s' \"$__rc\" \"$VIRTUAL_ENV\" "
        "\"${CONDA_DEFAULT_ENV-unset}\" \"$PATH\"",
        cwd=tmp_path,
        env={"PATH": "/original/bin:/usr/bin"},
    )

    status, venv, conda_env, path_value = applied.stdout.split("|", 3)
    assert status == "93"
    assert venv == "/original/.venv"
    assert conda_env == "unset"
    _assert_captured_path(path_value, "/original/bin:/usr/bin")
    assert not (tmp_path / "state.v1.raw").exists()


def test_apply_rejects_nameref_before_any_mutation(tmp_path):
    scripts = _scripts(tmp_path)
    (tmp_path / "state.v1").write_bytes(
        encode_safe_state(
            {
                "PATH": "/new/bin:/usr/bin:/bin",
                "VIRTUAL_ENV": "/new/.venv",
            },
            platform=TEST_PLATFORM,
        )
    )
    applied = _run(
        "readonly _hss_readonly_target=/original/.venv\n"
        "declare -n VIRTUAL_ENV=_hss_readonly_target\n"
        f"{scripts.probe}\n{scripts.apply}\n"
        "__rc=$?; printf '%s|%s|%s' \"$__rc\" \"$VIRTUAL_ENV\" \"$PATH\"",
        cwd=tmp_path,
        env={"PATH": "/original/bin:/usr/bin"},
    )

    status, venv, path_value = applied.stdout.split("|", 2)
    assert status == "93"
    assert venv == "/original/.venv"
    _assert_captured_path(path_value, "/original/bin:/usr/bin")


def test_apply_is_compatible_with_errexit(tmp_path):
    scripts = _scripts(tmp_path)
    (tmp_path / "state.v1").write_bytes(
        encode_safe_state(
            {"PATH": "/safe/bin:/usr/bin:/bin", "VIRTUAL_ENV": "/safe/.venv"},
            platform=TEST_PLATFORM,
        )
    )

    applied = _run(
        "set -e\n"
        f"{scripts.probe}\n{scripts.apply}\n"
        "printf reached",
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
    )

    assert applied.returncode == 0, applied.stderr
    assert applied.stdout == "reached"


def test_concurrent_writers_publish_only_complete_old_or_new_state(tmp_path):
    scripts = _scripts(tmp_path)
    initial_path = "/initial/bin:/usr/bin"
    expected_paths = {initial_path} | {
        f"/writer-{index}/bin:/usr/bin" for index in range(8)
    }
    initial_env = os.environ.copy()
    initial_env["PATH"] = initial_path
    assert _run(
        f"{scripts.probe}\n{scripts.capture}", cwd=tmp_path, env=initial_env
    ).returncode == 0

    start_reading = threading.Event()
    stop_reading = threading.Event()
    reader_errors = []
    observed_paths = []

    def read_during_writes():
        start_reading.wait(5)
        while not stop_reading.is_set():
            try:
                payload = (tmp_path / "state.v1").read_bytes()
                state = decode_safe_state(payload, platform=TEST_PLATFORM)
                path_value = {r.name: r.value for r in state.records}["PATH"]
                if not any(path_value.endswith(path) for path in expected_paths):
                    reader_errors.append(f"unexpected PATH: {path_value!r}")
                    return
                observed_paths.append(path_value)
            except PermissionError:
                continue
            except Exception as exc:
                reader_errors.append(repr(exc))
                return

    reader = threading.Thread(target=read_during_writes, daemon=True)
    reader.start()
    processes = []
    for path_value in sorted(expected_paths - {initial_path}):
        env = os.environ.copy()
        env.update({"PATH": path_value})
        env.pop(SAFE_STATE_FRESH_NAMES_ENV, None)
        env.pop(SAFE_STATE_PASSTHROUGH_ENV, None)
        script = f"{scripts.probe}\n" + "\n".join(
            scripts.capture for _ in range(6)
        )
        if sys.platform == "win32":
            args = [BASH, "-s"]
            script_input = script
        else:
            args = [BASH, "-c", script]
            script_input = None
        process = subprocess.Popen(
            args,
            cwd=tmp_path,
            env=env,
            text=True,
            stdin=subprocess.PIPE if script_input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        processes.append((process, script_input))
    start_reading.set()

    for process, script_input in processes:
        stdout, stderr = process.communicate(script_input, timeout=20)
        assert process.returncode == 0, (stdout, stderr)
    stop_reading.set()
    reader.join(timeout=5)

    assert not reader_errors
    assert observed_paths
    state = decode_safe_state((tmp_path / "state.v1").read_bytes(), platform=TEST_PLATFORM)
    final_path = {r.name: r.value for r in state.records}["PATH"]
    assert any(final_path.endswith(path) for path in expected_paths)
    assert list(tmp_path.glob("state.v1.tmp.*")) == []
