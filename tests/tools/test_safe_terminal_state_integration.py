import os
import subprocess
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from tools.env_passthrough import clear_env_passthrough, register_env_passthrough
from tools.environments import local
from tools.environments.local import LocalEnvironment
from tools.environments.safe_terminal_state import (
    SAFE_STATE_PASSTHROUGH_ENV,
    decode_safe_state,
    encode_safe_state,
)


SYNTHETIC_CREDENTIAL_NAMES = (
    "TELEGRAM_BOT_TOKEN",
    "API_SERVER_KEY",
    "OPENROUTER_API_KEY",
    "GOOGLE_API_KEY",
    "DEEPSEEK_API_KEY",
    "KIMI_API_KEY",
    "CONTEXT7_API_KEY",
    "LINKUP_API_KEY",
    "SERPER_API_KEY",
    "YOU_API_KEY",
)


def _new_env(tmp_path, monkeypatch):
    home = tmp_path / "hermes-home"
    monkeypatch.setenv("HERMES_HOME", str(home))
    env = LocalEnvironment(cwd=str(tmp_path), timeout=60)
    return env


def _activation_path():
    return ".venv/Scripts/activate" if sys.platform == "win32" else ".venv/bin/activate"


def test_local_user_stdin_survives_wrapper_stdin_transport(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    try:
        result = env.execute("cat", stdin_data="hello from stdin")
    finally:
        env.cleanup()

    assert result["returncode"] == 0
    assert result["output"] == "hello from stdin"


def test_local_explicit_empty_stdin_uses_safe_transport(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    try:
        result = env.execute("cat", stdin_data="")
    finally:
        env.cleanup()

    assert result["returncode"] == 0
    assert result["output"] == ""
    assert env._safe_state_ready is True


@pytest.mark.parametrize("stdin_data", ("", "payload"))
def test_local_inline_stdin_accepts_trailing_comment(tmp_path, monkeypatch, stdin_data):
    env = _new_env(tmp_path, monkeypatch)
    try:
        result = env.execute("cat # valid trailing comment", stdin_data=stdin_data)
    finally:
        env.cleanup()

    assert result["returncode"] == 0, result["output"]
    assert result["output"] == stdin_data


def test_local_command_without_stdin_sees_eof_not_wrapper(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    try:
        result = env.execute("cat")
    finally:
        env.cleanup()

    assert result["returncode"] == 0
    assert result["output"] == ""
    assert env._safe_state_ready is True


def test_python_venv_state_persists_but_arbitrary_exports_do_not(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    try:
        first = env.execute(
            f"python -m venv .venv && source {_activation_path()} && "
            "export ORDINARY_SETTING=drop-me"
        )
        second = env.execute(
            "printf '%s|%s|%s' \"${VIRTUAL_ENV-unset}\" "
            "\"${ORDINARY_SETTING-unset}\" \"$PATH\""
        )
    finally:
        env.cleanup()

    assert first["returncode"] == 0, first["output"]
    assert second["returncode"] == 0, second["output"]
    venv, ordinary, path_value = second["output"].split("|", 2)
    assert venv != "unset"
    assert ordinary == "unset"
    assert ".venv" in venv
    assert ".venv" in path_value


def test_fresh_allowlisted_passthrough_wins_over_persisted_state(tmp_path, monkeypatch):
    clear_env_passthrough()
    env = _new_env(tmp_path, monkeypatch)
    try:
        persisted = env.execute(
            "export PATH=/persisted/bin:/usr/bin:/bin; "
            "export VIRTUAL_ENV=/persisted/.venv"
        )
        register_env_passthrough(["PATH", "VIRTUAL_ENV"])
        monkeypatch.setenv("PATH", "/fresh/bin:/usr/bin:/bin")
        monkeypatch.setenv("VIRTUAL_ENV", "/fresh/.venv")
        fresh_values = {
            "PATH": "/fresh/bin:/usr/bin:/bin",
            "VIRTUAL_ENV": "/fresh/.venv",
        }
        monkeypatch.setattr(
            "tools.env_passthrough.resolve_passthrough_value",
            lambda name, fallback: fresh_values.get(name, fallback),
        )

        observed = env.execute(
            "printf '%s|%s' \"${VIRTUAL_ENV-unset}\" \"$PATH\""
        )
        state = decode_safe_state(
            Path(env._safe_state_path).read_bytes(),
            platform="msys" if sys.platform == "win32" else "posix",
        )
    finally:
        clear_env_passthrough()
        env.cleanup()

    assert persisted["returncode"] == 0
    assert observed["returncode"] == 0
    observed_venv, observed_path = observed["output"].split("|", 1)
    assert observed_venv == "/fresh/.venv"
    assert "/fresh/bin" in observed_path
    assert "/persisted/bin" not in observed_path
    assert dict(state.records)["PATH"] == "/persisted/bin:/usr/bin:/bin"
    assert dict(state.records)["VIRTUAL_ENV"] == "/persisted/.venv"
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "passthrough"


def test_invocation_passthrough_value_cannot_be_copied_into_safe_state(
    tmp_path, monkeypatch
):
    clear_env_passthrough()
    marker = "synthetic-invocation-only-credential"
    monkeypatch.setenv("SYNTHETIC_PASSTHROUGH_VALUE", marker)
    register_env_passthrough(["SYNTHETIC_PASSTHROUGH_VALUE"])
    monkeypatch.setattr(
        "tools.env_passthrough.resolve_passthrough_value",
        lambda name, fallback: marker
        if name == "SYNTHETIC_PASSTHROUGH_VALUE"
        else fallback,
    )
    env = _new_env(tmp_path, monkeypatch)
    try:
        result = env.execute(
            "export CONDA_DEFAULT_ENV=\"$SYNTHETIC_PASSTHROUGH_VALUE\"; "
            "export VIRTUAL_ENV=\"/tmp/$SYNTHETIC_PASSTHROUGH_VALUE\"; "
            "export PATH=\"/tmp/$SYNTHETIC_PASSTHROUGH_VALUE/bin:$PATH\""
        )
        state_exists = Path(env._safe_state_path).exists()
    finally:
        clear_env_passthrough()
        env.cleanup()

    assert result["returncode"] == 0
    assert state_exists is False
    assert env._safe_state_ready is False


def test_forwarded_passthrough_disables_safe_state_permanently(tmp_path, monkeypatch):
    clear_env_passthrough()
    env = _new_env(tmp_path, monkeypatch)
    marker = "synthetic-forwarded-credential"
    name = "SYNTHETIC_FORWARDED_CREDENTIAL"
    monkeypatch.setenv(name, marker)
    register_env_passthrough([name])
    monkeypatch.setattr(
        "tools.env_passthrough.resolve_passthrough_value",
        lambda candidate, fallback: marker if candidate == name else fallback,
    )
    try:
        result = env.execute(f'printf "%s" "${name}"')
    finally:
        clear_env_passthrough()
        env.cleanup()

    assert result["returncode"] == 0
    assert result["output"] == marker
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "passthrough"


@pytest.mark.windows_only
def test_shell_startup_cannot_bypass_host_passthrough_shutdown(tmp_path, monkeypatch):
    clear_env_passthrough()
    env = _new_env(tmp_path, monkeypatch)
    marker = "synthetic-forwarded-credential"
    name = "SYNTHETIC_FORWARDED_CREDENTIAL"
    bash_env = tmp_path / "bash-env"
    bash_env.write_text(
        "unset HERMES_SAFE_STATE_PASSTHROUGH_ACTIVE\n"
        "function [ { return 0; }\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("BASH_ENV", str(bash_env))
    monkeypatch.setenv(name, marker)
    register_env_passthrough([name])
    monkeypatch.setattr(
        "tools.env_passthrough.resolve_passthrough_value",
        lambda candidate, fallback: marker if candidate == name else fallback,
    )
    try:
        result = env.execute(
            f'export CONDA_DEFAULT_ENV="${name}"; printf "%s" "${name}"'
        )
        state = decode_safe_state(
            Path(env._safe_state_path).read_bytes(),
            platform="msys",
        )
    finally:
        clear_env_passthrough()
        env.cleanup()

    assert result["returncode"] == 0
    assert result["output"] == marker
    assert dict(state.records)["CONDA_DEFAULT_ENV"] is None
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "passthrough"


@pytest.mark.windows_only
def test_shell_startup_env_disables_persistence_host_side(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    bash_env = tmp_path / "credential-free-bash-env"
    bash_env.write_text("builtin() { return 0; }\n", encoding="utf-8")
    try:
        seeded = env.execute("export VIRTUAL_ENV=/stale-review/.venv")
        monkeypatch.setenv("BASH_ENV", str(bash_env))
        observed = env.execute("printf '%s' \"${VIRTUAL_ENV-unset}\"")
    finally:
        env.cleanup()

    assert seeded["returncode"] == 0
    assert observed["returncode"] == 0
    assert observed["output"] != "/stale-review/.venv"
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "shell_startup"


@pytest.mark.parametrize(
    "startup_env",
    (
        {"PATH": "/usr/bin:/bin", "BASH_ENV": "/tmp/bash-env"},
        {"PATH": "/usr/bin:/bin", "ENV": "/tmp/sh-env"},
        {"PATH": "/usr/bin:/bin", "BASH_FUNC_builtin%%": "() { return 0; }"},
    ),
)
def test_shell_startup_inputs_disable_persistence(tmp_path, monkeypatch, startup_env):
    env = _new_env(tmp_path, monkeypatch)
    monkeypatch.setattr(local, "_make_run_env", lambda _: startup_env)
    try:
        reason = env._safe_state_preflight_off_reason()
    finally:
        env.cleanup()

    assert reason == "shell_startup"


@pytest.mark.windows_only
def test_preflight_and_popen_use_same_run_env(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    first = {"PATH": os.environ["PATH"], "SYNTHETIC_VALUE": "first"}
    second = {
        "PATH": os.environ["PATH"],
        "SYNTHETIC_VALUE": "second",
        "HERMES_SAFE_STATE_PASSTHROUGH_ACTIVE": "1",
    }
    calls = []
    captured = {}

    def make_run_env(_):
        value = (first, second)[len(calls)]
        calls.append(value)
        return value

    class FakeProcess:
        pid = 1
        stdin = StringIO()

    def fake_popen(args, **kwargs):
        captured["env"] = kwargs["env"]
        return FakeProcess()

    monkeypatch.setattr(local, "_make_run_env", make_run_env)
    monkeypatch.setattr(local.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(local, "_find_bash", lambda: "bash")
    try:
        assert env._safe_state_preflight_off_reason() is None
        env._run_bash("true")
    finally:
        env.cleanup()

    assert calls == [first]
    assert captured["env"] is first


@pytest.mark.windows_only
def test_preflight_failure_clears_stale_prepared_run_env(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    stale = {
        "PATH": os.environ["PATH"],
        "STALE_SYNTHETIC_CREDENTIAL": "must-not-reappear",
    }
    fresh = {"PATH": os.environ["PATH"], "FRESH_VALUE": "current"}
    captured = {}
    env._prepared_run_env.set(stale)

    def fail_run_env(_):
        raise RuntimeError("synthetic preflight failure")

    class FakeProcess:
        pid = 1
        stdin = StringIO()

    def fake_popen(args, **kwargs):
        captured["env"] = kwargs["env"]
        return FakeProcess()

    monkeypatch.setattr(local, "_make_run_env", fail_run_env)
    with pytest.raises(RuntimeError, match="synthetic preflight failure"):
        env._safe_state_preflight_off_reason()
    assert env._prepared_run_env.get() is None

    monkeypatch.setattr(local, "_make_run_env", lambda _: fresh)
    monkeypatch.setattr(local.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(local, "_find_bash", lambda: "bash")
    try:
        env._run_bash("true")
    finally:
        env.cleanup()

    assert captured["env"] is fresh
    assert "STALE_SYNTHETIC_CREDENTIAL" not in captured["env"]


def test_passthrough_marker_contains_no_credential_and_cannot_persist(
    tmp_path, monkeypatch
):
    clear_env_passthrough()
    marker = "synthetic-invocation-only-credential"
    monkeypatch.setenv("SYNTHETIC_PASSTHROUGH_VALUE", marker)
    register_env_passthrough(["SYNTHETIC_PASSTHROUGH_VALUE"])
    monkeypatch.setattr(
        "tools.env_passthrough.resolve_passthrough_value",
        lambda name, fallback: marker
        if name == "SYNTHETIC_PASSTHROUGH_VALUE"
        else fallback,
    )
    run_env = local._make_run_env({})
    metadata = run_env[SAFE_STATE_PASSTHROUGH_ENV]
    env = _new_env(tmp_path, monkeypatch)
    try:
        copied = env.execute(
            f'export CONDA_DEFAULT_ENV="${SAFE_STATE_PASSTHROUGH_ENV}"'
        )
        clear_env_passthrough()
        monkeypatch.delenv("SYNTHETIC_PASSTHROUGH_VALUE", raising=False)
        observed = env.execute("printf '%s' \"${CONDA_DEFAULT_ENV-unset}\"")
        state_exists = Path(env._safe_state_path).exists()
    finally:
        clear_env_passthrough()
        env.cleanup()

    assert copied["returncode"] == 0
    assert metadata == "1"
    assert marker not in metadata
    assert observed["output"] == "unset"
    assert state_exists is False
    assert env._safe_state_ready is False


def test_unforwarded_scoped_value_does_not_set_passthrough_marker(monkeypatch):
    clear_env_passthrough()
    name = "SYNTHETIC_SCOPED_ONLY_VALUE"
    marker = "synthetic-scoped-only-credential"
    monkeypatch.delenv(name, raising=False)
    register_env_passthrough([name])
    monkeypatch.setattr(
        "tools.env_passthrough.resolve_passthrough_value",
        lambda candidate, fallback: marker if candidate == name else fallback,
    )
    try:
        run_env = local._make_run_env({})
    finally:
        clear_env_passthrough()

    assert name not in run_env
    assert SAFE_STATE_PASSTHROUGH_ENV not in run_env


def test_deactivate_clears_stale_venv_and_path(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    try:
        activated = env.execute(
            f"python -m venv .venv && source {_activation_path()}"
        )
        deactivated = env.execute(
            'unset VIRTUAL_ENV; export PATH="${PATH#*/Scripts:}"'
        )
        observed = env.execute(
            "printf '%s|%s' \"${VIRTUAL_ENV-unset}\" \"$PATH\""
        )
    finally:
        env.cleanup()

    assert activated["returncode"] == 0, activated["output"]
    assert deactivated["returncode"] == 0, deactivated["output"]
    venv, path_value = observed["output"].split("|", 1)
    assert venv == "unset"
    assert ".venv" not in path_value


def test_set_e_capture_failure_disables_stale_state(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    try:
        seeded = env.execute("export VIRTUAL_ENV=/stale/.venv")
        failed_capture = env.execute(
            "set -e; unset VIRTUAL_ENV; "
            "printf -v PATH '/%032767d' 0; "
            "printf -v CONDA_PREFIX '/%04095d' 0; "
            "printf -v CONDA_DEFAULT_ENV '%04096d' 0; "
            "printf -v CONDA_EXE '/%04095d' 0; "
            "printf -v CONDA_PYTHON_EXE '/%04095d' 0; "
            "printf -v _CE_CONDA '%04096d' 0; "
            "printf -v _CE_M '%04096d' 0; "
            "export CONDA_PREFIX CONDA_DEFAULT_ENV CONDA_EXE "
            "CONDA_PYTHON_EXE _CE_CONDA _CE_M"
        )
        observed = env.execute("printf '%s' \"${VIRTUAL_ENV-unset}\"")
    finally:
        env.cleanup()

    assert seeded["returncode"] == 0
    assert failed_capture["returncode"] == 0
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason.startswith("capture_")
    assert observed["output"] != "/stale/.venv"


def test_set_e_user_failure_disables_unobserved_stale_state(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    try:
        seeded = env.execute("export VIRTUAL_ENV=/stale/.venv")
        failed = env.execute("set -e; unset VIRTUAL_ENV; false")
        observed = env.execute("printf '%s' \"${VIRTUAL_ENV-unset}\"")
    finally:
        env.cleanup()

    assert seeded["returncode"] == 0
    assert failed["returncode"] == 1
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "command_failed"
    assert observed["output"] != "/stale/.venv"


@pytest.mark.windows_only
def test_failed_command_cannot_keep_state_ready_with_fake_cwd_marker(
    tmp_path, monkeypatch
):
    env = _new_env(tmp_path, monkeypatch)
    try:
        seeded = env.execute("export VIRTUAL_ENV=/stale-review/.venv")
        failed = env.execute(
            "if [[ ${_hermes_script-} =~ (__HERMES_CWD_[0-9a-f]{12}__) ]]; "
            "then _m=${BASH_REMATCH[1]}; "
            "printf '\\n%s%s%s\\n' \"$_m\" \"$PWD\" \"$_m\"; fi; "
            "set -e; unset VIRTUAL_ENV; false"
        )
        observed = env.execute("printf '%s' \"${VIRTUAL_ENV-unset}\"")
    finally:
        env.cleanup()

    assert seeded["returncode"] == 0
    assert failed["returncode"] == 1
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "command_failed"
    assert observed["output"] != "/stale-review/.venv"


@pytest.mark.windows_only
def test_zero_exit_fake_cwd_marker_cannot_hide_missing_capture(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    try:
        seeded = env.execute("export VIRTUAL_ENV=/stale-review/.venv")
        exited = env.execute(
            "if [[ ${_hermes_script-} =~ (__HERMES_CWD_[0-9a-f]{12}__) ]]; "
            "then _m=${BASH_REMATCH[1]}; "
            "printf '\\n%s%s%s\\n' \"$_m\" \"$PWD\" \"$_m\"; fi; "
            "unset VIRTUAL_ENV; exit 0"
        )
        observed = env.execute("printf '%s' \"${VIRTUAL_ENV-unset}\"")
    finally:
        env.cleanup()

    assert seeded["returncode"] == 0
    assert exited["returncode"] == 0
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "capture_unobserved"
    assert observed["output"] != "/stale-review/.venv"


def test_conda_markers_persist_and_deactivate(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    root = (
        local._windows_to_msys_path(str(tmp_path))
        if sys.platform == "win32"
        else str(tmp_path)
    )
    prefix = f"{root}/conda-env"
    conda_exe = f"{root}/miniconda/Scripts/conda.exe"
    conda_python = f"{root}/miniconda/python.exe"
    activate = (
        f"export CONDA_PREFIX='{prefix}' CONDA_DEFAULT_ENV=demo CONDA_SHLVL=1 "
        f"CONDA_EXE='{conda_exe}' CONDA_PYTHON_EXE='{conda_python}' "
        "_CE_CONDA= _CE_M=; "
        f"export PATH='{prefix}/Scripts':\"$PATH\""
    )
    try:
        activated = env.execute(activate)
        state = decode_safe_state(
            Path(env._safe_state_path).read_bytes(),
            platform="msys" if sys.platform == "win32" else "posix",
        )
        values = dict(state.records)

        deactivated = env.execute(
            "unset CONDA_PREFIX CONDA_DEFAULT_ENV CONDA_SHLVL CONDA_EXE "
            "CONDA_PYTHON_EXE _CE_CONDA _CE_M; "
            'export PATH="${PATH#*:}"'
        )
        cleared = decode_safe_state(
            Path(env._safe_state_path).read_bytes(),
            platform="msys" if sys.platform == "win32" else "posix",
        )
        observed = env.execute(
            "printf '%s|%s' \"${CONDA_PREFIX-unset}\" \"$PATH\""
        )
    finally:
        env.cleanup()

    assert activated["returncode"] == 0
    assert values["CONDA_PREFIX"] == prefix
    assert values["CONDA_DEFAULT_ENV"] == "demo"
    assert values["CONDA_SHLVL"] == "1"
    assert values["CONDA_EXE"] == conda_exe
    assert values["CONDA_PYTHON_EXE"] == conda_python
    assert f"{prefix}/Scripts" in values["PATH"]
    assert deactivated["returncode"] == 0
    cleared_values = dict(cleared.records)
    for name in (
        "CONDA_PREFIX",
        "CONDA_DEFAULT_ENV",
        "CONDA_SHLVL",
        "CONDA_EXE",
        "CONDA_PYTHON_EXE",
        "_CE_CONDA",
        "_CE_M",
    ):
        assert cleared_values[name] is None
    assert prefix not in cleared_values["PATH"]
    observed_prefix, observed_path = observed["output"].split("|", 1)
    assert observed_prefix == "unset"
    assert prefix not in observed_path


def test_user_failure_exit_code_survives_state_capture(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    try:
        result = env.execute(
            "export VIRTUAL_ENV=/failed-command/.venv; printf command-failed; false"
        )
        state = decode_safe_state(
            Path(env._safe_state_path).read_bytes(),
            platform="msys" if sys.platform == "win32" else "posix",
        )
    finally:
        env.cleanup()

    assert result["returncode"] == 1
    assert result["output"].strip() == "command-failed"
    assert dict(state.records)["VIRTUAL_ENV"] is None
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "command_failed"


def test_malformed_state_fails_closed_but_command_still_runs(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    Path(env._safe_state_path).write_text(
        "HERMES_SAFE_TERMINAL_STATE\t1\nBROKEN\n",
        encoding="utf-8",
    )
    try:
        result = env.execute("printf command-ok")
    finally:
        env.cleanup()

    assert result["returncode"] == 0
    assert result["output"].strip() == "command-ok"
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason.startswith("apply_")


def test_inherited_errexit_startup_disables_before_apply_and_runs_command(
    tmp_path, monkeypatch
):
    env = _new_env(tmp_path, monkeypatch)
    Path(env._safe_state_path).write_text(
        "HERMES_SAFE_TERMINAL_STATE\t1\nBROKEN\n",
        encoding="utf-8",
    )
    bash_env = tmp_path / "bash-env"
    bash_env.write_text("set -e\n", encoding="utf-8")
    monkeypatch.setenv("BASH_ENV", str(bash_env))
    try:
        result = env.execute("printf command-ran")
    finally:
        env.cleanup()

    assert result["returncode"] == 0
    assert result["output"] == "command-ran"
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "shell_startup"


def test_malformed_config_cannot_widen_persistence(tmp_path, monkeypatch):
    home = tmp_path / "hermes-home"
    home.mkdir()
    (home / "config.yaml").write_text(
        "terminal:\n  env_passthrough:\n    - SERVICE_TOKEN\n  broken: [\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    env = LocalEnvironment(cwd=str(tmp_path), timeout=30)
    try:
        result = env.execute("export SERVICE_TOKEN=synthetic-secret")
        payload = Path(env._safe_state_path).read_bytes()
    finally:
        env.cleanup()

    assert result["returncode"] == 0
    assert b"SERVICE_TOKEN" not in payload
    assert b"synthetic-secret" not in payload


def test_ten_synthetic_credentials_never_enter_safe_state(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    assignments = " ".join(
        f"export {name}=synthetic-{index}"
        for index, name in enumerate(SYNTHETIC_CREDENTIAL_NAMES)
    )
    try:
        result = env.execute(assignments)
        payload = Path(env._safe_state_path).read_bytes()
        state = decode_safe_state(
            payload,
            platform="msys" if sys.platform == "win32" else "posix",
        )
    finally:
        env.cleanup()

    assert result["returncode"] == 0
    decoded_values = [record.value or "" for record in state.records]
    for index, name in enumerate(SYNTHETIC_CREDENTIAL_NAMES):
        marker = f"synthetic-{index}"
        assert name.encode() not in payload
        assert marker.encode() not in payload
        assert all(marker not in value for value in decoded_values)
    assert dict(state.records)["PATH"] is not None


def test_new_environment_never_reuses_previous_state_path(tmp_path, monkeypatch):
    env_a = _new_env(tmp_path, monkeypatch)
    path_a = env_a._safe_state_path
    env_a.cleanup()

    env_b = _new_env(tmp_path, monkeypatch)
    try:
        assert env_b._safe_state_path != path_a
        assert path_a not in env_b._wrap_command("true", str(tmp_path))
    finally:
        env_b.cleanup()


def test_hardlinked_state_artifact_is_rejected(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    state = Path(env._safe_state_path)
    alias = tmp_path / "state-hardlink"
    try:
        os.link(state, alias)
        valid, reason = env._prepare_safe_state_artifact()
    finally:
        alias.unlink(missing_ok=True)
        env.cleanup()

    assert valid is False
    assert reason == "hardlink"


def test_unexpected_state_owner_is_rejected(tmp_path, monkeypatch):
    env = _new_env(tmp_path, monkeypatch)
    monkeypatch.setattr(
        local,
        "_local_owner_is_current_user",
        lambda path, info=None: False,
    )
    try:
        valid, reason = env._prepare_safe_state_artifact()
    finally:
        env.cleanup()

    assert valid is False
    assert reason == "owner"


def test_reparse_or_symlink_state_artifact_is_rejected(tmp_path, monkeypatch):
    with patch.object(LocalEnvironment, "init_session", autospec=True, return_value=None):
        env = _new_env(tmp_path, monkeypatch)
    state = Path(env._safe_state_path)
    target = tmp_path / "target-state"
    target.write_text("synthetic", encoding="utf-8")
    junction = False
    try:
        try:
            state.symlink_to(target)
        except OSError as symlink_error:
            if sys.platform != "win32":
                pytest.skip(f"symlink unavailable: {symlink_error}")
            target.unlink()
            target.mkdir()
            created = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(state), str(target)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if created.returncode != 0:
                pytest.skip(
                    "symlink and junction unavailable: "
                    f"symlink={symlink_error}; junction_rc={created.returncode}"
                )
            junction = True
        valid, reason = env._prepare_safe_state_artifact()
    finally:
        if junction:
            try:
                os.rmdir(state)
            except OSError:
                pass
            try:
                target.rmdir()
            except OSError:
                pass
        else:
            state.unlink(missing_ok=True)
            if target.is_dir():
                target.rmdir()
            else:
                target.unlink(missing_ok=True)
        env.cleanup()

    assert valid is False
    assert reason == "reparse"


def test_reparse_parent_chain_is_rejected(tmp_path, monkeypatch):
    with patch.object(LocalEnvironment, "init_session", autospec=True, return_value=None):
        env = _new_env(tmp_path, monkeypatch)
    private_cache = Path(env.get_temp_dir())
    alias = tmp_path / "cache-alias"
    state = private_cache / "parent-chain-state.v1"
    junction = False
    try:
        state.write_text("synthetic", encoding="utf-8")
        if sys.platform == "win32":
            local._set_windows_private_acl(state, directory=False)
        else:
            state.chmod(0o600)
        try:
            alias.symlink_to(private_cache, target_is_directory=True)
        except OSError as symlink_error:
            if sys.platform != "win32":
                pytest.skip(f"directory symlink unavailable: {symlink_error}")
            created = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(alias), str(private_cache)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if created.returncode != 0:
                pytest.skip(
                    "directory symlink and junction unavailable: "
                    f"symlink={symlink_error}; junction_rc={created.returncode}"
                )
            junction = True
        env._safe_state_path = str(alias / state.name)

        valid, reason = env._prepare_safe_state_target()
    finally:
        state.unlink(missing_ok=True)
        if junction:
            try:
                os.rmdir(alias)
            except OSError:
                pass
        else:
            alias.unlink(missing_ok=True)
        env.cleanup()

    assert valid is False
    assert reason == "parent_reparse"


@pytest.mark.linux_only
def test_posix_state_modes_are_private_without_changing_user_umask(
    tmp_path, monkeypatch
):
    import stat

    env = _new_env(tmp_path, monkeypatch)
    try:
        user_file = tmp_path / "user-created.txt"
        result = env.execute(f"touch '{user_file}'")
        state_mode = stat.S_IMODE(Path(env._safe_state_path).stat().st_mode)
        directory_mode = stat.S_IMODE(Path(env.get_temp_dir()).stat().st_mode)
        user_mode = stat.S_IMODE(user_file.stat().st_mode)
    finally:
        env.cleanup()

    assert result["returncode"] == 0
    assert state_mode == 0o600
    assert directory_mode == 0o700
    assert user_mode == 0o644


@pytest.mark.windows_only
def test_windows_insecure_preexisting_target_is_rejected_before_bootstrap(
    tmp_path, monkeypatch
):
    import ntsecuritycon
    import win32security

    with patch.object(LocalEnvironment, "init_session", autospec=True, return_value=None):
        env = _new_env(tmp_path, monkeypatch)
    state = Path(env._safe_state_path)
    state.write_text("synthetic", encoding="utf-8")
    everyone = win32security.ConvertStringSidToSid("S-1-1-0")
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAceEx(
        win32security.ACL_REVISION,
        0,
        ntsecuritycon.FILE_ALL_ACCESS,
        everyone,
    )
    win32security.SetNamedSecurityInfo(
        str(state),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )
    calls = []

    def unexpected_bootstrap(*args, **kwargs):
        calls.append((args, kwargs))
        raise RuntimeError("preflight must reject before bootstrap")

    env._run_bash = unexpected_bootstrap

    try:
        env.init_session()
    finally:
        env.cleanup()

    assert calls == []
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "acl"


@pytest.mark.windows_only
def test_windows_runtime_rejects_insecure_state_before_apply(tmp_path, monkeypatch):
    import ntsecuritycon
    import win32security

    env = _new_env(tmp_path, monkeypatch)
    state = Path(env._safe_state_path)
    state.write_bytes(
        encode_safe_state(
            {
                "PATH": "/synthetic-attacker/bin:/usr/bin:/bin",
                "VIRTUAL_ENV": "/synthetic-attacker/.venv",
            },
            platform="msys",
        )
    )
    everyone = win32security.ConvertStringSidToSid("S-1-1-0")
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAceEx(
        win32security.ACL_REVISION,
        0,
        ntsecuritycon.FILE_ALL_ACCESS,
        everyone,
    )
    win32security.SetNamedSecurityInfo(
        str(state),
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION
        | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )

    try:
        result = env.execute(
            "printf '%s|%s' \"${VIRTUAL_ENV-unset}\" \"$PATH\""
        )
    finally:
        env.cleanup()

    assert result["returncode"] == 0
    assert "/synthetic-attacker" not in result["output"]
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "acl"


@pytest.mark.windows_only
def test_windows_state_acl_is_explicit_and_restricted(tmp_path, monkeypatch):
    import win32security

    env = _new_env(tmp_path, monkeypatch)
    try:
        valid, reason = env._prepare_safe_state_artifact()
        security = win32security.GetNamedSecurityInfo(
            env._safe_state_path,
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION,
        )
        dacl = security.GetSecurityDescriptorDacl()
        entries = []
        for index in range(dacl.GetAceCount()):
            header, _mask, sid = dacl.GetAce(index)
            entries.append((header, win32security.ConvertSidToStringSid(sid)))
    finally:
        env.cleanup()

    assert valid is True, reason
    assert {sid for _header, sid in entries} == {
        "S-1-5-18",
        "S-1-5-32-544",
        win32security.ConvertSidToStringSid(
            win32security.GetTokenInformation(
                win32security.OpenProcessToken(
                    __import__("win32api").GetCurrentProcess(),
                    win32security.TOKEN_QUERY,
                ),
                win32security.TokenUser,
            )[0]
        ),
    }
    assert all(not (header[1] & win32security.INHERITED_ACE) for header, _sid in entries)
