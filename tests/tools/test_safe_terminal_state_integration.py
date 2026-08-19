import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from tools.environments import local
from tools.environments.local import LocalEnvironment
from tools.environments.safe_terminal_state import decode_safe_state


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
        result = env.execute("printf command-failed; false")
    finally:
        env.cleanup()

    assert result["returncode"] == 1
    assert result["output"].strip() == "command-failed"
    assert env._safe_state_ready is True


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
    for index, name in enumerate(SYNTHETIC_CREDENTIAL_NAMES):
        assert name.encode() not in payload
        assert f"synthetic-{index}".encode() not in payload
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


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode contract")
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


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACL contract")
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


@pytest.mark.skipif(sys.platform != "win32", reason="Windows ACL contract")
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
