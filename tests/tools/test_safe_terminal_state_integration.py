import os
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
    try:
        try:
            state.symlink_to(target)
        except OSError as exc:
            pytest.skip(f"symlink unavailable: {exc}")
        valid, reason = env._prepare_safe_state_artifact()
    finally:
        state.unlink(missing_ok=True)
        target.unlink(missing_ok=True)
        env.cleanup()

    assert valid is False
    assert reason == "reparse"


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
