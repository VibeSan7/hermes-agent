"""Session-scoped gateway variables must never enter safe terminal state."""

import sys

import pytest

from tools.environments.safe_terminal_state import (
    SAFE_STATE_NAMES,
    SafeStateError,
    decode_safe_state,
    encode_safe_state,
)


def test_every_bridged_session_variable_is_outside_safe_allowlist():
    from gateway.session_context import _VAR_MAP

    assert set(_VAR_MAP).isdisjoint(SAFE_STATE_NAMES)


@pytest.mark.parametrize("name", [
    "HERMES_SESSION_ID",
    "HERMES_SESSION_KEY",
    "HERMES_SESSION_CHAT_NAME",
    "HERMES_SESSION_USER_NAME",
    "HERMES_UI_SESSION_ID",
    "HERMES_CRON_AUTO_DELIVER_TARGET",
])
def test_session_variable_cannot_be_encoded(name):
    with pytest.raises(SafeStateError, match="unknown_name"):
        encode_safe_state(
            {"PATH": "/usr/bin:/bin", name: "synthetic-session-value"},
            platform="posix",
        )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX Local integration lane")
def test_shared_environment_does_not_persist_another_sessions_id(tmp_path):
    import threading

    from gateway.session_context import _UNSET, _VAR_MAP, set_session_vars
    from tools.environments.local import LocalEnvironment

    env = LocalEnvironment(cwd=str(tmp_path), timeout=30)
    env.init_session()
    try:
        def run_as(session_id):
            output = {}

            def worker():
                for variable in _VAR_MAP.values():
                    variable.set(_UNSET)
                set_session_vars(
                    session_key="k" + session_id,
                    session_id=session_id,
                    source="desktop",
                )
                output["result"] = env.execute('echo "[$HERMES_SESSION_ID]"')

            thread = threading.Thread(target=worker)
            thread.start()
            thread.join(10)
            assert not thread.is_alive()
            return output["result"].get("output", "")

        output_a = run_as("SIDAAA")
        output_b = run_as("SIDBBB")

        assert "SIDAAA" in output_a
        assert "SIDBBB" in output_b
        assert "SIDAAA" not in output_b

        payload = open(env._safe_state_path, "rb").read()
        state = decode_safe_state(payload, platform="posix")
        assert set(dict(state.records)) == set(SAFE_STATE_NAMES)
        assert b"HERMES_SESSION" not in payload
        assert b"SIDAAA" not in payload
        assert b"SIDBBB" not in payload
    finally:
        env.cleanup()
