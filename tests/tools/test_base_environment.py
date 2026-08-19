"""Tests for BaseEnvironment unified execution model.

Tests _wrap_command(), _extract_cwd_from_output(), _embed_stdin_heredoc(),
init_session() failure handling, and the CWD marker contract.
"""

import logging
from unittest.mock import MagicMock

from tools.environments.base import BaseEnvironment, _BoundedOutputCollector


class _TestableEnv(BaseEnvironment):
    """Concrete subclass for testing base class methods."""

    def __init__(self, cwd="/tmp", timeout=10):
        super().__init__(cwd=cwd, timeout=timeout)

    def _run_bash(self, cmd_string, *, login=False, timeout=120, stdin_data=None):
        raise NotImplementedError("Use mock")

    def cleanup(self):
        pass


class TestBoundedOutputCollector:
    def test_large_stream_retains_bounded_head_and_tail(self):
        collector = _BoundedOutputCollector(1_000)
        collector.append("HEAD-SENTINEL\n")
        for _ in range(2_000):
            collector.append("x" * 4_096)
        collector.append("\nTAIL-SENTINEL")

        rendered = collector.render()

        assert collector.total_chars > 8_000_000
        assert collector.buffered_chars <= 1_000
        assert len(rendered) <= 1_000
        assert rendered.startswith("HEAD-SENTINEL")
        assert rendered.endswith("TAIL-SENTINEL")
        assert "[OUTPUT TRUNCATED" in rendered


    def test_required_status_suffix_stays_inside_limit(self):
        collector = _BoundedOutputCollector(120)
        collector.append("A" * 10_000)

        rendered = collector.render(suffix="\n[Command timed out after 1s]")

        assert len(rendered) <= 120
        assert rendered.endswith("[Command timed out after 1s]")
        assert "[OUTPUT TRUNCATED" in rendered


class TestWrapCommand:
    def test_basic_shape(self):
        env = _TestableEnv()
        env._safe_state_ready = True
        wrapped = env._wrap_command("echo hello", "/tmp")

        assert "source " not in wrapped
        assert "export -p" not in wrapped
        assert "cd -- /tmp" in wrapped or "cd -- '/tmp'" in wrapped
        assert "eval 'echo hello'" in wrapped
        assert "__hermes_ec=$?" in wrapped
        assert env._safe_state_path in wrapped
        assert env._cwd_marker in wrapped
        assert "exit $__hermes_ec" in wrapped

    def test_no_safe_state_skips_codec(self):
        env = _TestableEnv()
        env._safe_state_ready = False
        wrapped = env._wrap_command("echo hello", "/tmp")

        assert env._safe_state_path not in wrapped
        assert "_hss_apply" not in wrapped
        assert "_hss_capture" not in wrapped

    def test_single_quote_escaping(self):
        env = _TestableEnv()
        env._safe_state_ready = True
        wrapped = env._wrap_command("echo 'hello world'", "/tmp")

        assert "eval 'echo '\\''hello world'\\'''" in wrapped

    def test_cd_failure_exit_126(self):
        env = _TestableEnv()
        env._safe_state_ready = True
        wrapped = env._wrap_command("ls", "/nonexistent")

        assert "exit 126" in wrapped


class TestAtomicSafeStateWrite:
    def test_wrap_command_uses_atomic_temp_then_mv(self):
        env = _TestableEnv()
        env._safe_state_ready = True

        wrapped = env._wrap_command("echo hi", "/tmp")

        assert "export -p" not in wrapped
        assert "source " not in wrapped
        assert "mktemp " in wrapped
        assert ".tmp.XXXXXXXXXX" in wrapped
        assert "mv -f " in wrapped
        assert env._safe_state_path in wrapped

    def test_temp_path_uses_mktemp_not_pid_variables(self):
        env = _TestableEnv()
        env._safe_state_ready = True

        wrapped = env._wrap_command("echo hi", "/tmp")

        assert "mktemp " in wrapped
        assert ".tmp.XXXXXXXXXX" in wrapped
        assert "$BASHPID" not in wrapped
        assert ".tmp.$$" not in wrapped

    def test_init_session_bootstrap_also_atomic_and_mktemp(self):
        env = _TestableEnv()
        captured = {}

        def fake_run_bash(cmd_string, *, login=False, timeout=120, stdin_data=None):
            captured.setdefault("cmd", cmd_string)
            raise RuntimeError("stop after capture")

        env._run_bash = fake_run_bash  # type: ignore[assignment]
        env.init_session()

        boot = captured.get("cmd", "")
        assert ".tmp.XXXXXXXXXX" in boot
        assert "mktemp " in boot
        assert "mv -f " in boot
        assert "$BASHPID" not in boot
        assert ".tmp.$$" not in boot
        assert "export -p" not in boot
        assert "source " not in boot

    def test_init_session_bootstrap_uses_private_umask(self):
        env = _TestableEnv()
        captured = {}

        def fake_run_bash(cmd_string, *, login=False, timeout=120, stdin_data=None):
            captured.setdefault("cmd", cmd_string)
            raise RuntimeError("stop after capture")

        env._run_bash = fake_run_bash  # type: ignore[assignment]
        env.init_session()

        boot = captured.get("cmd", "")
        assert "umask 077" in boot
        assert "export -p" not in boot


class TestExtractCwdFromOutput:
    def test_happy_path(self):
        env = _TestableEnv()
        marker = env._cwd_marker
        result = {
            "output": f"hello\n{marker}/home/user{marker}\n",
        }
        env._extract_cwd_from_output(result)

        assert env.cwd == "/home/user"
        assert marker not in result["output"]


    def test_output_cleaned(self):
        env = _TestableEnv()
        marker = env._cwd_marker
        result = {
            "output": f"hello\n{marker}/tmp{marker}\n",
        }
        env._extract_cwd_from_output(result)

        assert "hello" in result["output"]
        assert marker not in result["output"]


class TestEmbedStdinHeredoc:
    def test_heredoc_format(self):
        result = BaseEnvironment._embed_stdin_heredoc("cat", "hello world")

        assert result.startswith("cat << '")
        assert "hello world" in result
        assert "HERMES_STDIN_" in result

    def test_unique_delimiter_each_call(self):
        r1 = BaseEnvironment._embed_stdin_heredoc("cat", "data")
        r2 = BaseEnvironment._embed_stdin_heredoc("cat", "data")

        # Extract delimiters
        d1 = r1.split("'")[1]
        d2 = r2.split("'")[1]
        assert d1 != d2  # UUID-based, should be unique


class TestInitSessionFailure:
    def test_safe_state_ready_false_on_failure(self):
        env = _TestableEnv()

        def failing_run_bash(*args, **kwargs):
            raise RuntimeError("bash not found")

        env._run_bash = failing_run_bash
        env.init_session()

        assert env._safe_state_ready is False
        assert env._safe_state_disabled_reason == "init_failed"

    def test_prefer_nonlogin_when_login_bash_is_dead(self):
        """Safe-state init failure keeps the working non-login Bash fallback."""
        env = _TestableEnv()

        def mock_run_bash(cmd, *, login=False, timeout=120, stdin_data=None):
            mock = MagicMock()
            mock.poll.return_value = 0
            mock.stdout = iter([])
            if login:
                mock.returncode = 1
            else:
                mock.returncode = 0
            return mock

        env._run_bash = mock_run_bash
        env.init_session()

        assert env._safe_state_ready is False
        assert env._safe_state_disabled_reason == "init_failed"
        assert env._prefer_nonlogin is True

        calls = []

        def track_run_bash(cmd, *, login=False, timeout=120, stdin_data=None):
            calls.append({"login": login})
            mock = MagicMock()
            mock.poll.return_value = 0
            mock.returncode = 0
            mock.stdout = iter([])
            return mock

        env._run_bash = track_run_bash
        env.execute("echo test")

        assert calls[0]["login"] is False


class TestCwdMarker:
    def test_marker_contains_session_id(self):
        env = _TestableEnv()
        assert env._session_id in env._cwd_marker

    def test_unique_per_instance(self):
        env1 = _TestableEnv()
        env2 = _TestableEnv()
        assert env1._cwd_marker != env2._cwd_marker


class TestSafeTerminalStateContract:
    def test_constructor_uses_versioned_non_executable_state_path(self):
        env = _TestableEnv()

        assert "hermes-safe-state-" in env._safe_state_path
        assert env._safe_state_path.endswith(".v1")
        assert env._safe_state_ready is False
        assert env._safe_state_disabled_reason is None
        assert not hasattr(env, "_snapshot_path")
        assert not hasattr(env, "_snapshot_ready")

    def test_wrap_command_never_sources_or_dumps_environment(self):
        env = _TestableEnv()
        env._safe_state_ready = True

        wrapped = env._wrap_command("echo hello", "/tmp")

        for forbidden in ("source ", "export -p", "declare -x"):
            assert forbidden not in wrapped
        assert "eval 'echo hello'" in wrapped
        assert f"eval '{env._safe_state_path}'" not in wrapped
        assert env._cwd_marker in wrapped
        assert env._safe_state_path in wrapped

    def test_init_session_never_builds_full_environment_dump(self):
        env = _TestableEnv()
        captured = []

        def capture_and_fail(cmd, **kwargs):
            captured.append(cmd)
            raise RuntimeError("stop after capture")

        env._run_bash = capture_and_fail  # type: ignore[assignment]
        env.init_session()

        assert captured
        for forbidden in ("source ", "eval ", "export -p", "declare -x"):
            assert forbidden not in captured[0]
        assert env._safe_state_path in captured[0]

    def test_multiplex_mode_disables_state_before_bootstrap(self, monkeypatch):
        from agent import secret_scope

        env = _TestableEnv()
        calls = []
        monkeypatch.setattr(secret_scope, "is_multiplex_active", lambda: True)

        def unexpected_run(*args, **kwargs):
            calls.append((args, kwargs))
            raise RuntimeError("must not run")

        env._run_bash = unexpected_run  # type: ignore[assignment]
        env.init_session()

        assert calls == []
        assert env._safe_state_ready is False
        assert env._safe_state_disabled_reason == "multiplex_mode"

    def test_disable_safe_state_warns_once_without_values(self, caplog):
        env = _TestableEnv()
        caplog.set_level(logging.WARNING)

        env._disable_safe_state("codec_unavailable")
        env._disable_safe_state("codec_unavailable")

        matching = [
            record for record in caplog.records
            if "codec_unavailable" in record.getMessage()
        ]
        assert len(matching) == 1
        assert "synthetic-secret-value" not in caplog.text

    def test_state_failure_marker_disables_and_is_removed_from_output(self, caplog):
        env = _TestableEnv()
        env._safe_state_ready = True
        caplog.set_level(logging.WARNING)
        marker = env._safe_state_marker
        result = {
            "output": f"before\n{marker}apply_invalid{marker}\nafter\n",
        }

        env._extract_safe_state_status(result)

        assert env._safe_state_ready is False
        assert env._safe_state_disabled_reason == "apply_invalid"
        assert marker not in result["output"]
        assert "before" in result["output"]
        assert "after" in result["output"]

    def test_legacy_snapshot_file_is_never_referenced(self):
        env = _TestableEnv()
        env._safe_state_ready = True

        wrapped = env._wrap_command("true", "/tmp")

        assert "hermes-snap-" not in wrapped
        assert ".sh" not in env._safe_state_path
