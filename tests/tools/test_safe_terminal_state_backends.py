import pytest

from tools.environments.base import BaseEnvironment
from tools.environments.daytona import DaytonaEnvironment
from tools.environments.modal import ModalEnvironment
from tools.environments.singularity import SingularityEnvironment
from tools.environments.ssh import SSHEnvironment
from tools.environments.vercel_sandbox import VercelSandboxEnvironment


UNSUPPORTED_BACKENDS = (
    SSHEnvironment,
    SingularityEnvironment,
    ModalEnvironment,
    DaytonaEnvironment,
    VercelSandboxEnvironment,
)


class UnclassifiedEnvironment(BaseEnvironment):
    def _run_bash(self, cmd_string, *, login=False, timeout=120, stdin_data=None):
        raise AssertionError("unclassified backend must not initialize state")

    def cleanup(self):
        pass


def test_unclassified_backend_defaults_to_persistence_off():
    env = UnclassifiedEnvironment(cwd="/tmp", timeout=10)

    env.init_session()

    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "unsupported_backend"


@pytest.mark.parametrize("backend_class", UNSUPPORTED_BACKENDS)
def test_unsupported_backend_disables_state_and_still_executes(backend_class):
    env = backend_class.__new__(backend_class)
    BaseEnvironment.__init__(env, cwd="/tmp", timeout=10)

    init_calls = []

    def fail_if_initialized(*args, **kwargs):
        init_calls.append((args, kwargs))
        raise RuntimeError("safe-state backend must remain off")

    env._run_bash = fail_if_initialized
    env.init_session()

    assert init_calls == []
    assert env._safe_state_ready is False
    assert env._safe_state_disabled_reason == "unsupported_backend"

    command_calls = []
    env._before_execute = lambda: None
    env._run_bash = lambda command, **kwargs: command_calls.append(
        (command, kwargs)
    ) or object()
    env._wait_for_process = lambda *args, **kwargs: {
        "output": "command-ok",
        "returncode": 0,
    }

    result = env.execute("printf command-ok")

    assert result == {"output": "command-ok", "returncode": 0}
    assert len(command_calls) == 1
    wrapped, kwargs = command_calls[0]
    assert kwargs["login"] is True
    for forbidden in (
        "source ",
        "export -p",
        "declare -x",
        "hermes-snap-",
        env._safe_state_path,
    ):
        assert forbidden not in wrapped
