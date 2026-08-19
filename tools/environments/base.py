"""Base class for all Hermes execution environment backends.

Unified spawn-per-call model: every command spawns a fresh ``bash -c`` process.
Default-deny safe terminal state preserves only validated Python/Conda runtime
markers in single-profile mode. CWD persists through an in-band stdout marker.
"""

import codecs
import json
import logging
import os
import re
import select
import shlex
import subprocess
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections import deque
from pathlib import Path
from typing import IO, Callable, Protocol

from hermes_constants import get_hermes_home
from hermes_cli._subprocess_compat import windows_hide_flags
from tools.environments.safe_terminal_state import (
    SafeStatePlatform,
    SafeStateShellScripts,
    build_safe_state_shell_scripts,
)
from tools.interrupt import is_interrupted

logger = logging.getLogger(__name__)

# Opt-in debug tracing for the interrupt/activity/poll machinery.  Set
# HERMES_DEBUG_INTERRUPT=1 to log loop entry/exit, periodic heartbeats, and
# every is_interrupted() state change from _wait_for_process.  Off by default
# to avoid flooding production gateway logs.
_DEBUG_INTERRUPT = bool(os.getenv("HERMES_DEBUG_INTERRUPT"))

if _DEBUG_INTERRUPT:
    # AIAgent's quiet_mode path (run_agent.py) forces the `tools` logger to
    # ERROR on CLI startup, which would silently swallow every trace we emit.
    # Force this module's own logger back to INFO so the trace is visible in
    # agent.log regardless of quiet-mode.  Scoped to the opt-in case only.
    logger.setLevel(logging.INFO)

# Thread-local activity callback.  The agent sets this before a tool call so
# long-running _wait_for_process loops can report liveness to the gateway.
_activity_callback_local = threading.local()


# Sentinel capacity for full-fidelity capture (internal consumers). Large
# enough that the collector never evicts in practice, keeping a single code
# path for both bounded and unbounded modes.
_UNBOUNDED_CAPTURE_CHARS = 2**63 - 1


class EnvironmentConnectionError(RuntimeError):
    """Infrastructure/connection-class failure of a terminal backend.

    Raised when the backend itself is unreachable (SSH host down, Docker
    daemon not running, remote file sync failing on a dead link) — never
    for a command that merely exited nonzero.  Subclassing RuntimeError
    keeps every existing ``except RuntimeError`` catcher working.

    ``terminal_tool`` turns this into a structured ``status: "degraded"``
    tool result (config gate ``terminal.degraded_mode: warn|fail``) so the
    model gets an actionable reason + retry hint instead of a traceback.
    The failed backend is never cached, so a later call retries from
    scratch and simply works once the backend is reachable again.
    """

    def __init__(self, reason: str, *, retry_hint: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.retry_hint = retry_hint or (
            "This is an infrastructure failure, not a command failure. "
            "Verify the backend is reachable (network, service running, "
            "credentials), then retry the same command — recovery is "
            "automatic once the backend is back."
        )


class _BoundedOutputCollector:
    """Retain a bounded 40/60 head-tail window of streamed text.

    When ``spill_path`` is set, the collector also tees the FULL stream to
    that file once eviction begins (up to ``_SPILL_CAP_CHARS``), so a
    truncated foreground result is recoverable without re-running the
    command. Memory stays bounded either way — the spill is disk-only.
    """

    # Hard ceiling on spill file size. Beyond this the file stops growing
    # (marker appended); protects disk from pathological runaway output.
    _SPILL_CAP_CHARS = 5_000_000

    def __init__(self, max_chars: int, spill_path: "Path | None" = None):
        self.max_chars = max(1, int(max_chars))
        self._head_limit = int(self.max_chars * 0.4)
        self._tail_limit = self.max_chars - self._head_limit
        self._head: list[str] = []
        self._tail: deque[str] = deque()
        self._head_chars = 0
        self._tail_chars = 0
        self._total_chars = 0
        self._lock = threading.Lock()
        self._spill_path = spill_path
        self._spill_fh: IO[str] | None = None
        self._spill_chars = 0
        self._spill_capped = False

    def _maybe_spill(self, text: str) -> None:
        """Tee ``text`` to the spill file (opened lazily on first overflow)."""
        if self._spill_path is None or self._spill_capped:
            return
        try:
            if self._spill_fh is None:
                from tools.spill_safety import ensure_spill_dir, open_exclusive

                # Raw pre-redaction output: private perms + symlink-refusing
                # exclusive create (a planted link must fail the spill, never
                # redirect the write).
                ensure_spill_dir(self._spill_path.parent, private=True)
                self._spill_fh = open_exclusive(
                    self._spill_path, private=True, errors="replace"
                )
                # Backfill everything retained so far so the file holds the
                # stream from byte 0, not just from the overflow point.
                backlog = "".join(self._head) + "".join(self._tail)
                self._spill_fh.write(backlog)
                self._spill_chars = len(backlog)
            budget = self._SPILL_CAP_CHARS - self._spill_chars
            if budget <= 0 or len(text) > budget:
                self._spill_fh.write(text[:max(0, budget)])
                self._spill_fh.write("\n... [spill capped at 5,000,000 chars] ...\n")
                self._spill_capped = True
            else:
                self._spill_fh.write(text)
            self._spill_chars += len(text)
        except OSError:
            # Disk trouble must never break command execution.
            self._spill_capped = True

    def close_spill(self) -> "str | None":
        """Close the spill file and return its path if it was used."""
        with self._lock:
            if self._spill_fh is None:
                return None
            try:
                self._spill_fh.close()
            except OSError:
                pass
            self._spill_fh = None
            return str(self._spill_path)

    @property
    def buffered_chars(self) -> int:
        with self._lock:
            return self._head_chars + self._tail_chars

    @property
    def total_chars(self) -> int:
        with self._lock:
            return self._total_chars

    def append(self, text: str) -> None:
        if not text:
            return
        with self._lock:
            text_len = len(text)
            # Spill tee: activates at the first overflow (backfilling what's
            # retained so far), then mirrors every subsequent chunk.
            if self._spill_path is not None and (
                self._spill_fh is not None
                or self._total_chars + text_len > self.max_chars
            ):
                self._maybe_spill(text)
            self._total_chars += text_len
            start = 0

            if self._head_chars < self._head_limit:
                take = min(self._head_limit - self._head_chars, text_len)
                if take:
                    self._head.append(text[:take])
                    self._head_chars += take
                    start = take

            remaining = text_len - start
            if remaining <= 0 or self._tail_limit <= 0:
                return
            if remaining >= self._tail_limit:
                self._tail.clear()
                self._tail.append(text[-self._tail_limit :])
                self._tail_chars = self._tail_limit
                return

            chunk = text[start:]
            self._tail.append(chunk)
            self._tail_chars += len(chunk)
            while self._tail_chars > self._tail_limit:
                excess = self._tail_chars - self._tail_limit
                first = self._tail[0]
                if len(first) <= excess:
                    self._tail.popleft()
                    self._tail_chars -= len(first)
                else:
                    self._tail[0] = first[excess:]
                    self._tail_chars -= excess

    def render(self, *, suffix: str = "") -> str:
        """Render within ``max_chars``, preserving a required status suffix."""
        with self._lock:
            if len(suffix) >= self.max_chars:
                return suffix[-self.max_chars :]

            head = "".join(self._head)
            tail = "".join(self._tail)
            available = self.max_chars - len(suffix)
            if self._total_chars <= available:
                return head + tail + suffix

            notice = ""
            for _ in range(4):
                content_budget = max(0, available - len(notice))
                head_chars = int(content_budget * 0.4)
                tail_chars = content_budget - head_chars
                omitted = max(0, self._total_chars - head_chars - tail_chars)
                updated = (
                    f"\n\n... [OUTPUT TRUNCATED - {omitted:,} chars omitted "
                    f"out of {self._total_chars:,} total] ...\n\n"
                )
                if updated == notice:
                    break
                notice = updated

            content_budget = max(0, available - len(notice))
            head_chars = int(content_budget * 0.4)
            tail_chars = content_budget - head_chars
            rendered_tail = tail[-tail_chars:] if tail_chars else ""
            return head[:head_chars] + notice[:available] + rendered_tail + suffix


def set_activity_callback(cb: Callable[[str], None] | None) -> None:
    """Register a callback that _wait_for_process fires periodically."""
    _activity_callback_local.callback = cb


def get_activity_callback() -> Callable[[str], None] | None:
    """Return the thread-local activity callback (see ``set_activity_callback``).

    Public accessor for callers outside this module that need to capture the
    calling thread's callback before handing work to another thread (the
    callback is thread-local, so a freshly spawned thread cannot read it
    back) — e.g. the manual cron-run heartbeat (#76502).
    """
    return getattr(_activity_callback_local, "callback", None)


def touch_activity_if_due(
    state: dict,
    label: str,
) -> None:
    """Fire the activity callback at most once every ``state['interval']`` seconds.

    *state* must contain ``last_touch`` (monotonic timestamp) and ``start``
    (monotonic timestamp of the operation start).  An optional ``interval``
    key overrides the default 10 s cadence.

    Swallows all exceptions so callers don't need their own try/except.
    """
    now = time.monotonic()
    interval = state.get("interval", 10.0)
    if now - state["last_touch"] < interval:
        return
    state["last_touch"] = now
    try:
        cb = get_activity_callback()
        if cb:
            elapsed = int(now - state["start"])
            cb(f"{label} ({elapsed}s elapsed)")
    except Exception:
        pass


def get_sandbox_dir() -> Path:
    """Return the host-side root for all sandbox storage (Docker workspaces,
    Singularity overlays/SIF cache, etc.).

    Configurable via TERMINAL_SANDBOX_DIR. Defaults to {HERMES_HOME}/sandboxes/.
    """
    custom = os.getenv("TERMINAL_SANDBOX_DIR")
    if custom:
        p = Path(custom)
    else:
        p = get_hermes_home() / "sandboxes"
    p.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# Shared constants and utilities
# ---------------------------------------------------------------------------


def _pipe_stdin(proc: subprocess.Popen, data: str) -> None:
    """Write *data* to proc.stdin on a daemon thread to avoid pipe-buffer deadlocks.

    On Windows, text-mode stdin (``text=True`` / ``encoding="utf-8"``)
    translates ``\\n`` → ``\\r\\n`` as the data flows through the pipe —
    which corrupts every write_file / patch call because the bytes that
    land on disk include injected carriage returns.  The file IS created,
    but every subsequent byte-count / content compare against the
    caller's ``\\n``-only string fails.

    Workaround: write through ``proc.stdin.buffer`` (the underlying byte
    buffer), encoding to UTF-8 ourselves.  That bypasses Python's
    newline translation entirely on every platform.  No behaviour change
    on POSIX — the byte sequence is identical to what text-mode would
    produce there.

    Encoding uses ``errors="surrogateescape"`` — the exact inverse of the
    surrogateescape decode, so original bytes are restored.  For
    surrogate-free strings it is byte-identical to strict UTF-8.
    Surrogates outside the round-trip range U+DC80–U+DCFF raise and are
    recorded on ``proc._hermes_stdin_errors`` while stdin is still closed
    in ``finally`` so the child sees EOF instead of hanging;
    ``_wait_for_process`` reads the recorded error and surfaces it as
    ``stdin_error`` on the result.
    """

    errors: list[BaseException] = []
    proc._hermes_stdin_errors = errors

    def _write():
        if proc.stdin is None:
            errors.append(RuntimeError("process stdin unavailable"))
            return
        # Resolve the target BEFORE encoding: a failed encode must still
        # reach the finally-close, or the child hangs on EOF forever.
        target = getattr(proc.stdin, "buffer", proc.stdin)
        try:
            raw = data.encode("utf-8", "surrogateescape") if isinstance(data, str) else data
            written = target.write(raw)
            if written != len(raw):
                # Buffered writers normally complete or raise; a short write
                # is a real failure and must be surfaced, not swallowed.
                raise RuntimeError(f"short stdin write: {written} of {len(raw)} bytes")
        except (BrokenPipeError, OSError):
            pass  # child closed stdin early — normal
        except Exception as exc:
            # Only reachable with surrogates outside the surrogateescape
            # round-trip range (e.g. a literal U+D800). Record it so
            # _wait_for_process can surface it instead of a silent false
            # success.
            errors.append(exc)
        finally:
            try:
                target.close()
            except Exception:
                pass

    thread = threading.Thread(target=_write, daemon=True)
    proc._hermes_stdin_thread = thread
    thread.start()


def _popen_bash(
    cmd: list[str], stdin_data: str | None = None, **kwargs
) -> subprocess.Popen:
    """Spawn a subprocess with standard stdout/stderr/stdin setup.

    If *stdin_data* is provided, writes it asynchronously via :func:`_pipe_stdin`.
    Backends with special Popen needs (e.g. local's ``preexec_fn``) can bypass
    this and call :func:`_pipe_stdin` directly.
    """
    kwargs.setdefault("creationflags", windows_hide_flags())
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
        text=True, encoding="utf-8", errors="replace",
        **kwargs,
    )
    if stdin_data is not None:
        _pipe_stdin(proc, stdin_data)
    return proc


def _load_json_store(path: Path) -> dict:
    """Load a JSON file as a dict, returning ``{}`` on any error."""
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_json_store(path: Path, data: dict) -> None:
    """Write *data* as pretty-printed JSON to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _file_mtime_key(host_path: str) -> tuple[float, int] | None:
    """Return ``(mtime, size)`` for cache comparison, or ``None`` if unreadable."""
    try:
        st = Path(host_path).stat()
        return (st.st_mtime, st.st_size)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# ProcessHandle protocol
# ---------------------------------------------------------------------------


class ProcessHandle(Protocol):
    """Duck type that every backend's _run_bash() must return.

    subprocess.Popen satisfies this natively.  SDK backends (Modal, Daytona)
    return _ThreadedProcessHandle which adapts their blocking calls.
    """

    def poll(self) -> int | None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float | None = None) -> int: ...

    @property
    def stdout(self) -> IO[str] | None: ...

    @property
    def returncode(self) -> int | None: ...


class _ThreadedProcessHandle:
    """Adapter for SDK backends (Modal, Daytona) that have no real subprocess.

    Wraps a blocking ``exec_fn() -> (output_str, exit_code)`` in a background
    thread and exposes a ProcessHandle-compatible interface.  An optional
    ``cancel_fn`` is invoked on ``kill()`` for backend-specific cancellation
    (e.g. Modal sandbox.terminate, Daytona sandbox.stop).
    """

    def __init__(
        self,
        exec_fn: Callable[[], tuple[str, int]],
        cancel_fn: Callable[[], None] | None = None,
    ):
        self._cancel_fn = cancel_fn
        self._done = threading.Event()
        self._returncode: int | None = None
        self._error: Exception | None = None

        # Pipe for stdout — drain thread in _wait_for_process reads the read end.
        read_fd, write_fd = os.pipe()
        self._stdout = os.fdopen(read_fd, "r", encoding="utf-8", errors="replace")
        self._write_fd = write_fd

        def _worker():
            try:
                output, exit_code = exec_fn()
                self._returncode = exit_code
                # Write output into the pipe so drain thread picks it up.
                try:
                    os.write(self._write_fd, output.encode("utf-8", errors="replace"))
                except OSError:
                    pass
            except Exception as exc:
                self._error = exc
                self._returncode = 1
            finally:
                try:
                    os.close(self._write_fd)
                except OSError:
                    pass
                self._done.set()

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    @property
    def stdout(self):
        return self._stdout

    @property
    def returncode(self) -> int | None:
        return self._returncode

    def poll(self) -> int | None:
        return self._returncode if self._done.is_set() else None

    def kill(self):
        if self._cancel_fn:
            try:
                self._cancel_fn()
            except Exception:
                pass

    def wait(self, timeout: float | None = None) -> int:
        self._done.wait(timeout=timeout)
        return self._returncode


# ---------------------------------------------------------------------------
# CWD marker for remote backends
# ---------------------------------------------------------------------------


def _cwd_marker(session_id: str) -> str:
    return f"__HERMES_CWD_{session_id}__"


def _safe_state_marker(session_id: str) -> str:
    return f"__HERMES_SAFE_STATE_{session_id}__"


# ---------------------------------------------------------------------------
# BaseEnvironment
# ---------------------------------------------------------------------------


class BaseEnvironment(ABC):
    """Common interface and unified execution flow for all Hermes backends.

    Subclasses implement ``_run_bash()`` and ``cleanup()``.  The base class
    provides ``execute()`` with safe state persistence, CWD tracking,
    interrupt handling, and timeout enforcement.
    """

    # Backends choose pipe, heredoc, or inline process-substitution stdin.
    _stdin_mode: str = "pipe"

    # Safe-state initialization timeout (override for slow cold-starts).
    _safe_state_timeout: int = 30

    def get_temp_dir(self) -> str:
        """Return the backend temp directory used for session artifacts.

        Most sandboxed backends use ``/tmp`` inside the target environment.
        LocalEnvironment overrides this on platforms like Termux where ``/tmp``
        may be missing and ``TMPDIR`` is the portable writable location.
        """
        return "/tmp"

    def __init__(self, cwd: str, timeout: int, env: dict = None):
        self.cwd = cwd
        self.timeout = timeout
        self.env = env or {}

        self._session_id = uuid.uuid4().hex[:12]
        temp_dir = self.get_temp_dir().rstrip("/") or "/"
        self._safe_state_path = (
            f"{temp_dir}/hermes-safe-state-{self._session_id}.v1"
        )
        self._cwd_file = f"{temp_dir}/hermes-cwd-{self._session_id}.txt"
        self._cwd_marker = _cwd_marker(self._session_id)
        self._safe_state_marker = _safe_state_marker(self._session_id)
        self._safe_state_ready = False
        self._safe_state_disabled_reason: str | None = None
        self._safe_state_warning_emitted = False
        self._safe_state_platform: SafeStatePlatform = "posix"
        # When True, login bash is unusable (e.g. broken Git-for-Windows
        # ``Directory \\drivers\\etc`` startup) so execute() must not fall
        # back to ``bash -l`` per command — use non-login ``bash -c`` instead.
        self._prefer_nonlogin = False

    # ------------------------------------------------------------------
    # Abstract methods
    # ------------------------------------------------------------------

    def _run_bash(
        self,
        cmd_string: str,
        *,
        login: bool = False,
        timeout: int = 120,
        stdin_data: str | None = None,
    ) -> ProcessHandle:
        """Spawn a bash process to run *cmd_string*.

        Returns a ProcessHandle (subprocess.Popen or _ThreadedProcessHandle).
        Must be overridden by every backend.
        """
        raise NotImplementedError(f"{type(self).__name__} must implement _run_bash()")

    @abstractmethod
    def cleanup(self):
        """Release backend resources (container, instance, connection)."""
        ...

    # ------------------------------------------------------------------
    # Safe terminal state
    # ------------------------------------------------------------------

    def _safe_state_shell_path(self, path: str) -> str:
        """Return *path* in the target Bash namespace without quoting it."""
        return path

    def _safe_state_scripts(self) -> SafeStateShellScripts:
        state_path = self._safe_state_shell_path(self._safe_state_path)
        temp_template = self._safe_state_shell_path(
            self._safe_state_path + ".tmp.XXXXXXXXXX"
        )
        return build_safe_state_shell_scripts(
            state_path,
            temp_template,
            platform=self._safe_state_platform,
        )

    def _prepare_safe_state_artifact(self) -> tuple[bool, str]:
        """Validate backend-specific file identity before state use."""
        return True, ""

    def _disable_safe_state(self, reason_code: str) -> None:
        self._safe_state_ready = False
        if self._safe_state_disabled_reason is None:
            self._safe_state_disabled_reason = reason_code
        if self._safe_state_warning_emitted:
            return
        self._safe_state_warning_emitted = True
        logger.warning(
            "Safe terminal state disabled (session=%s, backend=%s, reason=%s, path=%s)",
            self._session_id,
            type(self).__name__,
            self._safe_state_disabled_reason,
            self._safe_state_path,
        )

    def init_session(self):
        """Capture validated safe runtime state from a login shell."""
        try:
            from agent.secret_scope import is_multiplex_active
        except Exception:
            self._disable_safe_state("scope_unavailable")
            return
        if is_multiplex_active():
            self._disable_safe_state("multiplex_mode")
            return

        try:
            scripts = self._safe_state_scripts()
        except Exception:
            self._disable_safe_state("script_build_failed")
            return

        quoted_cwd = self._quote_cwd_for_cd(self.cwd)
        bootstrap = "\n".join(
            (
                scripts.probe,
                "_hss_init_rc=$?",
                '[ "$_hss_init_rc" -eq 0 ] || exit "$_hss_init_rc"',
                scripts.capture,
                "_hss_init_rc=$?",
                'if [ "$_hss_init_rc" -ne 0 ]; then',
                "_hss_capture",
                "_hss_init_rc=$?",
                "fi",
                '[ "$_hss_init_rc" -eq 0 ] || exit "$_hss_init_rc"',
                f"builtin cd -- {quoted_cwd} 2>/dev/null || true",
                f"printf '\\n{self._cwd_marker}%s{self._cwd_marker}\\n' \"$(pwd -P)\"",
            )
        )
        try:
            proc = self._run_bash(
                bootstrap,
                login=True,
                timeout=self._safe_state_timeout,
            )
            result = self._wait_for_process(
                proc,
                timeout=self._safe_state_timeout,
            )
            returncode = int(result.get("returncode") or 0)
            if returncode != 0:
                raise RuntimeError(
                    f"safe state bootstrap failed with exit code {returncode}"
                )
            valid, reason = self._prepare_safe_state_artifact()
            if not valid:
                self._disable_safe_state(reason)
                return
            self._safe_state_ready = True
            self._safe_state_disabled_reason = None
            self._safe_state_warning_emitted = False
            self._update_cwd(result)
            logger.info(
                "Safe terminal state created (session=%s, cwd=%s)",
                self._session_id,
                self.cwd,
            )
        except Exception as exc:
            self._disable_safe_state("init_failed")
            detail = str(exc)
            prefer_nonlogin = False
            try:
                probe = self._run_bash(
                    "true",
                    login=False,
                    timeout=min(15, self._safe_state_timeout),
                )
                probe_result = self._wait_for_process(
                    probe,
                    timeout=min(15, self._safe_state_timeout),
                )
                prefer_nonlogin = int(probe_result.get("returncode") or 0) == 0
                if not prefer_nonlogin:
                    detail = (probe_result.get("stdout") or detail).strip() or detail
            except Exception as probe_exc:
                detail = f"{detail}; non-login probe: {probe_exc}"

            self._prefer_nonlogin = prefer_nonlogin
            if prefer_nonlogin:
                logger.warning(
                    "Safe state init failed (session=%s): %s — "
                    "login Bash unusable; falling back to non-login Bash",
                    self._session_id,
                    exc,
                )
            else:
                logger.warning(
                    "Safe state init failed (session=%s): %s — "
                    "falling back to login Bash per command",
                    self._session_id,
                    detail,
                )

    # ------------------------------------------------------------------
    # Command wrapping
    # ------------------------------------------------------------------

    @staticmethod
    def _quote_cwd_for_cd(cwd: str) -> str:
        """Quote a ``cd`` target while preserving ``~`` expansion."""
        if cwd == "~":
            return cwd
        if cwd == "~/":
            return "$HOME"
        if cwd.startswith("~/"):
            return f"$HOME/{shlex.quote(cwd[2:])}"
        return shlex.quote(cwd)

    def _wrap_command(self, command: str, cwd: str) -> str:
        """Build a Bash wrapper with default-deny safe state and CWD markers."""
        escaped = command.replace("'", "'\\''")
        parts: list[str] = []
        scripts: SafeStateShellScripts | None = None
        if self._safe_state_ready:
            valid, reason = self._prepare_safe_state_artifact()
            if not valid:
                self._disable_safe_state(reason)
        if self._safe_state_ready:
            try:
                scripts = self._safe_state_scripts()
            except Exception:
                self._disable_safe_state("script_build_failed")

        if scripts is not None and self._safe_state_ready:
            parts.extend(
                (
                    scripts.probe,
                    "_hss_rc=$?",
                    "_hss_state_ok=1",
                    'if [ "$_hss_rc" -ne 0 ]; then',
                    f"printf '\\n{self._safe_state_marker}probe_%s"
                    f"{self._safe_state_marker}\\n' \"$_hss_rc\"",
                    "_hss_state_ok=0",
                    "else",
                    scripts.apply,
                    "_hss_rc=$?",
                    'if [ "$_hss_rc" -ne 0 ]; then',
                    f"printf '\\n{self._safe_state_marker}apply_%s"
                    f"{self._safe_state_marker}\\n' \"$_hss_rc\"",
                    "_hss_state_ok=0",
                    "fi",
                    "fi",
                )
            )

        parts.append(
            'export AI_AGENT="${AI_AGENT:-hermes-agent}" '
            'HERMES_AGENT="${HERMES_AGENT:-true}"'
        )
        quoted_cwd = self._quote_cwd_for_cd(cwd)
        parts.append(f"builtin cd -- {quoted_cwd} || exit 126")
        parts.append(f"eval '{escaped}'")
        parts.append("__hermes_ec=$?")

        if scripts is not None and self._safe_state_ready:
            parts.extend(
                (
                    'if [ "$_hss_state_ok" -eq 1 ]; then',
                    scripts.capture,
                    "_hss_rc=$?",
                    'if [ "$_hss_rc" -ne 0 ]; then',
                    "_hss_capture",
                    "_hss_rc=$?",
                    "fi",
                    'if [ "$_hss_rc" -ne 0 ]; then',
                    f"printf '\\n{self._safe_state_marker}capture_%s"
                    f"{self._safe_state_marker}\\n' \"$_hss_rc\"",
                    "fi",
                    "fi",
                )
            )

        parts.append(
            f"printf '\\n{self._cwd_marker}%s{self._cwd_marker}\\n' \"$(pwd -P)\""
        )
        parts.append("exit $__hermes_ec")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Stdin heredoc embedding (for SDK backends)
    # ------------------------------------------------------------------

    @staticmethod
    def _embed_stdin_heredoc(command: str, stdin_data: str) -> str:
        """Append stdin_data as a shell heredoc to the command string."""
        delimiter = f"HERMES_STDIN_{uuid.uuid4().hex[:12]}"
        return f"{command} << '{delimiter}'\n{stdin_data}\n{delimiter}"

    @staticmethod
    def _embed_stdin_inline(command: str, stdin_data: str) -> str:
        """Feed exact text through an anonymous Bash process substitution."""
        if "\x00" in stdin_data:
            raise ValueError("NUL is not supported by inline terminal stdin")
        return (
            f"{{ {command}; }} < <(printf '%s' {shlex.quote(stdin_data)})"
        )

    # ------------------------------------------------------------------
    # Process lifecycle
    # ------------------------------------------------------------------

    def _wait_for_process(
        self, proc: ProcessHandle, timeout: int = 120, *, bounded_capture: bool = False
    ) -> dict:
        """Poll-based wait with interrupt checking and stdout draining.

        Shared across all backends — not overridden.

        ``bounded_capture=True`` (foreground terminal-tool path only) retains
        at most ``tool_output.max_bytes`` of output in a head/tail window
        while draining, so a verbose subprocess cannot OOM the process
        (#64435). The default (False) preserves full-fidelity capture for
        internal consumers — file-operation ``cat`` reads feeding the patch
        engine, code-execution RPC reads, log reads — where truncation would
        corrupt data.

        Fires the ``activity_callback`` (if set on this instance) every 10s
        while the process is running so the gateway's inactivity timeout
        doesn't kill long-running commands.

        Also wraps the poll loop in a ``try/finally`` that guarantees we
        call ``self._kill_process(proc)`` if we exit via ``KeyboardInterrupt``
        or ``SystemExit``.  Without this, the local backend (which spawns
        subprocesses with ``os.setsid`` into their own process group) leaves
        an orphan with ``PPID=1`` when python is shut down mid-tool — the
        ``sleep 300``-survives-30-min bug Physikal and I both hit.
        """
        if bounded_capture:
            try:
                from tools.tool_output_limits import get_max_bytes

                capture_limit = get_max_bytes()
            except Exception:
                capture_limit = 50_000
        else:
            # Full fidelity: effectively unbounded collector (single head
            # segment, no eviction) so behavior matches the historical
            # accumulate-everything semantics.
            capture_limit = _UNBOUNDED_CAPTURE_CHARS
        spill_path = None
        if bounded_capture:
            # Foreground terminal path: tee overflow to a spill file so a
            # truncated result is recoverable without re-running (the file
            # only gets created if output actually exceeds the cap).
            try:
                spill_dir = get_hermes_home() / "cache" / "terminal-output"
                spill_path = spill_dir / f"out-{int(time.time())}-{os.getpid()}-{id(proc) & 0xffff:x}.log"
                # Opportunistic cleanup of spills older than 7 days.
                if spill_dir.is_dir():
                    cutoff = time.time() - 7 * 86400
                    for old in spill_dir.glob("out-*.log"):
                        try:
                            if old.stat().st_mtime < cutoff:
                                old.unlink()
                        except OSError:
                            pass
            except Exception:
                spill_path = None
        output = _BoundedOutputCollector(capture_limit, spill_path=spill_path)

        # Non-blocking drain via select().
        #
        # The old pattern — ``for line in proc.stdout`` — blocks on
        # ``readline()`` until the pipe reaches EOF.  When the user's command
        # backgrounds a process (``cmd &``, ``setsid cmd & disown``, etc.),
        # that backgrounded grandchild inherits the write-end of our stdout
        # pipe via ``fork()``.  Even after ``bash`` itself exits, the pipe
        # stays open because the grandchild still holds it — so the drain
        # thread never returns and the tool hangs for the full lifetime of
        # the grandchild (issue #8340: users reported indefinite hangs when
        # restarting uvicorn with ``setsid ... & disown``).
        #
        # The fix: select() with a short poll interval, and stop draining
        # shortly after ``bash`` exits even if the pipe hasn't EOF'd yet.
        # Any output the grandchild writes after that point goes to an
        # orphaned pipe (harmless — the kernel reaps it when our end closes).
        #
        # Decoding: we ``os.read()`` raw bytes in fixed-size chunks (4096)
        # so a single multibyte UTF-8 character can split across reads.  An
        # incremental decoder buffers partial sequences across chunks, and
        # ``errors="replace"`` mirrors the baseline ``TextIOWrapper`` (which
        # was constructed with ``encoding="utf-8", errors="replace"`` on
        # ``Popen``) so binary or mis-encoded output is preserved with
        # U+FFFD substitution rather than clobbering the whole buffer.
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

        def _drain_iterable(stream):
            # Fallback path: ``stream`` is not backed by a real OS file
            # descriptor (no usable ``fileno()``).  This covers in-memory
            # ProcessHandle adapters that expose stdout as a plain iterator of
            # already-collected output (the legacy ``for line in proc.stdout``
            # contract) rather than a live pipe.  Iterate it to EOF.  Without
            # this, the drain thread would raise an unhandled exception and die
            # silently, losing all of the process's output.
            try:
                for piece in stream:
                    if piece is None:
                        continue
                    if isinstance(piece, bytes):
                        output.append(decoder.decode(piece))
                    else:
                        output.append(str(piece))
            except Exception:
                pass
            finally:
                try:
                    tail = decoder.decode(b"", final=True)
                    if tail:
                        output.append(tail)
                except Exception:
                    pass

        def _drain():
            # Resolve a real OS file descriptor up front.  Real subprocesses and
            # the SDK ``_ThreadedProcessHandle`` (os.pipe-backed) both return an
            # integer fd here.  Mocks / iterator-style stdout streams either lack
            # ``fileno()`` entirely or return a non-integer — in that case fall
            # back to draining the stream as an iterable instead of crashing the
            # thread (issue: 'list_iterator' object has no attribute 'fileno').
            stream = proc.stdout
            if stream is None:
                return
            fileno = getattr(stream, "fileno", None)
            try:
                fd = fileno() if callable(fileno) else None
            except Exception:
                fd = None
            if not isinstance(fd, int) or fd < 0:
                _drain_iterable(stream)
                return
            # select.select does NOT work on pipe fds on Windows (only sockets).
            # Use blocking os.read in a daemon thread instead — safe because
            # EOF arrives promptly when bash exits.
            if os.name == "nt":
                try:
                    while True:
                        chunk = os.read(fd, 4096)
                        if not chunk:
                            break
                        output.append(decoder.decode(chunk))
                except (ValueError, OSError):
                    pass
                finally:
                    try:
                        tail = decoder.decode(b"", final=True)
                        if tail:
                            output.append(tail)
                    except Exception:
                        pass
                return
            idle_after_exit = 0
            try:
                while True:
                    try:
                        ready, _, _ = select.select([fd], [], [], 0.1)
                    except (ValueError, OSError):
                        break  # fd already closed
                    if ready:
                        try:
                            chunk = os.read(fd, 4096)
                        except (ValueError, OSError):
                            break
                        if not chunk:
                            break  # true EOF — all writers closed
                        output.append(decoder.decode(chunk))
                        idle_after_exit = 0
                    elif proc.poll() is not None:
                        # bash is gone and the pipe was idle for ~100ms.  Give
                        # it two more cycles to catch any buffered tail, then
                        # stop — otherwise we wait forever on a grandchild pipe.
                        idle_after_exit += 1
                        if idle_after_exit >= 3:
                            break
            finally:
                # Flush any bytes buffered mid-sequence.  With ``errors="replace"``
                # this emits U+FFFD for any final incomplete sequence rather than
                # raising.
                try:
                    tail = decoder.decode(b"", final=True)
                    if tail:
                        output.append(tail)
                except Exception:
                    pass

        drain_thread = threading.Thread(target=_drain, daemon=True)
        drain_thread.start()
        deadline = time.monotonic() + timeout
        _now = time.monotonic()
        _activity_state = {
            "last_touch": _now,
            "start": _now,
        }

        # --- Debug tracing (opt-in via HERMES_DEBUG_INTERRUPT=1) -------------
        # Captures loop entry/exit, interrupt state changes, and periodic
        # heartbeats so we can diagnose "agent never sees the interrupt"
        # reports without reproducing locally.
        _tid = threading.current_thread().ident
        _pid = getattr(proc, "pid", None)
        _iter_count = 0
        _last_heartbeat = _now
        _last_interrupt_state = False
        _cb_was_none = get_activity_callback() is None
        if _DEBUG_INTERRUPT:
            logger.info(
                "[interrupt-debug] _wait_for_process ENTER tid=%s pid=%s "
                "timeout=%ss activity_cb=%s initial_interrupt=%s",
                _tid, _pid, timeout,
                "set" if not _cb_was_none else "MISSING",
                is_interrupted(),
            )

        try:
            _poll_sleep = 0.005
            while proc.poll() is None:
                _iter_count += 1
                if is_interrupted():
                    if _DEBUG_INTERRUPT:
                        logger.info(
                            "[interrupt-debug] _wait_for_process INTERRUPT DETECTED "
                            "tid=%s pid=%s iter=%d elapsed=%.1fs — killing process group",
                            _tid, _pid, _iter_count, time.monotonic() - _activity_state["start"],
                        )
                    self._kill_process(proc)
                    drain_thread.join(timeout=2)
                    return self._finalize_wait_result(
                        output,
                        output.render(suffix="\n[Command interrupted]"),
                        130,
                    )
                if time.monotonic() > deadline:
                    if _DEBUG_INTERRUPT:
                        logger.info(
                            "[interrupt-debug] _wait_for_process TIMEOUT "
                            "tid=%s pid=%s iter=%d timeout=%ss",
                            _tid, _pid, _iter_count, timeout,
                        )
                    self._kill_process(proc)
                    drain_thread.join(timeout=2)
                    timeout_msg = f"\n[Command timed out after {timeout}s]"
                    return self._finalize_wait_result(
                        output,
                        output.render(suffix=timeout_msg).lstrip()
                        if output.total_chars == 0
                        else output.render(suffix=timeout_msg),
                        124,
                    )
                # Periodic activity touch so the gateway knows we're alive
                touch_activity_if_due(_activity_state, "terminal command running")

                # Heartbeat every ~30s: proves the loop is alive and reports
                # the activity-callback state (thread-local, can get clobbered
                # by nested tool calls or executor thread reuse).
                if _DEBUG_INTERRUPT and time.monotonic() - _last_heartbeat >= 30.0:
                    _cb_now_none = get_activity_callback() is None
                    logger.info(
                        "[interrupt-debug] _wait_for_process HEARTBEAT "
                        "tid=%s pid=%s iter=%d elapsed=%.0fs "
                        "interrupt=%s activity_cb=%s%s",
                        _tid, _pid, _iter_count,
                        time.monotonic() - _activity_state["start"],
                        is_interrupted(),
                        "set" if not _cb_now_none else "MISSING",
                        " (LOST during run)" if _cb_now_none and not _cb_was_none else "",
                    )
                    _last_heartbeat = time.monotonic()
                    _cb_was_none = _cb_now_none

                # Adaptive poll: start at 5ms so fast commands (echo, pwd,
                # date, cat short files) return in ~6ms instead of being
                # stuck waiting for the next 200ms tick. Back off
                # exponentially toward 200ms so long-running commands
                # (builds, tests, sleeps) don't pay measurable CPU in the
                # poll loop. For an `echo` this saves ~195ms per tool call;
                # for a 10s build the steady-state poll rate is identical
                # to the old behavior.
                time.sleep(_poll_sleep)
                if _poll_sleep < 0.2:
                    _poll_sleep = min(_poll_sleep * 1.5, 0.2)
        except (KeyboardInterrupt, SystemExit):
            # Signal arrived (SIGTERM/SIGHUP/SIGINT) or sys.exit() was called
            # while we were polling.  The local backend spawns subprocesses
            # with os.setsid, which puts them in their own process group — so
            # if we let the interrupt propagate without killing the child,
            # python exits and the child is reparented to init (PPID=1) and
            # keeps running as an orphan.  Killing the process group here
            # guarantees the tool's side effects stop when the agent stops.
            if _DEBUG_INTERRUPT:
                logger.info(
                    "[interrupt-debug] _wait_for_process EXCEPTION_EXIT "
                    "tid=%s pid=%s iter=%d elapsed=%.1fs — killing subprocess group before re-raise",
                    _tid, _pid, _iter_count,
                    time.monotonic() - _activity_state["start"],
                )
            try:
                self._kill_process(proc)
                drain_thread.join(timeout=2)
            except Exception:
                pass  # cleanup is best-effort
            raise

        # Drain thread now exits promptly after bash does (~300ms idle
        # check).  A short join is enough; a long one would be a bug since
        # it means the non-blocking loop itself stopped cooperating.
        drain_thread.join(timeout=2)

        try:
            proc.stdout.close()
        except Exception:
            pass

        if _DEBUG_INTERRUPT:
            logger.info(
                "[interrupt-debug] _wait_for_process EXIT (natural) "
                "tid=%s pid=%s iter=%d elapsed=%.1fs returncode=%s",
                _tid, _pid, _iter_count,
                time.monotonic() - _activity_state["start"],
                proc.returncode,
            )

        # Join the stdin writer thread before reading its error list: a child
        # that exits without reading stdin can otherwise race ahead of a
        # recorded encode failure, silently dropping it. The thread cannot
        # block long after child exit (write raises BrokenPipeError once the
        # pipe closes); the timeout is a pure safety net.
        stdin_thread = getattr(proc, "_hermes_stdin_thread", None)
        if stdin_thread is not None:
            stdin_thread.join(timeout=5)
        rendered = output.render()
        result = self._finalize_wait_result(output, rendered, proc.returncode)
        stdin_errors = getattr(proc, "_hermes_stdin_errors", None)
        if stdin_errors:
            err = str(stdin_errors[0])
            result["stdin_error"] = err
            result["output"] = rendered + f"\n[stdin write failed: {err}]"
        return result

    @staticmethod
    def _finalize_wait_result(collector: "_BoundedOutputCollector",
                              rendered: str, returncode: int | None) -> dict:
        """Assemble a wait result, attaching spill metadata when overflow occurred."""
        result = {"output": rendered, "returncode": returncode}
        spill = collector.close_spill()
        if spill:
            result["output_total_chars"] = collector.total_chars
            result["full_output_path"] = spill
        return result

    def _kill_process(self, proc: ProcessHandle):
        """Terminate a process. Subclasses may override for process-group kill."""
        try:
            proc.kill()
        except (ProcessLookupError, PermissionError, OSError):
            pass

    # ------------------------------------------------------------------
    # Safe-state and CWD extraction
    # ------------------------------------------------------------------

    def _extract_safe_state_status(self, result: dict) -> None:
        """Disable persistence when the wrapper emits a value-free error marker."""
        output = result.get("output", "")
        marker = re.escape(self._safe_state_marker)
        pattern = re.compile(
            rf"\n?{marker}([A-Za-z0-9_]{{1,64}}){marker}\r?\n?"
        )
        matches = list(pattern.finditer(output))
        if not matches:
            return
        self._disable_safe_state(matches[0].group(1))
        result["output"] = pattern.sub("", output)

    # ------------------------------------------------------------------
    # CWD extraction
    # ------------------------------------------------------------------

    def _update_cwd(self, result: dict):
        """Extract CWD from command output. Override for local file-based read."""
        self._extract_cwd_from_output(result)

    def _extract_cwd_from_output(self, result: dict):
        """Parse the __HERMES_CWD_{session}__ marker from stdout output.

        Updates self.cwd and strips the marker from result["output"].
        Used by remote backends (Docker, SSH, Modal, Daytona, Singularity).

        Sets ``result["cwd_observed"]`` when the marker yielded a directory for
        THIS command. The wrapper prints the marker after the command returns,
        so a killed / timed-out command never emits one and ``self.cwd`` keeps
        whatever the previous command left there. That environment is shared by
        every session, so callers must not attribute an unobserved cwd to the
        session that ran this command (see terminal_tool's session-cwd record).
        """
        output = result.get("output", "")
        marker = self._cwd_marker
        last = output.rfind(marker)
        if last == -1:
            return

        # Find the opening marker before this closing one
        search_start = max(0, last - 4096)  # CWD path won't be >4KB
        first = output.rfind(marker, search_start, last)
        if first == -1 or first == last:
            return

        cwd_path = output[first + len(marker) : last].strip()
        if cwd_path:
            self.cwd = cwd_path
            result["cwd_observed"] = True

        # Strip the marker line AND the \n we injected before it.
        # The wrapper emits: printf '\n__MARKER__%s__MARKER__\n'
        # So the output looks like: <cmd output>\n__MARKER__path__MARKER__\n
        # We want to remove everything from the injected \n onwards.
        line_start = output.rfind("\n", 0, first)
        if line_start == -1:
            line_start = first
        line_end = output.find("\n", last + len(marker))
        line_end = line_end + 1 if line_end != -1 else len(output)

        result["output"] = output[:line_start] + output[line_end:]

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    def _before_execute(self) -> None:
        """Hook called before each command execution.

        Remote backends (SSH, Modal, Daytona) override this to trigger
        their FileSyncManager.  Bind-mount backends (Docker, Singularity)
        and Local don't need file sync — the host filesystem is directly
        visible inside the container/process.
        """
        pass

    # ------------------------------------------------------------------
    # Unified execute()
    # ------------------------------------------------------------------

    def execute(
        self,
        command: str,
        cwd: str = "",
        *,
        timeout: int | None = None,
        stdin_data: str | None = None,
        rewrite_compound_background: bool = True,
        bounded_capture: bool = False,
    ) -> dict:
        """Execute a command, return {"output": str, "returncode": int}.

        ``bounded_capture=True`` caps stdout/stderr retention at
        ``tool_output.max_bytes`` WHILE the stream is drained (head/tail
        window) instead of holding the full output in memory (#64435).
        It must only be set by callers whose output is destined for the
        model/tool payload (the foreground terminal tool). Internal
        full-fidelity consumers — file operations ``cat`` reads that feed
        the patch engine, code-execution RPC reads, log reads — MUST leave
        it False: truncating those corrupts data, not just display.
        """
        self._before_execute()

        exec_command, sudo_stdin = self._prepare_command(command)
        # Guard against the `A && B &` subshell-wait trap by default.
        # Some callers (spawn_via_env) already produce shell-safe wrappers and
        # pass rewrite_compound_background=False.
        if rewrite_compound_background:
            from tools.terminal_tool import _rewrite_compound_background
            exec_command = _rewrite_compound_background(exec_command)
        effective_timeout = timeout or self.timeout
        effective_cwd = cwd or self.cwd

        # Merge sudo stdin with caller stdin
        if sudo_stdin is not None and stdin_data is not None:
            effective_stdin = sudo_stdin + stdin_data
        elif sudo_stdin is not None:
            effective_stdin = sudo_stdin
        else:
            effective_stdin = stdin_data

        # Embed stdin as heredoc for backends that need it
        if effective_stdin and self._stdin_mode == "heredoc":
            exec_command = self._embed_stdin_heredoc(exec_command, effective_stdin)
            effective_stdin = None
        elif effective_stdin and self._stdin_mode == "inline":
            exec_command = self._embed_stdin_inline(exec_command, effective_stdin)
            effective_stdin = None

        wrapped = self._wrap_command(exec_command, effective_cwd)

        # Use a login shell when safe state is unavailable, unless login Bash
        # itself is broken and init_session selected the non-login fallback.
        login = not self._safe_state_ready and not self._prefer_nonlogin

        proc = self._run_bash(
            wrapped, login=login, timeout=effective_timeout, stdin_data=effective_stdin
        )
        result = self._wait_for_process(
            proc, timeout=effective_timeout, bounded_capture=bounded_capture
        )
        self._extract_safe_state_status(result)
        if self._safe_state_ready:
            valid, reason = self._prepare_safe_state_artifact()
            if not valid:
                self._disable_safe_state(reason)
        self._update_cwd(result)

        return result

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def stop(self):
        """Alias for cleanup (compat with older callers)."""
        self.cleanup()

    def __del__(self):
        try:
            self.cleanup()
        except Exception:
            pass

    def _prepare_command(self, command: str) -> tuple[str, str | None]:
        """Transform sudo commands if SUDO_PASSWORD is available."""
        from tools.terminal_tool import _transform_sudo_command

        return _transform_sudo_command(command)
