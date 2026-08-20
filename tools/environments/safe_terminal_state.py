"""Safe terminal state policy, versioned data format, and shell codec.

Security invariants:

1. Only the code-defined allowlist below may ever be persisted.
2. The state file is data, never a shell script: it is never sourced or
   evaluated.
3. The shell codec runs under an ABSOLUTE trusted interpreter (``sys.executable``
   for Local, or a ``command -v`` result pinned at probe time on the FRESH
   environment, before any persisted state is applied).  No ``$PATH``-resolved
   tool can be substituted by a persisted ``PATH``.
4. Any malformed record invalidates the whole file; nothing is applied
   partially.
5. The Bash wrapper only assigns decoded values to variables (``export
   "NAME=$VALUE"``); it never evaluates the value as shell code.
"""

from __future__ import annotations

import base64
import binascii
import re
import shlex
from dataclasses import dataclass
from typing import Literal, Mapping, NamedTuple

SAFE_STATE_VERSION = 1
SAFE_STATE_HEADER = "HERMES_SAFE_TERMINAL_STATE\t1"
SAFE_STATE_FRESH_NAMES_ENV = "HERMES_SAFE_STATE_FRESH_NAMES"
SAFE_STATE_PASSTHROUGH_ENV = "HERMES_SAFE_STATE_PASSTHROUGH_ACTIVE"


SAFE_STATE_NAMES: tuple[str, ...] = (
    "PATH",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "CONDA_DEFAULT_ENV",
    "CONDA_SHLVL",
    "CONDA_EXE",
    "CONDA_PYTHON_EXE",
    "_CE_CONDA",
    "_CE_M",
)

SAFE_STATE_MAX_FILE_BYTES = 64 * 1024
_PATH_VALUE_MAX_BYTES = 32 * 1024
_OTHER_VALUE_MAX_BYTES = 4 * 1024

SafeStatePlatform = Literal["posix", "msys"]

_DRIVE_RE = re.compile(r"^[A-Za-z]:[/\\]")
_ASCII_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class SafeStateError(ValueError):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def _validate_platform(platform: str) -> SafeStatePlatform:
    if platform not in ("posix", "msys"):
        raise SafeStateError("platform")
    return platform  # type: ignore[return-value]


def _is_abs_path(value: str, platform: SafeStatePlatform) -> bool:
    if value.startswith("/"):
        return True
    return platform == "msys" and _DRIVE_RE.match(value) is not None


def _split_path_entries(value: str, platform: SafeStatePlatform) -> list[str]:
    if platform != "msys":
        return value.split(":")
    if ";" in value:
        parts = value.split(";")
        for part in parts:
            for index, character in enumerate(part):
                if character == ":" and not (
                    index == 1 and _DRIVE_RE.match(part) is not None
                ):
                    raise SafeStateError("path_mixed_separator")
        return parts
    parts: list[str] = []
    start = 0
    for index, character in enumerate(value):
        if character != ":":
            continue
        drive_colon = (
            index == start + 1
            and value[start].isalpha()
            and index + 1 < len(value)
            and value[index + 1] in "/\\"
        )
        if drive_colon:
            continue
        parts.append(value[start:index])
        start = index + 1
    parts.append(value[start:])
    return parts


def _validate_path_list(value: str, platform: SafeStatePlatform) -> None:
    if "://" in value:
        raise SafeStateError("path_uri")
    parts = _split_path_entries(value, platform)
    if not parts or any(not part for part in parts):
        raise SafeStateError("path_empty_entry")
    if any(not _is_abs_path(part, platform) for part in parts):
        raise SafeStateError("path_not_absolute")


def validate_safe_value(
    name: str,
    value: str,
    *,
    platform: SafeStatePlatform,
) -> str:
    platform = _validate_platform(platform)
    if name not in SAFE_STATE_NAMES:
        raise SafeStateError("unknown_name")
    if not isinstance(value, str):
        raise SafeStateError("value_type")
    if _ASCII_CONTROL_RE.search(value):
        raise SafeStateError("control_character")

    encoded_length = len(value.encode("utf-8"))
    if name == "PATH":
        if encoded_length > _PATH_VALUE_MAX_BYTES:
            raise SafeStateError("path_too_large")
        _validate_path_list(value, platform)
    elif encoded_length > _OTHER_VALUE_MAX_BYTES:
        raise SafeStateError("value_too_large")

    if name in ("VIRTUAL_ENV", "CONDA_PREFIX", "CONDA_EXE", "CONDA_PYTHON_EXE"):
        if not _is_abs_path(value, platform):
            raise SafeStateError("path_not_absolute")
    if name == "CONDA_SHLVL":
        if not value.isdecimal() or not 0 <= int(value) <= 99:
            raise SafeStateError("conda_shlvl")
    return value


def encode_safe_state(
    values: Mapping[str, str | None],
    *,
    platform: SafeStatePlatform,
) -> bytes:
    platform = _validate_platform(platform)
    unknown_names = set(values) - set(SAFE_STATE_NAMES)
    if unknown_names:
        raise SafeStateError("unknown_name")

    lines = [SAFE_STATE_HEADER]
    for name in SAFE_STATE_NAMES:
        value = values.get(name)
        if value is not None:
            try:
                value = validate_safe_value(name, value, platform=platform)
            except SafeStateError:
                value = None
        if value is None:
            lines.append(f"UNSET\t{name}")
        else:
            encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
            lines.append(f"SET\t{name}\t{encoded}")

    payload = ("\n".join(lines) + "\n").encode("utf-8")
    if len(payload) > SAFE_STATE_MAX_FILE_BYTES:
        raise SafeStateError("file_too_large")
    return payload


class SafeStateRecord(NamedTuple):
    name: str
    value: str | None


@dataclass(frozen=True)
class SafeTerminalState:
    records: tuple[SafeStateRecord, ...]


def _decode_value(encoded: str) -> str:
    try:
        encoded_bytes = encoded.encode("ascii")
        raw = base64.b64decode(encoded_bytes, validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise SafeStateError("base64") from exc
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise SafeStateError("base64")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SafeStateError("utf8") from exc


def decode_safe_state(payload: bytes, *, platform: SafeStatePlatform) -> SafeTerminalState:
    platform = _validate_platform(platform)
    if not isinstance(payload, bytes):
        raise SafeStateError("payload_type")
    if len(payload) > SAFE_STATE_MAX_FILE_BYTES:
        raise SafeStateError("file_too_large")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SafeStateError("utf8") from exc
    if not text.endswith("\n"):
        raise SafeStateError("newline")
    if "\r" in text:
        raise SafeStateError("record_shape")

    lines = text[:-1].split("\n")
    if not lines or lines[0] != SAFE_STATE_HEADER:
        raise SafeStateError("header")
    if len(lines) != len(SAFE_STATE_NAMES) + 1:
        raise SafeStateError("record_set")

    records: list[SafeStateRecord] = []
    for expected_name, line in zip(SAFE_STATE_NAMES, lines[1:], strict=True):
        fields = line.split("\t")
        if len(fields) < 2 or fields[1] != expected_name:
            raise SafeStateError("record_set")
        operation = fields[0]
        if operation == "UNSET":
            if len(fields) != 2:
                raise SafeStateError("record_shape")
            value = None
        elif operation == "SET":
            if len(fields) != 3:
                raise SafeStateError("record_shape")
            value = _decode_value(fields[2])
            value = validate_safe_value(expected_name, value, platform=platform)
        else:
            raise SafeStateError("record_shape")
        records.append(SafeStateRecord(expected_name, value))

    return SafeTerminalState(records=tuple(records))


@dataclass(frozen=True)
class SafeStateShellScripts:
    probe: str
    apply: str
    capture: str


def _codec_helper_source() -> str:
    """Self-contained Python codec embedded in every generated Bash wrapper.

    The whole program is delivered as a single-quoted shell string and run by
    an absolute trusted interpreter, so it never depends on ``$PATH``.  All
    validation duplicates the Python policy oracle above; parity is pinned by
    ``test_runtime_parser_rejects_every_payload_rejected_by_python_oracle``.
    """
    return r'''
import base64 as b
import os
import sys
import tempfile
import time

N = ("PATH", "VIRTUAL_ENV", "CONDA_PREFIX", "CONDA_DEFAULT_ENV", "CONDA_SHLVL", "CONDA_EXE", "CONDA_PYTHON_EXE", "_CE_CONDA", "_CE_M")
H = "HERMES_SAFE_TERMINAL_STATE\t1"
P = sys.argv[1]
M = sys.argv[2]
PM = 32768
VM = 4096
FM = 65536

BS = chr(92)
S = set(os.environ.get("HERMES_SAFE_STATE_FRESH_NAMES", "").split(":"))


def al(value):
    return "A" <= value <= "Z" or "a" <= value <= "z"


def idv(value):
    return len(value) > 2 and al(value[0]) and value[1] == ":" and value[2] in "/" + BS


def ia(value):
    if P == "msys":
        return value.startswith("/") or idv(value)
    return value.startswith("/")


def np(value):
    if P == "msys" and len(value) > 3 and value[0] == "/" and al(value[1]) and value[2] == "/":
        return value[1].upper() + ":" + value[2:]
    return value


def pp(value):
    if P != "msys": return value.split(":")
    if ";" in value:
        parts = value.split(";"); return [] if any(":" in x[2:] or (":" in x and not idv(x)) for x in parts) else parts
    parts = []; start = 0
    for index, character in enumerate(value):
        drive_colon = index == start + 1 and al(value[start]) and index + 1 < len(value) and value[index + 1] in "/" + BS
        if character == ":" and not drive_colon:
            parts.append(value[start:index]); start = index + 1
    return parts + [value[start:]]


def vv(name, value):
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return False
    encoded = value.encode("utf-8")
    if name == "PATH":
        if len(encoded) > PM:
            return False
        if "://" in value:
            return False
        parts = pp(value)
        if not parts or any(not part or not ia(part) for part in parts):
            return False
    else:
        if len(encoded) > VM:
            return False
        if name in ("VIRTUAL_ENV", "CONDA_PREFIX", "CONDA_EXE", "CONDA_PYTHON_EXE"):
            if not ia(value):
                return False
        if name == "CONDA_SHLVL":
            if not (value.isdecimal() and 0 <= int(value) <= 99):
                return False
    return True


def ps(data):
    if len(data) > FM:
        raise ValueError("size")
    text = data.decode("utf-8")
    if not text.endswith("\n") or "\r" in text:
        raise ValueError("n")
    lines = text[:-1].split("\n")
    if not lines or lines[0] != H:
        raise ValueError("h")
    if len(lines) != 1 + len(N):
        raise ValueError("s")
    out = []
    for line, name in zip(lines[1:], N):
        f = line.split("\t")
        if f == ["UNSET", name]:
            out.append(("UNSET", name, None))
        elif len(f) == 3 and f[0] == "SET" and f[1] == name:
            try:
                value = b.b64decode(f[2], validate=True).decode("utf-8")
            except Exception:
                raise ValueError("v")
            if not vv(name, value):
                raise ValueError("v")
            c = b.b64encode(value.encode("utf-8")).decode("ascii")
            if c != f[2]:
                raise ValueError("c")
            out.append(("SET", name, value))
        else:
            raise ValueError("r")
    return out


def er(records):
    handle = sys.stdout.buffer
    for op, name, value in records:
        if op == "UNSET":
            handle.write(b"UNSET\t" + name.encode("ascii") + b"\n")
        else:
            handle.write(
                b"SET\t" + name.encode("ascii") + b"\t"
                + value.encode("utf-8") + b"\n"
            )


def gv(name):
    if name == "PATH" and "HERMES_SAFE_STATE_CAPTURE_PATH" in os.environ:
        return os.environ["HERMES_SAFE_STATE_CAPTURE_PATH"]
    value = os.environ.get(name)
    if value is None and P == "msys" and name == "PATH":
        value = next((v for k, v in os.environ.items() if k.upper() == "PATH"), None)
    return value


def main():
    if M == "encode":
        values = {name: gv(name) for name in N if name not in S}
        lines = [H]
        for name in N:
            value = values.get(name)
            if value is not None and vv(name, value):
                encoded = b.b64encode(value.encode("utf-8")).decode("ascii")
                lines.append("SET\t%s\t%s" % (name, encoded))
            else:
                lines.append("UNSET\t%s" % name)
        payload = ("\n".join(lines) + "\n").encode("utf-8")
        if len(payload) > FM:
            raise ValueError("z")
        target = np(sys.argv[3])
        fd, tmp = tempfile.mkstemp(prefix=os.path.basename(target) + ".tmp.", dir=os.path.dirname(target) or ".")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
            for attempt in range(50):
                try: os.replace(tmp, target); break
                except PermissionError:
                    if attempt == 49: raise
                    time.sleep(0.01)
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
        return 0

    target = np(sys.argv[3])
    with open(target, "rb") as handle:
        data = handle.read(FM + 1)
    records = ps(data)
    er(records)
    return 0


if __name__ == "__main__":
    try: sys.exit(main())
    except Exception: sys.exit(1)
'''.strip()


def _build_probe_script(
    *,
    platform: SafeStatePlatform,
    python_path: str | None,
) -> str:
    return "\n".join(
        [
            "    _hss_helper_code='__HSS_HELPER__'",
            "_hss_probe() {",
            "    _hss_codec=0",
            f'    [ -z "${{{SAFE_STATE_PASSTHROUGH_ENV}-}}" ] || return 98',
            (f"    _hss_py={shlex.quote(python_path)}" if python_path else
             "    _hss_py=$(command type -P python3 2>/dev/null || command type -P python 2>/dev/null || true)"),
            '    case "$_hss_py" in /*) ;; *) _hss_py= ;; esac',
            '    if [ -n "$_hss_py" ] && "$_hss_py" -I -c "import sys" >/dev/null 2>&1; then',
            '        _hss_codec=1',
            '    fi',
            f"    readonly {SAFE_STATE_FRESH_NAMES_ENV} {SAFE_STATE_PASSTHROUGH_ENV}",
            "    readonly _hss_helper_code _hss_py _hss_codec",
            '    [ "$_hss_codec" = 1 ] || return 97',
            "}",
            "_hss_probe",
        ]
    )


def _build_capture_script(
    quoted_python_state: str,
    platform: SafeStatePlatform,
) -> str:
    command = (
        'MSYS_NO_PATHCONV=1 HERMES_SAFE_STATE_CAPTURE_PATH="$PATH" '
        '"$_hss_py" -I -c "$_hss_helper_code"'
        f" {shlex.quote(platform)} encode {quoted_python_state}"
    )
    return "\n".join(
        (
            'if [ "$_hss_codec" = 1 ]; then',
            "    (",
            "        umask 077",
            f"        {command}",
            "    )",
            "else",
            "    (exit 97)",
            "fi",
        )
    )


def _build_apply_script(
    quoted_python_state: str,
    platform: SafeStatePlatform,
) -> str:
    names = " ".join(shlex.quote(name) for name in SAFE_STATE_NAMES)
    return "\n".join(
        [
            "_hss_apply() {",
            '    [ "$_hss_codec" = 1 ] || return 97',
            "    local _hss_raw _hss_op _hss_name _hss_value _hss_extra _hss_expected _hss_decl",
            "    local _hss_i=0 _hss_parse_rc=0",
            f"    local -a _hss_names=({names}) _hss_ops _hss_values",
            '    _hss_raw=$("$_hss_py" -I -c "$_hss_helper_code"'
            f" {shlex.quote(platform)} decode {quoted_python_state}) || return 93",
            "    while IFS=$'\t' read -r _hss_op _hss_name _hss_value _hss_extra; do",
            '        [ "$_hss_i" -lt "${#_hss_names[@]}" ] || { _hss_parse_rc=93; break; }',
            '        _hss_expected="${_hss_names[$_hss_i]}"',
            '        [ "$_hss_name" = "$_hss_expected" ] || { _hss_parse_rc=93; break; }',
            '        case "$_hss_op" in',
            "            UNSET)",
            '                [ -z "$_hss_value" ] && [ -z "$_hss_extra" ] || { _hss_parse_rc=93; break; }',
            '                _hss_ops[$_hss_i]=UNSET; _hss_values[$_hss_i]= ;;',
            "            SET)",
            '                [ -z "$_hss_extra" ] || { _hss_parse_rc=93; break; }',
            '                _hss_ops[$_hss_i]=SET; _hss_values[$_hss_i]="$_hss_value" ;;',
            "            *) _hss_parse_rc=93; break ;;",
            "        esac",
            "        _hss_i=$((_hss_i + 1))",
            '    done <<< "$_hss_raw"',
            '    [ "$_hss_i" -eq "${#_hss_names[@]}" ] || _hss_parse_rc=93',
            '    [ "$_hss_parse_rc" -eq 0 ] || return 93',
            "    for ((_hss_i=0; _hss_i < ${#_hss_names[@]}; _hss_i++)); do",
            '        _hss_name="${_hss_names[$_hss_i]}"',
            '        case ":${' + SAFE_STATE_FRESH_NAMES_ENV + '-}:" in *:"$_hss_name":*) continue ;; esac',
            '        _hss_decl=$(builtin declare -p "$_hss_name" 2>/dev/null) || _hss_decl=',
            '        _hss_decl=${_hss_decl#declare -}; _hss_decl=${_hss_decl%% *}',
            '        case "$_hss_decl" in ""|-|x) ;; *) return 93 ;; esac',
            "    done",
            "    for ((_hss_i=0; _hss_i < ${#_hss_names[@]}; _hss_i++)); do",
            '        _hss_name="${_hss_names[$_hss_i]}"',
            '        case ":${' + SAFE_STATE_FRESH_NAMES_ENV + '-}:" in *:"$_hss_name":*) continue ;; esac',
            '        if [ "${_hss_ops[$_hss_i]}" = SET ]; then',
            '            builtin export "$_hss_name=${_hss_values[$_hss_i]}" || return 93',
            "        else",
            '            builtin unset "$_hss_name" || return 93',
            "        fi",
            "    done",
            "}",
            "readonly -f _hss_apply",
            "_hss_apply",
        ]
    )


def _inline_helper(script: str) -> str:
    helper = "\n".join(line for line in _codec_helper_source().splitlines() if line.strip())
    return script.replace("__HSS_HELPER__", helper)


def build_safe_state_shell_scripts(
    state_path: str,
    temp_template: str,
    *,
    platform: SafeStatePlatform,
    python_path: str | None = None,
) -> SafeStateShellScripts:
    """Build probe/apply/capture scripts for one backend.

    ``python_path`` is the absolute interpreter for the codec.  When omitted
    (container backends) the probe resolves ``command -v`` on the fresh PATH
    and pins the result read-only for the wrapper lifetime, so a persisted
    ``PATH`` can never redirect the codec.
    """
    platform = _validate_platform(platform)
    python_state = state_path
    quoted_python_state = shlex.quote(python_state)

    probe = _inline_helper(_build_probe_script(platform=platform, python_path=python_path))

    apply = _build_apply_script(quoted_python_state, platform)
    capture = _build_capture_script(quoted_python_state, platform)
    return SafeStateShellScripts(probe=probe, apply=apply, capture=capture)
