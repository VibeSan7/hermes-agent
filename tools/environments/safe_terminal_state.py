from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Literal, Mapping


SAFE_STATE_VERSION = 1
SAFE_STATE_HEADER = "HERMES_SAFE_TERMINAL_STATE\t1"
SAFE_STATE_NAMES = (
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
SAFE_STATE_MAX_FILE_BYTES = 65_536

SafeStatePlatform = Literal["posix", "msys"]

_PATH_VALUE_MAX_BYTES = 32_768
_OTHER_VALUE_MAX_BYTES = 4_096
_PATH_VALUE_NAMES = frozenset(
    {"VIRTUAL_ENV", "CONDA_PREFIX", "CONDA_EXE", "CONDA_PYTHON_EXE"}
)
_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:[\\/]")


class SafeStateError(ValueError):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class SafeTerminalState:
    records: tuple[tuple[str, str | None], ...]


def _validate_platform(platform: str) -> SafeStatePlatform:
    if platform not in ("posix", "msys"):
        raise SafeStateError("platform")
    return platform


def _is_absolute_path(value: str, platform: SafeStatePlatform) -> bool:
    if value.startswith("/"):
        return True
    return platform == "msys" and _WINDOWS_ABSOLUTE_RE.match(value) is not None


def _validate_path_list(value: str, platform: SafeStatePlatform) -> None:
    if "://" in value:
        raise SafeStateError("path_uri")

    separator = ";" if platform == "msys" and ";" in value else ":"
    parts = value.split(separator)
    if not parts or any(not part for part in parts):
        raise SafeStateError("path_empty_entry")
    if any(not _is_absolute_path(part, platform) for part in parts):
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
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SafeStateError("control_character")

    encoded_length = len(value.encode("utf-8"))
    if name == "PATH":
        if encoded_length > _PATH_VALUE_MAX_BYTES:
            raise SafeStateError("path_too_large")
        _validate_path_list(value, platform)
    elif encoded_length > _OTHER_VALUE_MAX_BYTES:
        raise SafeStateError("value_too_large")

    if name in _PATH_VALUE_NAMES and not _is_absolute_path(value, platform):
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


def decode_safe_state(
    payload: bytes,
    *,
    platform: SafeStatePlatform,
) -> SafeTerminalState:
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

    records: list[tuple[str, str | None]] = []
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
        records.append((expected_name, value))

    return SafeTerminalState(records=tuple(records))
