from __future__ import annotations

import base64
import binascii
import re
import shlex
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


@dataclass(frozen=True)
class SafeStateShellScripts:
    probe: str
    apply: str
    capture: str


def _build_codec_probe_script(platform: SafeStatePlatform) -> str:
    return f'''__hermes_safe_platform={shlex.quote(platform)}
__hermes_safe_codec=0
__hermes_safe_b64_decode=
__hermes_safe_is_abs_path() {{
    case "$__hermes_safe_platform:$1" in
        posix:/*|msys:/*|msys:[A-Za-z]:[\\\\/]*) return 0 ;;
        *) return 1 ;;
    esac
}}
__hermes_safe_validate_path_list() {{
    local __value="$1" __separator=":" __part
    local -a __parts
    case "$__value" in *://*) return 1 ;; esac
    if [ "$__hermes_safe_platform" = msys ]; then
        case "$__value" in
            *';'*) __separator=';' ;;
            [A-Za-z]:[\\\\/]*) __parts=("$__value") ;;
        esac
    fi
    if [ "${{#__parts[@]}}" -eq 0 ]; then
        IFS="$__separator" read -r -a __parts <<< "$__value"
    fi
    [ "${{#__parts[@]}}" -gt 0 ] || return 1
    for __part in "${{__parts[@]}}"; do
        [ -n "$__part" ] || return 1
        __hermes_safe_is_abs_path "$__part" || return 1
    done
}}
__hermes_safe_validate_value() {{
    local __name="$1" __value="$2" __clean __bytes
    __clean=$(printf '%s' "$__value" | LC_ALL=C tr -d '\\000-\\037\\177') || return 1
    [ "$__clean" = "$__value" ] || return 1
    __bytes=$(printf '%s' "$__value" | wc -c | tr -d '[:space:]') || return 1
    case "$__bytes" in ''|*[!0-9]*) return 1 ;; esac
    if [ "$__name" = PATH ]; then
        [ "$__bytes" -le {_PATH_VALUE_MAX_BYTES} ] || return 1
        __hermes_safe_validate_path_list "$__value" || return 1
    else
        [ "$__bytes" -le {_OTHER_VALUE_MAX_BYTES} ] || return 1
    fi
    case "$__name" in
        VIRTUAL_ENV|CONDA_PREFIX|CONDA_EXE|CONDA_PYTHON_EXE)
            __hermes_safe_is_abs_path "$__value" || return 1 ;;
        CONDA_SHLVL)
            case "$__value" in ''|*[!0-9]*) return 1 ;; esac
            [ "$__value" -le 99 ] 2>/dev/null || return 1 ;;
    esac
}}
__hermes_safe_encode() {{
    printf '%s' "$1" | base64 | tr -d '\\r\\n'
}}
__hermes_safe_decode() {{
    printf '%s' "$1" | base64 "$__hermes_safe_b64_decode" 2>/dev/null
}}
if command -v base64 >/dev/null 2>&1 \
   && command -v tr >/dev/null 2>&1 \
   && command -v wc >/dev/null 2>&1 \
   && command -v mktemp >/dev/null 2>&1 \
   && command -v mv >/dev/null 2>&1 \
   && command -v rm >/dev/null 2>&1; then
    if [ "$(printf 'QQ==' | base64 --decode 2>/dev/null)" = A ]; then
        __hermes_safe_b64_decode=--decode
    elif [ "$(printf 'QQ==' | base64 -d 2>/dev/null)" = A ]; then
        __hermes_safe_b64_decode=-d
    elif [ "$(printf 'QQ==' | base64 -D 2>/dev/null)" = A ]; then
        __hermes_safe_b64_decode=-D
    fi
fi
if [ -n "$__hermes_safe_b64_decode" ]; then
    __hermes_safe_codec=1
    true
else
    (exit 97)
fi'''


def _build_capture_script(quoted_state: str, quoted_temp: str) -> str:
    names = " ".join(shlex.quote(name) for name in SAFE_STATE_NAMES)
    return f'''__hermes_safe_capture() {{
    [ "$__hermes_safe_codec" = 1 ] || return 97
    umask 077
    local __hermes_safe_file={quoted_state} __hermes_safe_template={quoted_temp}
    local __hermes_safe_tmp __hermes_safe_size __hermes_safe_encoded
    local __hermes_safe_name __hermes_safe_value
    local -a __hermes_safe_names=({names})
    __hermes_safe_tmp=$(mktemp "$__hermes_safe_template") || return 94
    if ! {{
        printf '%s\\n' {shlex.quote(SAFE_STATE_HEADER)}
        for __hermes_safe_name in "${{__hermes_safe_names[@]}}"; do
            if [ "${{!__hermes_safe_name+x}}" = x ]; then
                __hermes_safe_value="${{!__hermes_safe_name}}"
                if __hermes_safe_validate_value "$__hermes_safe_name" \
                    "$__hermes_safe_value"; then
                    __hermes_safe_encoded=$(__hermes_safe_encode \
                        "$__hermes_safe_value") || return 95
                    printf 'SET\\t%s\\t%s\\n' "$__hermes_safe_name" \
                        "$__hermes_safe_encoded"
                else
                    printf 'UNSET\\t%s\\n' "$__hermes_safe_name"
                fi
            else
                printf 'UNSET\\t%s\\n' "$__hermes_safe_name"
            fi
        done
    }} > "$__hermes_safe_tmp"; then
        rm -f "$__hermes_safe_tmp"
        return 95
    fi
    __hermes_safe_size=$(wc -c < "$__hermes_safe_tmp" | tr -d '[:space:]') || {{
        rm -f "$__hermes_safe_tmp"
        return 95
    }}
    case "$__hermes_safe_size" in ''|*[!0-9]*)
        rm -f "$__hermes_safe_tmp"; return 95 ;;
    esac
    if [ "$__hermes_safe_size" -gt {SAFE_STATE_MAX_FILE_BYTES} ]; then
        rm -f "$__hermes_safe_tmp"
        return 95
    fi
    if ! mv -f "$__hermes_safe_tmp" "$__hermes_safe_file"; then
        rm -f "$__hermes_safe_tmp"
        return 96
    fi
}}
__hermes_safe_capture'''


def _build_apply_script(quoted_state: str) -> str:
    names = " ".join(shlex.quote(name) for name in SAFE_STATE_NAMES)
    return f'''__hermes_safe_apply() {{
    [ "$__hermes_safe_codec" = 1 ] || return 97
    local __hermes_safe_file={quoted_state}
    [ -f "$__hermes_safe_file" ] && [ ! -L "$__hermes_safe_file" ] || return 93
    local __hermes_safe_size __hermes_safe_magic __hermes_safe_version
    local __hermes_safe_extra __hermes_safe_op __hermes_safe_name
    local __hermes_safe_encoded __hermes_safe_decoded __hermes_safe_canonical
    local __hermes_safe_expected __hermes_safe_index
    local -a __hermes_safe_names=({names})
    local -a __hermes_safe_ops __hermes_safe_values
    __hermes_safe_size=$(wc -c < "$__hermes_safe_file" | tr -d '[:space:]') || return 93
    case "$__hermes_safe_size" in ''|*[!0-9]*) return 93 ;; esac
    [ "$__hermes_safe_size" -le {SAFE_STATE_MAX_FILE_BYTES} ] || return 93
    exec 3< "$__hermes_safe_file" || return 93
    IFS=$'\\t' read -r __hermes_safe_magic __hermes_safe_version \
        __hermes_safe_extra <&3 || {{ exec 3<&-; return 93; }}
    if [ "$__hermes_safe_magic" != HERMES_SAFE_TERMINAL_STATE ] \
       || [ "$__hermes_safe_version" != {SAFE_STATE_VERSION} ] \
       || [ -n "$__hermes_safe_extra" ]; then
        exec 3<&-
        return 93
    fi
    for ((__hermes_safe_index=0; \
          __hermes_safe_index < ${{#__hermes_safe_names[@]}}; \
          __hermes_safe_index++)); do
        __hermes_safe_expected="${{__hermes_safe_names[$__hermes_safe_index]}}"
        IFS=$'\\t' read -r __hermes_safe_op __hermes_safe_name \
            __hermes_safe_encoded __hermes_safe_extra <&3 \
            || {{ exec 3<&-; return 93; }}
        [ "$__hermes_safe_name" = "$__hermes_safe_expected" ] \
            || {{ exec 3<&-; return 93; }}
        if [ "$__hermes_safe_op" = UNSET ]; then
            [ -z "$__hermes_safe_encoded" ] \
                && [ -z "$__hermes_safe_extra" ] \
                || {{ exec 3<&-; return 93; }}
            __hermes_safe_ops[$__hermes_safe_index]=UNSET
            __hermes_safe_values[$__hermes_safe_index]=
        elif [ "$__hermes_safe_op" = SET ]; then
            [ -z "$__hermes_safe_extra" ] || {{ exec 3<&-; return 93; }}
            __hermes_safe_decoded=$(__hermes_safe_decode \
                "$__hermes_safe_encoded") || {{ exec 3<&-; return 93; }}
            __hermes_safe_canonical=$(__hermes_safe_encode \
                "$__hermes_safe_decoded") || {{ exec 3<&-; return 93; }}
            [ "$__hermes_safe_canonical" = "$__hermes_safe_encoded" ] \
                || {{ exec 3<&-; return 93; }}
            __hermes_safe_validate_value "$__hermes_safe_expected" \
                "$__hermes_safe_decoded" || {{ exec 3<&-; return 93; }}
            __hermes_safe_ops[$__hermes_safe_index]=SET
            __hermes_safe_values[$__hermes_safe_index]="$__hermes_safe_decoded"
        else
            exec 3<&-
            return 93
        fi
    done
    if IFS= read -r __hermes_safe_extra <&3; then
        exec 3<&-
        return 93
    fi
    exec 3<&-
    for ((__hermes_safe_index=0; \
          __hermes_safe_index < ${{#__hermes_safe_names[@]}}; \
          __hermes_safe_index++)); do
        __hermes_safe_expected="${{__hermes_safe_names[$__hermes_safe_index]}}"
        if [ "${{__hermes_safe_ops[$__hermes_safe_index]}}" = SET ]; then
            export "$__hermes_safe_expected=${{__hermes_safe_values[$__hermes_safe_index]}}"
        else
            unset "$__hermes_safe_expected"
        fi
    done
}}
__hermes_safe_apply'''


def _compact_shell_script(script: str) -> str:
    compact = "\n".join(
        line.strip() for line in script.splitlines() if line.strip()
    )
    return compact.replace("__hermes_safe_", "_hss_")


def build_safe_state_shell_scripts(
    state_path: str,
    temp_template: str,
    *,
    platform: SafeStatePlatform,
) -> SafeStateShellScripts:
    platform = _validate_platform(platform)
    quoted_state = shlex.quote(state_path)
    quoted_temp = shlex.quote(temp_template)
    return SafeStateShellScripts(
        probe=_compact_shell_script(_build_codec_probe_script(platform)),
        apply=_compact_shell_script(_build_apply_script(quoted_state)),
        capture=_compact_shell_script(
            _build_capture_script(quoted_state, quoted_temp)
        ),
    )
