import base64

import pytest

from tools.environments.safe_terminal_state import (
    SAFE_STATE_HEADER,
    SAFE_STATE_MAX_FILE_BYTES,
    SAFE_STATE_NAMES,
    SAFE_STATE_PASSTHROUGH_ENV,
    SafeStateError,
    decode_safe_state,
    encode_safe_state,
    validate_safe_value,
)


EXPECTED_NAMES = (
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


def test_allowlist_is_exact_and_ordered():
    assert SAFE_STATE_NAMES == EXPECTED_NAMES
    assert SAFE_STATE_HEADER == "HERMES_SAFE_TERMINAL_STATE\t1"
    assert SAFE_STATE_MAX_FILE_BYTES == 65_536


def test_passthrough_marker_is_fixed_and_contains_no_value():
    assert SAFE_STATE_PASSTHROUGH_ENV == "HERMES_SAFE_STATE_PASSTHROUGH_ACTIVE"


def test_round_trip_emits_one_record_per_name():
    payload = encode_safe_state(
        {
            "PATH": "/opt/app/.venv/bin:/usr/bin",
            "VIRTUAL_ENV": "/opt/app/.venv",
        },
        platform="posix",
    )

    state = decode_safe_state(payload, platform="posix")
    records = dict(state.records)

    assert records["PATH"] == "/opt/app/.venv/bin:/usr/bin"
    assert records["VIRTUAL_ENV"] == "/opt/app/.venv"
    assert records["CONDA_PREFIX"] is None
    assert state.records[0][0] == "PATH"
    assert state.records[0] == ("PATH", "/opt/app/.venv/bin:/usr/bin")
    assert payload.count(b"\n") == len(EXPECTED_NAMES) + 1
    assert payload.endswith(b"\n")


@pytest.mark.parametrize(
    "name",
    ["SERVICE_TOKEN", "DATABASE_URL", "ORDINARY_SETTING", "PATH_EXTRA"],
)
def test_unknown_name_is_rejected(name):
    with pytest.raises(SafeStateError, match="unknown_name"):
        encode_safe_state({name: "synthetic"}, platform="posix")


@pytest.mark.parametrize(
    "value",
    ["line1\nline2", "carriage\rreturn", "tab\tvalue", "nul\x00value", "bell\x07value"],
)
def test_control_characters_are_rejected(value):
    with pytest.raises(SafeStateError, match="control_character"):
        validate_safe_value("VIRTUAL_ENV", value, platform="posix")


def test_encoder_turns_invalid_allowed_value_into_unset():
    payload = encode_safe_state(
        {
            "PATH": "/usr/bin:/bin",
            "VIRTUAL_ENV": "line1\nline2",
        },
        platform="posix",
    )

    assert b"UNSET\tVIRTUAL_ENV\n" in payload
    assert dict(decode_safe_state(payload, platform="posix").records)["VIRTUAL_ENV"] is None


@pytest.mark.parametrize(
    "value",
    ["https://example.test/bin:/usr/bin", "relative/bin:/usr/bin", ":/usr/bin"],
)
def test_posix_path_list_rejects_uri_relative_and_empty_entries(value):
    with pytest.raises(SafeStateError, match="path_"):
        validate_safe_value("PATH", value, platform="posix")


def test_posix_paths_are_accepted():
    assert validate_safe_value(
        "PATH", "/opt/app/.venv/bin:/usr/local/bin:/usr/bin", platform="posix"
    ) == "/opt/app/.venv/bin:/usr/local/bin:/usr/bin"
    assert validate_safe_value(
        "VIRTUAL_ENV", "/opt/app/.venv", platform="posix"
    ) == "/opt/app/.venv"


def test_msys_and_native_windows_paths_are_accepted():
    assert validate_safe_value(
        "PATH", "/c/Project/.venv/Scripts:/usr/bin", platform="msys"
    ) == "/c/Project/.venv/Scripts:/usr/bin"
    assert validate_safe_value(
        "PATH", r"C:\Project\.venv\Scripts;C:\Windows\System32", platform="msys"
    ) == r"C:\Project\.venv\Scripts;C:\Windows\System32"
    assert validate_safe_value(
        "VIRTUAL_ENV", r"C:\Project\.venv", platform="msys"
    ) == r"C:\Project\.venv"
    mixed = r"C:\Project\.venv/Scripts:/usr/bin:/bin"
    assert validate_safe_value("PATH", mixed, platform="msys") == mixed


def test_msys_drive_prefixed_colon_list_rejects_relative_tail():
    with pytest.raises(SafeStateError, match="path_not_absolute"):
        validate_safe_value("PATH", "C:/safe:relative", platform="msys")
    with pytest.raises(SafeStateError, match="path_not_absolute"):
        validate_safe_value("PATH", "É:/usr/bin:/bin", platform="msys")
    with pytest.raises(SafeStateError, match="path_mixed_separator"):
        validate_safe_value("PATH", "/usr/bin:relative;/bin", platform="msys")


@pytest.mark.parametrize("value", ["-1", "100", "not-a-number", "1.0", ""])
def test_conda_shlvl_rejects_invalid_values(value):
    with pytest.raises(SafeStateError, match="conda_shlvl"):
        validate_safe_value("CONDA_SHLVL", value, platform="posix")


@pytest.mark.parametrize("value", ["0", "1", "99"])
def test_conda_shlvl_accepts_range(value):
    assert validate_safe_value("CONDA_SHLVL", value, platform="posix") == value


def test_empty_non_path_marker_is_allowed():
    payload = encode_safe_state(
        {"PATH": "/usr/bin:/bin", "_CE_M": ""},
        platform="posix",
    )
    assert dict(decode_safe_state(payload, platform="posix").records)["_CE_M"] == ""


def test_path_and_other_value_size_limits():
    with pytest.raises(SafeStateError, match="path_too_large"):
        validate_safe_value("PATH", "/" + "a" * 32_768, platform="posix")
    with pytest.raises(SafeStateError, match="value_too_large"):
        validate_safe_value("CONDA_DEFAULT_ENV", "a" * 4_097, platform="posix")


def _set_line(name: str, value: bytes) -> bytes:
    encoded = base64.b64encode(value)
    return b"SET\t" + name.encode("ascii") + b"\t" + encoded + b"\n"


def _valid_payload() -> bytes:
    return encode_safe_state(
        {"PATH": "/usr/bin:/bin", "VIRTUAL_ENV": "/workspace/.venv"},
        platform="posix",
    )


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (lambda p: p.replace(b"HERMES_SAFE_TERMINAL_STATE\t1", b"WRONG\t1", 1), "header"),
        (lambda p: p.rsplit(b"\n", 2)[0] + b"\n", "record_set"),
        (
            lambda p: p.replace(b"UNSET\tCONDA_PREFIX\n", b"UNSET\tPATH\n", 1),
            "record_set",
        ),
        (
            lambda p: p.replace(b"UNSET\tCONDA_PREFIX\n", b"UNSET\tUNKNOWN\n", 1),
            "record_set",
        ),
        (lambda p: p + b"UNSET\tPATH\n", "record_set"),
        (
            lambda p: p.replace(b"UNSET\tCONDA_PREFIX\n", b"SET\tCONDA_PREFIX\n", 1),
            "record_shape",
        ),
        (
            lambda p: p.replace(b"UNSET\tCONDA_PREFIX\n", b"SET\tCONDA_PREFIX\t***\n", 1),
            "base64",
        ),
        (lambda p: p[:-1], "newline"),
    ],
)
def test_malformed_payload_rejects_whole_file(mutator, reason):
    with pytest.raises(SafeStateError, match=reason):
        decode_safe_state(mutator(_valid_payload()), platform="posix")


def test_noncanonical_base64_is_rejected():
    payload = _valid_payload().replace(
        _set_line("VIRTUAL_ENV", b"/workspace/.venv"),
        b"SET\tVIRTUAL_ENV\tL3dvcmtzcGFjZS8udmVudg\n",
    )
    with pytest.raises(SafeStateError, match="base64"):
        decode_safe_state(payload, platform="posix")


def test_invalid_utf8_is_rejected():
    payload = _valid_payload().replace(
        _set_line("VIRTUAL_ENV", b"/workspace/.venv"),
        _set_line("VIRTUAL_ENV", b"\xff"),
    )
    with pytest.raises(SafeStateError, match="utf8"):
        decode_safe_state(payload, platform="posix")


def test_invalid_decoded_value_rejects_whole_file():
    payload = _valid_payload().replace(
        _set_line("VIRTUAL_ENV", b"/workspace/.venv"),
        _set_line("VIRTUAL_ENV", b"line1\nline2"),
    )
    with pytest.raises(SafeStateError, match="control_character"):
        decode_safe_state(payload, platform="posix")


def test_total_file_size_limit_is_enforced_before_decode():
    with pytest.raises(SafeStateError, match="file_too_large"):
        decode_safe_state(b"x" * (SAFE_STATE_MAX_FILE_BYTES + 1), platform="posix")
