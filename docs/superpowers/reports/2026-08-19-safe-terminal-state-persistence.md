# Safe Terminal State Persistence — Implementation Report

Date: 2026-08-19
Status: **review-ready after owner-approved fail-closed amendment; not deployed**

## 1. Review scope

- Hermes source worktree: `safe-terminal-state-persistence`
- Clean implementation base: `13ce0c5c6`
- Tasks 1–6 head: `7419a8ae14c725c00b9fa1472c46c86eda943461`
- Task 7 changes are the final report/tests/preflight hardening commit on top of that head.
- Approved specification: `C:\Users\Vladislav\projects\altron-hermes-guard\docs\superpowers\specs\2026-08-19-terminal-state-safe-allowlist-design.md`
- Approved implementation plan: `C:\Users\Vladislav\projects\altron-hermes-guard\docs\superpowers\plans\2026-08-19-safe-terminal-state-persistence.md`

This range contains code and tests only. It does not deploy to the live Hermes checkout, delete live legacy files, restart Desktop/gateway, or rotate credentials.

## 2. Task commits

| Task | Commit | Purpose |
|---|---|---|
| 1 | `478dbbed1` | Immutable allowlist, value policy, and versioned data format |
| 2 | `79caa5512` | Non-executable Bash codec and atomic publication |
| 3 | `3d072506d` | Replace full-environment Base snapshots |
| 4 | `0b70a04b6` | Local private cache, Windows ACL/identity checks, real venv behavior |
| 5 | `8732422df` | Invocation-local Docker profile credentials and unsets |
| 6 | `7419a8ae1` | Default-off unsupported backend gate and user documentation |

## 3. Implemented policy

The only persisted environment names are:

```text
PATH
VIRTUAL_ENV
CONDA_PREFIX
CONDA_DEFAULT_ENV
CONDA_SHLVL
CONDA_EXE
CONDA_PYTHON_EXE
_CE_CONDA
_CE_M
```

The state file is versioned data, not a shell script. It is never sourced or evaluated. Config, skills, plugins, provider registries, and passthrough configuration cannot widen the allowlist.

Backend behavior:

| Backend | Credential-free single-profile v1 state | Passthrough / multiplex state | Credential handling |
|---|---|---|---|
| Local | Enabled after private-path, identity, ACL/mode, codec checks | Permanently off for the environment object before apply/capture | Fresh subprocess environment per invocation |
| Docker | Off | Off | Profile values/unsets remain invocation-local; command and filesystem persistence are separate |
| SSH | Off | Off | Existing invocation path; no terminal env persistence |
| Singularity | Off | Off | Existing invocation path; no terminal env persistence |
| Modal (direct and managed) | Off | Off | Existing transport/filesystem lifecycle; no Hermes terminal env persistence |
| Daytona | Off | Off | Existing invocation path; no terminal env persistence |
| Vercel Sandbox | Off | Off | Existing invocation path; no terminal env persistence |
| New/unclassified Base backend | Off by default | Off | Must explicitly prove the v1 contract before opt-in |

The owner-approved 2026-08-20 amendment removes transformed-credential detection entirely. A fixed value-free marker (`HERMES_SAFE_STATE_PASSTHROUGH_ACTIVE=1`) makes probe return `98`, so any invocation that actually receives a passthrough value runs without applying or capturing terminal environment state. Any nonzero user-command result likewise preserves its result and permanently disables persistence for that environment object.

Filesystem/container snapshots used by Modal, Singularity, Daytona, and Vercel are separate product features. They do not authorize terminal environment serialization.

## 4. Requirement-to-test matrix

| Security requirement / acceptance criterion | Exact test evidence |
|---|---|
| Exact immutable allowlist | `tests/tools/test_safe_terminal_state.py::test_allowlist_is_exact_and_ordered` |
| Exactly one SET/UNSET record per allowed name | `tests/tools/test_safe_terminal_state.py::test_round_trip_emits_one_record_per_name` |
| Unknown/arbitrary names rejected | `tests/tools/test_safe_terminal_state.py::test_unknown_name_is_rejected` |
| Control characters, invalid UTF-8, noncanonical Base64, invalid values rejected | `tests/tools/test_safe_terminal_state.py::test_control_characters_are_rejected`, `::test_invalid_utf8_is_rejected`, `::test_noncanonical_base64_is_rejected`, `::test_invalid_decoded_value_rejects_whole_file` |
| PATH and marker size/range/path validation | `tests/tools/test_safe_terminal_state.py::test_path_and_other_value_size_limits`, `::test_conda_shlvl_rejects_invalid_values`, `::test_posix_path_list_rejects_uri_relative_and_empty_entries`, `::test_msys_and_native_windows_paths_are_accepted` |
| Python/runtime MSYS parser parity rejects non-ASCII drive letters | `tests/tools/test_safe_terminal_state.py::test_msys_drive_prefixed_colon_list_rejects_relative_tail`, `tests/tools/test_safe_terminal_state_shell.py::test_runtime_parser_rejects_drive_prefixed_colon_path_list` |
| No full environment dump | `tests/tools/test_safe_terminal_state_shell.py::test_generated_scripts_never_execute_or_dump_environment`, `tests/tools/test_base_environment.py::TestSafeTerminalStateContract::test_init_session_never_builds_full_environment_dump` |
| State contents treated only as data | `tests/tools/test_safe_terminal_state_shell.py::test_apply_treats_encoded_value_as_data_not_shell_code` |
| Whole malformed state rejected; no partial apply | `tests/tools/test_safe_terminal_state_shell.py::test_malformed_extra_line_rejects_whole_file_without_partial_apply`, `tests/tools/test_safe_terminal_state.py::test_malformed_payload_rejects_whole_file` |
| Arbitrary exports omitted | `tests/tools/test_safe_terminal_state_shell.py::test_capture_and_apply_round_trip_drops_unknown_exports`, `tests/tools/test_safe_terminal_state_integration.py::test_python_venv_state_persists_but_arbitrary_exports_do_not` |
| Credential omission | `tests/tools/test_safe_terminal_state_integration.py::test_ten_synthetic_credentials_never_enter_safe_state` |
| Malformed config cannot widen policy | `tests/tools/test_safe_terminal_state_integration.py::test_malformed_config_cannot_widen_persistence` |
| Python venv activation persists | `tests/tools/test_safe_terminal_state_integration.py::test_python_venv_state_persists_but_arbitrary_exports_do_not` |
| Venv deactivation clears stale state and PATH | `tests/tools/test_safe_terminal_state_integration.py::test_deactivate_clears_stale_venv_and_path`, `tests/tools/test_safe_terminal_state_shell.py::test_second_capture_emits_unset_and_clears_stale_venv` |
| Conda markers persist and deactivate | `tests/tools/test_safe_terminal_state_integration.py::test_conda_markers_persist_and_deactivate` |
| Multiplex mode writes/applies no state | `tests/tools/test_base_environment.py::TestSafeTerminalStateContract::test_multiplex_mode_disables_state_before_bootstrap`, `tests/tools/test_docker_environment.py::test_multiplexed_docker_init_never_starts_safe_state` |
| Credential-bearing invocation disables state host-side before shell startup/apply/capture | `tests/tools/test_safe_terminal_state_integration.py::test_forwarded_passthrough_disables_safe_state_permanently`, `::test_shell_startup_cannot_bypass_host_passthrough_shutdown`, `::test_passthrough_marker_contains_no_credential_and_cannot_persist` |
| Unforwarded scope values set no persistence-off marker | `tests/tools/test_safe_terminal_state_integration.py::test_unforwarded_scoped_value_does_not_set_passthrough_marker` |
| Nonzero user command preserves result and disables state | `tests/tools/test_safe_terminal_state_integration.py::test_user_failure_exit_code_survives_state_capture`, `::test_set_e_user_failure_disables_unobserved_stale_state`, `::test_failed_command_cannot_keep_state_ready_with_fake_cwd_marker` |
| Successful early exit must produce a new Local state-file revision | `tests/tools/test_safe_terminal_state_integration.py::test_zero_exit_fake_cwd_marker_cannot_hide_missing_capture` |
| Startup hooks disable state host-side and inherited `set -e` cannot suppress the command | `tests/tools/test_safe_terminal_state_integration.py::test_shell_startup_env_disables_persistence_host_side`, `::test_shell_startup_inputs_disable_persistence`, `::test_inherited_errexit_startup_disables_before_apply_and_runs_command` |
| Host preflight and Bash spawn consume one exact invocation-local env; failure clears stale env | `tests/tools/test_safe_terminal_state_integration.py::test_preflight_and_popen_use_same_run_env`, `::test_preflight_failure_clears_stale_prepared_run_env` |
| Inline stdin safely frames trailing comments | `tests/tools/test_safe_terminal_state_integration.py::test_local_inline_stdin_accepts_trailing_comment` |
| Capture flattens exported strings and is independent of post-command `declare`/`builtin`/`printf` | `tests/tools/test_safe_terminal_state_shell.py::test_capture_flattens_exported_values_and_ignores_printf_shadow`, `::test_capture_uses_exported_value_when_declare_is_disabled`, `::test_capture_ignores_builtin_function_shadow`, `::test_capture_uses_exported_value_when_builtin_is_disabled` |
| Docker missing-handle recovery is controlled and cannot re-enable permanent-off state | `tests/tools/test_docker_environment.py::test_execute_recreates_missing_container_before_base_execute`, `::test_recovery_cannot_reenable_permanently_disabled_state` |
| Docker long wrappers use stdin transport | `tests/tools/test_docker_environment.py::test_docker_run_bash_transports_long_script_over_stdin` |
| Profile credentials remain invocation-local | `tests/tools/test_docker_environment.py::test_wrapped_exec_scopes_explicit_forward_env_across_profiles`, `::test_runtime_exec_tracks_scope_and_clears_missing_value`, `tests/tools/test_env_passthrough.py::TestProfileScopedResolution` |
| Docker concurrent login decisions do not race through shared fields | `tests/tools/test_docker_environment.py::test_concurrent_login_invocations_keep_unsets_local` |
| Resolver/import failure fails closed | `tests/tools/test_docker_environment.py::test_passthrough_import_failure_unsets_multiplex_secret`, `tests/tools/test_env_passthrough.py::TestTerminalIntegration::test_provider_blocklist_import_failure_fails_closed` |
| Docker and managed Modal safe state are explicitly unsupported | `tests/tools/test_docker_environment.py::test_single_profile_docker_safe_state_is_unsupported`, `tests/tools/test_managed_modal_environment.py::test_managed_modal_explicitly_disables_safe_state` |
| Unsupported and unclassified backends remain off but commands run | `tests/tools/test_safe_terminal_state_backends.py::test_unclassified_backend_defaults_to_persistence_off`, `::test_unsupported_backend_disables_state_and_still_executes` |
| Codec failure creates no state | `tests/tools/test_safe_terminal_state_shell.py::test_codec_probe_failure_creates_no_state_file` |
| Malformed state disables persistence but user command continues | `tests/tools/test_safe_terminal_state_integration.py::test_malformed_state_fails_closed_but_command_still_runs` |
| User command failure exit code is preserved | `tests/tools/test_safe_terminal_state_integration.py::test_user_failure_exit_code_survives_state_capture` |
| Atomic publication and complete old-or-new reads | `tests/tools/test_safe_terminal_state_shell.py::test_concurrent_writers_publish_only_complete_old_or_new_state`, `::test_failed_atomic_publish_keeps_previous_complete_state` |
| Unique temp names; no PID collision | `tests/tools/test_base_environment.py::TestAtomicSafeStateWrite::test_temp_path_uses_mktemp_not_pid_variables` |
| New process does not reuse prior random state path | `tests/tools/test_safe_terminal_state_integration.py::test_new_environment_never_reuses_previous_state_path` |
| Hardlinks rejected | `tests/tools/test_safe_terminal_state_integration.py::test_hardlinked_state_artifact_is_rejected` |
| Symlink/reparse points rejected with real Windows junction fallback | `tests/tools/test_safe_terminal_state_integration.py::test_reparse_or_symlink_state_artifact_is_rejected` |
| Insecure pre-existing Windows target rejected before bootstrap/replacement | `tests/tools/test_safe_terminal_state_integration.py::test_windows_insecure_preexisting_target_is_rejected_before_bootstrap` |
| Explicit restricted Windows file ACL | `tests/tools/test_safe_terminal_state_integration.py::test_windows_state_acl_is_explicit_and_restricted` |
| POSIX directory/file modes and unchanged user umask | `tests/tools/test_safe_terminal_state_integration.py::test_posix_state_modes_are_private_without_changing_user_umask` (POSIX lane) |
| Legacy executable snapshot is never referenced | `tests/tools/test_base_environment.py::TestSafeTerminalStateContract::test_legacy_snapshot_file_is_never_referenced` |
| Stale known legacy files deleted without touching fresh state | `tests/tools/test_local_tempdir.py::TestLocalTempDir::test_prunes_only_stale_known_state_artifacts` |
| Session IDs and multiline session values cannot enter/execute through state | `tests/tools/test_snapshot_session_id_leak.py`, `tests/tools/test_snapshot_multiline_session_env_injection.py` |
| Failure warnings are value-free and rate-limited | `tests/tools/test_base_environment.py::TestSafeTerminalStateContract::test_disable_safe_state_warns_once_without_values` |

## 5. RED evidence

The implementation followed TDD checkpoints. Representative failures before production changes:

- Task 1: `ModuleNotFoundError` for the absent safe-state policy module.
- Task 2: missing shell-script builder; then a real Windows `bash -c` truncation failure at approximately 12.6 KiB.
- Task 3: seven Base contract failures for absent safe-state fields/methods and legacy source/dump behavior.
- Task 4: real Local venv persistence failure (`capture_94`) and missing hardlink/ACL artifact hook.
- Task 5: three failures proving list-only login builder, process-env fallback on resolver import failure, and shared unset race.
- Task 6: five failures showing unsupported adapters attempted state bootstrap; one failure showing an unclassified backend defaulted on.
- Task 7: Windows permissive pre-existing target reached Bash bootstrap before ACL preflight.

## 6. Fresh verification evidence

### Canonical security/backend suite

```text
scripts/run_tests.sh -j 4 <13 focused test files> -q
272 passed, 0 failed, 6 skipped
```

The six skips are explicit platform lanes (`linux_only`/POSIX contracts) on the native Windows host. Windows ACL, owner, reparse/junction, MSYS transport, and explicit-empty stdin tests ran on their real host.

A separate 12-file Local baseline sweep produced `148 passed, 11 failed, 8 skipped`. The failures are outside the changed code: three stale full-snapshot expectations that contradict the new default-deny contract, three Windows `HOME`/native-path portability assumptions, two POSIX process-group tests on Windows, one existing background-child pipe-hang case, and two cwd/platform expectations. They are reported rather than counted as green or silently waived.

### Docker/Modal off-contract and command evidence

- Docker and managed Modal explicitly advertise `_safe_state_persistence_supported = False`; their tests prove no bootstrap/state file is attempted.
- A 40,067-character Docker command transported through stdin returned the exact user payload with exit code 0; command execution remains available without terminal env persistence.
- Docker recovery keeps a previously disabled reason and cannot re-enable persistence on the same environment object.
- Local safe-state Bash snippets parsed byte-exactly under host Git Bash and real Docker Bash 3.2.

### Static/security gates

- Ruff: passed on every changed Python file.
- Python `py_compile`: passed on every changed Python file.
- `git diff --check`: passed.
- Gitleaks raw live diff scan: zero findings.
- Product search: zero `export -p` / `declare -x` persistence paths; no `_snapshot_path`, `_snapshot_ready`, hash/Base64 credential metadata, or legacy state reads. The only `hermes-snap-*` product reference is delete-only stale cleanup.

### Documentation

```text
npm run build:fast: passed
```

Docusaurus reported two pre-existing broken links from `/docs/` to `/docs/llms.txt` and `/docs/llms-full.txt`; neither is in the changed pages.

## 7. Review focus

The independent reviewer should specifically inspect:

1. Whether any path can serialize a full environment or execute state contents.
2. Whether Python host-side passthrough preflight disables Local state before any Bash startup file can mutate shell gates.
3. Whether nonzero commands or zero-exit early termination can leave stale state reusable despite the Local artifact-revision check.
4. Whether Local ACL/owner/reparse/hardlink checks and capture transport failures fail closed without values in logs.
5. Whether Docker profile values/unsets, recovery, long wrapper/user stdin, and filesystem persistence remain functional while env persistence stays unsupported.
6. Whether Docker, direct/managed Modal, and every unsupported backend can enter the safe-state bootstrap/apply/capture path.

Any Critical or Important finding blocks deployment.

## 8. Deployment boundary

No live deployment is authorized by this report. After and only after independent review returns `deployment_safe: YES`, a separate owner-approved ceremony must:

1. close Desktop and stop the gateway;
2. apply the reviewed commit range to the live checkout;
3. remove legacy plaintext terminal snapshots while the runtime is stopped;
4. restart and prove new files contain only valid allowlisted records and zero current credentials;
5. rotate Context7, Linkup, Serper, and You credentials provider-by-provider;
6. preserve rollback evidence without preserving plaintext secret values.
