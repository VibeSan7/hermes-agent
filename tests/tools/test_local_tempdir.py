import os
import time
from pathlib import Path
from unittest.mock import patch

from tools.environments import local
from tools.environments.local import LocalEnvironment


class TestLocalTempDir:
    def test_posix_ignores_shared_tmpdir_and_uses_private_hermes_cache(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(local, "_IS_WINDOWS", False)
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
        monkeypatch.setenv("TMPDIR", "/data/data/com.termux/files/usr/tmp")

        with patch.object(LocalEnvironment, "init_session", autospec=True, return_value=None):
            env = LocalEnvironment(cwd=str(tmp_path), timeout=10)

        expected = tmp_path / "hermes-home" / "cache" / "terminal"
        assert Path(env.get_temp_dir()) == expected
        assert Path(env._safe_state_path).parent == expected
        assert env._safe_state_path.endswith(".v1")

    def test_missing_tmp_variables_do_not_change_private_cache(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(local, "_IS_WINDOWS", False)
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))
        monkeypatch.delenv("TMPDIR", raising=False)
        monkeypatch.delenv("TMP", raising=False)
        monkeypatch.delenv("TEMP", raising=False)

        with patch.object(LocalEnvironment, "init_session", autospec=True, return_value=None):
            env = LocalEnvironment(cwd=str(tmp_path), timeout=10)

        expected = tmp_path / "hermes-home" / "cache" / "terminal"
        assert Path(env.get_temp_dir()) == expected
        assert Path(env._safe_state_path).parent == expected

    def test_windows_uses_private_hermes_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr(local, "_IS_WINDOWS", True)
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes-home"))

        with patch.object(LocalEnvironment, "init_session", autospec=True, return_value=None):
            env = LocalEnvironment(cwd=str(tmp_path), timeout=10)

        expected = tmp_path / "hermes-home" / "cache" / "terminal"
        assert Path(env.get_temp_dir()) == expected
        assert Path(env._safe_state_path).parent == expected
        assert env._safe_state_path.endswith(".v1")

    def test_prunes_only_stale_known_state_artifacts(self, tmp_path, monkeypatch):
        home = tmp_path / "hermes-home"
        cache = home / "cache" / "terminal"
        cache.mkdir(parents=True)
        monkeypatch.setenv("HERMES_HOME", str(home))

        old_files = [
            cache / "hermes-snap-old.sh",
            cache / "hermes-safe-state-old.v1",
            cache / "hermes-safe-state-old.v1.tmp.deadbeef",
        ]
        for path in old_files:
            path.write_text("synthetic", encoding="utf-8")
            os.utime(path, (1, 1))
        fresh = cache / "hermes-safe-state-fresh.v1"
        fresh.write_text("synthetic", encoding="utf-8")
        now = time.time()
        os.utime(fresh, (now, now))

        with patch.object(LocalEnvironment, "init_session", autospec=True, return_value=None):
            LocalEnvironment(cwd=str(tmp_path), timeout=10)

        assert all(not path.exists() for path in old_files)
        assert fresh.exists()
