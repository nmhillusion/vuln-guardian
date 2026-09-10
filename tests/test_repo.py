# tests/test_repo.py
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.repo import clone_or_update, detect_default_branch, branch_exists, create_branch, checkout


def test_clone_or_update_clones_new_repo(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        result = clone_or_update(str(tmp_path), "myorg/myrepo")
        assert result == tmp_path / "myrepo"
        assert mock_run.call_count == 1
        assert "clone" in mock_run.call_args[0][0]


def test_clone_or_update_updates_existing(tmp_path):
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        result = clone_or_update(str(tmp_path), "myorg/myrepo")
        assert result == repo_dir
        assert mock_run.call_count == 2


def test_detect_default_branch_origin_head(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="origin/HEAD -> origin/main\n")
        branch = detect_default_branch(tmp_path)
        assert branch == "main"


def test_detect_default_branch_fallback(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        branch = detect_default_branch(tmp_path)
        assert branch in ("main", "master")


def test_branch_exists_true(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="  fix/GHSA-1234\n  main\n")
        assert branch_exists(tmp_path, "fix/GHSA-1234") is True


def test_branch_exists_false(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="  main\n")
        assert branch_exists(tmp_path, "fix/GHSA-1234") is False
