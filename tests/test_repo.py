# tests/test_repo.py
import subprocess
from pathlib import Path
import pytest
from unittest.mock import patch, MagicMock
from src.repo import clone_or_update, detect_default_branch, update_default_branch, branch_exists, create_branch, checkout


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
        assert mock_run.call_count == 3


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


def test_clone_or_update_rejects_dot_segment_traversal(tmp_path):
    traversal_names = [
        "evilorg/..",
        "evilorg/../",
        "evilorg/../../outside",
        "..",
        "../outside",
        "evilorg/%2e%2e",
        "evilorg/%2e%2e%2f",
        "evilorg/%2E%2E",
        "evilorg/%2e./",
        "%2e%2e/evilorg",
    ]
    for bad in traversal_names:
        with pytest.raises(ValueError):
            clone_or_update(str(tmp_path), bad)


def test_clone_or_update_rejects_malformed_names(tmp_path):
    malformed = [
        "",
        "noorganization",
        "/leading/slash",
        "owner/repo/extra",
        "owner//repo",
        "owner/",
        "owner/ repo",
    ]
    for bad in malformed:
        with pytest.raises(ValueError):
            clone_or_update(str(tmp_path), bad)


def test_clone_or_update_no_subprocess_for_malicious_name(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with pytest.raises(ValueError):
            clone_or_update(str(tmp_path), "evilorg/..")
        mock_run.assert_not_called()


def test_update_default_branch_syncs_to_origin(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        update_default_branch(tmp_path, "main")
        assert mock_run.call_count == 3
        cmds = [c.args[0] for c in mock_run.call_args_list]
        assert cmds[0][-2:] == ["checkout", "main"]
        assert cmds[1][-4:] == ["fetch", "--prune", "origin", "main"]
        assert cmds[2][-3:] == ["reset", "--hard", "origin/main"]


def test_update_default_branch_fails_loudly(tmp_path):
    ok = MagicMock(returncode=0, stderr="")
    fail = MagicMock(returncode=1, stderr="fetch failed")
    with patch("subprocess.run", side_effect=[ok, fail]) as mock_run:
        with pytest.raises(RuntimeError, match="Failed to fetch"):
            update_default_branch(tmp_path, "main")
        assert mock_run.call_count == 2


def test_clone_or_update_prunes_deleted_branches(tmp_path):
    from src.repo import clone_or_update as _clone
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        _clone(str(tmp_path), "myorg/myrepo")
        cmds = [c.args[0] for c in mock_run.call_args_list]
        assert any(cmd[-3:] == ["fetch", "--all", "--prune"] for cmd in cmds)


def test_update_default_branch_prunes(tmp_path):
    from src.repo import update_default_branch as _update
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        _update(tmp_path, "main")
        cmds = [c.args[0] for c in mock_run.call_args_list]
        assert cmds[1][-4:] == ["fetch", "--prune", "origin", "main"]


def test_sync_prunes_stale_local_fix_branch(tmp_path):
    from src import repo as _repo
    with patch.object(_repo, "branch_exists", return_value=True), \
         patch.object(_repo, "remote_branch_exists", return_value=False), \
         patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert _repo.sync_prune_fix_branch(tmp_path, "fix/batch-abc123") is True
        cmds = [c.args[0] for c in mock_run.call_args_list]
        assert any(cmd[-3:] == ["branch", "-D", "fix/batch-abc123"] for cmd in cmds)


def test_sync_keeps_live_local_fix_branch(tmp_path):
    from src import repo as _repo
    with patch.object(_repo, "branch_exists", return_value=True), \
         patch.object(_repo, "remote_branch_exists", return_value=True), \
         patch("subprocess.run") as mock_run:
        assert _repo.sync_prune_fix_branch(tmp_path, "fix/batch-abc123") is False
        mock_run.assert_not_called()
