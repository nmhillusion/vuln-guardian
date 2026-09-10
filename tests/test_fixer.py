# tests/test_fixer.py
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.fixer import apply_fix
from src.models import Vulnerability
from src.config import Config


def _make_config():
    return Config(
        org="test-org",
        clone_dir=".repos",
        report_path="report.html",
        opencode_binary="opencode",
        github_pat="ghp_test",
    )


def _make_vuln():
    return Vulnerability(
        repo_full_name="test-org/repo1",
        advisory_id="GHSA-test-1234",
        severity="high",
        title="Test vulnerability",
        description="A test vuln",
        affected_files=["src/app.py"],
        package_name=None,
        source="ghsa",
        state="open",
    )


def test_apply_fix_success(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            result = apply_fix(config, tmp_path, vuln)
            assert result is True


def test_apply_fix_no_changes(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=False):
            result = apply_fix(config, tmp_path, vuln)
            assert result is False


def test_apply_fix_opencode_fails(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        result = apply_fix(config, tmp_path, vuln)
        assert result is False
