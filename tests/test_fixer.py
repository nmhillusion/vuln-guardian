# tests/test_fixer.py
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.fixer import apply_fix, _agent_label
from src.models import Vulnerability
from src.config import Config


def _make_config(**overrides):
    kwargs = dict(
        org="test-org",
        clone_dir=".repos",
        report_path="report.html",
        github_pat="ghp_test",
        ai_agent_args=["kilo", "run", "--auto", "{prompt}"],
    )
    kwargs.update(overrides)
    return Config(**kwargs)


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


def test_apply_fix_agent_fails(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        result = apply_fix(config, tmp_path, vuln)
        assert result is False


def test_apply_fix_npm_project_gets_lockfile_rule(tmp_path):
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "package.json").write_text("{}", encoding="utf-8")
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    agent_call = next(
        c for c in mock_run.call_args_list if c.args[0][0] == config.ai_agent_args[0]
    )
    prompt = agent_call.args[0][config.ai_agent_args.index("{prompt}")]
    assert "delete the affected package-lock.json" in prompt


def test_apply_fix_non_npm_project_no_lockfile_rule(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    agent_call = next(
        c for c in mock_run.call_args_list if c.args[0][0] == config.ai_agent_args[0]
    )
    prompt = agent_call.args[0][config.ai_agent_args.index("{prompt}")]
    assert "delete the affected package-lock.json" not in prompt


def test_apply_fix_custom_agent_template(tmp_path):
    config = _make_config(ai_agent_args=["gemini", "-p", "{prompt}"])
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    agent_call = next(
        c for c in mock_run.call_args_list if c.args[0][0] == "gemini"
    )
    cmd = agent_call.args[0]
    assert cmd[0] == "gemini"
    assert cmd[1] == "-p"
    assert "Fix security vulnerability GHSA-test-1234" in cmd[2]


def test_apply_fix_model_placeholder_pinned(tmp_path):
    config = _make_config(
        ai_agent_args=["kilo", "run", "--auto", "-m", "{model}", "{prompt}"],
        ai_agent_model="anthropic/claude-opus",
    )
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    cmd = mock_run.call_args_list[0].args[0]
    assert cmd[:5] == ["kilo", "run", "--auto", "-m", "anthropic/claude-opus"]
    assert "Fix security vulnerability GHSA-test-1234" in cmd[5]


def test_apply_fix_model_placeholder_empty_drops_flag(tmp_path):
    config = _make_config(
        ai_agent_args=["kilo", "run", "--auto", "-m", "{model}", "{prompt}"],
        ai_agent_model="",
    )
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    cmd = mock_run.call_args_list[0].args[0]
    assert "-m" not in cmd
    assert "{model}" not in cmd
    assert "Fix security vulnerability GHSA-test-1234" in cmd[3]


def test_agent_label_prefers_configured_model():
    assert _agent_label(["kilo", "run", "{prompt}"], "x/y") == "kilo (x/y)"
    assert _agent_label(["kilo", "run", "-m", "{model}", "{prompt}"], "") == "kilo (default)"
    assert _agent_label(["kilo", "run", "-m", "a/b", "{prompt}"], "") == "kilo (a/b)"
