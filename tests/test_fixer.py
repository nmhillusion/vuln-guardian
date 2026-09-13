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


def _fake_proc(lines=("agent ok\n",), returncode=0):
    proc = MagicMock()
    proc.stdout = list(lines)
    proc.wait.return_value = returncode
    proc.returncode = returncode
    return proc


def test_apply_fix_success(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_popen.return_value = _fake_proc()
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            result = apply_fix(config, tmp_path, vuln)
            assert result is True


def test_apply_fix_no_changes(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_popen.return_value = _fake_proc()
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=False):
            result = apply_fix(config, tmp_path, vuln)
            assert result is False


def test_apply_fix_agent_fails(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.Popen") as mock_popen:
        mock_popen.return_value = _fake_proc(returncode=1)
        result = apply_fix(config, tmp_path, vuln)
        assert result is False


def test_apply_fix_npm_project_gets_lockfile_rule(tmp_path):
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "package.json").write_text("{}", encoding="utf-8")
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_popen.return_value = _fake_proc()
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    prompt = mock_popen.call_args.args[0][config.ai_agent_args.index("{prompt}")]
    assert "delete the affected package-lock.json" in prompt


def test_apply_fix_non_npm_project_no_lockfile_rule(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_popen.return_value = _fake_proc()
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    prompt = mock_popen.call_args.args[0][config.ai_agent_args.index("{prompt}")]
    assert "delete the affected package-lock.json" not in prompt


def test_apply_fix_custom_agent_template(tmp_path):
    config = _make_config(ai_agent_args=["gemini", "-p", "{prompt}"])
    vuln = _make_vuln()
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_popen.return_value = _fake_proc()
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    cmd = mock_popen.call_args.args[0]
    assert cmd[0] == "gemini"
    assert cmd[1] == "-p"
    assert "Fix security vulnerability GHSA-test-1234" in cmd[2]


def test_apply_fix_model_placeholder_pinned(tmp_path):
    config = _make_config(
        ai_agent_args=["kilo", "run", "--auto", "-m", "{model}", "{prompt}"],
        ai_agent_model="anthropic/claude-opus",
    )
    vuln = _make_vuln()
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_popen.return_value = _fake_proc()
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    cmd = mock_popen.call_args.args[0]
    assert cmd[:5] == ["kilo", "run", "--auto", "-m", "anthropic/claude-opus"]
    assert "Fix security vulnerability GHSA-test-1234" in cmd[5]


def test_apply_fix_model_placeholder_empty_drops_flag(tmp_path):
    config = _make_config(
        ai_agent_args=["kilo", "run", "--auto", "-m", "{model}", "{prompt}"],
        ai_agent_model="",
    )
    vuln = _make_vuln()
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_popen.return_value = _fake_proc()
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    cmd = mock_popen.call_args.args[0]
    assert "-m" not in cmd
    assert "{model}" not in cmd
    assert "Fix security vulnerability GHSA-test-1234" in cmd[3]


def test_agent_label_prefers_configured_model():
    assert _agent_label(["kilo", "run", "{prompt}"], "x/y") == "kilo (x/y)"
    assert _agent_label(["kilo", "run", "-m", "{model}", "{prompt}"], "") == "kilo (default)"
    assert _agent_label(["kilo", "run", "-m", "a/b", "{prompt}"], "") == "kilo (a/b)"


_MAVEN_POM = """<project>
    <dependencies>
        <dependency>
            <groupId>org.apache.calcite</groupId>
            <artifactId>calcite-core</artifactId>
            <version>1.41.0</version>
        </dependency>
    </dependencies>
</project>
"""


def _make_dep_vuln():
    v = _make_vuln()
    v.source = "dependabot"
    v.package_name = "org.apache.calcite:calcite-core"
    v.patched_version = "1.42.0"
    v.vulnerable_range = "< 1.42.0"
    v.manifest_path = "backend/pom.xml"
    v.dependency_relationship = "transitive"
    v.dependency_scope = "runtime"
    return v


def test_apply_fix_dependabot_snippet_and_suggestion(tmp_path):
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "pom.xml").write_text(_MAVEN_POM, encoding="utf-8")
    config = _make_config()
    vuln = _make_dep_vuln()
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_popen.return_value = _fake_proc()
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    cmd = mock_popen.call_args.args[0]
    prompt = cmd[config.ai_agent_args.index("{prompt}")]
    assert "GitHub recommends upgrading org.apache.calcite:calcite-core to version 1.42.0" in prompt
    assert "backend/pom.xml:5" in prompt
    assert ">>> 5:             <artifactId>calcite-core</artifactId>" in prompt
    assert vuln.introduced_at is not None


def test_read_code_snippet(tmp_path):
    from src.fixer import _read_code_snippet
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("line1\nline2\nvuln()\nline4\nline5\nline6\nline7\n", encoding="utf-8")
    snippet = _read_code_snippet(tmp_path, "src/app.py", 3)
    assert snippet is not None
    assert ">>> 3: vuln()" in snippet
    assert "src/app.py:3" in snippet


def _prompt_of_last_agent_call(mock_popen, config):
    return mock_popen.call_args.args[0][config.ai_agent_args.index("{prompt}")]


def test_apply_fix_transitive_dep_rule(tmp_path):
    config = _make_config()
    vuln = _make_dep_vuln()  # relationship == "transitive"
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_popen.return_value = _fake_proc()
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    prompt = _prompt_of_last_agent_call(mock_popen, config)
    assert "TRANSITIVE dependency" in prompt
    assert "org.apache.calcite:calcite-core" in prompt
    assert "DIRECT dependency" in prompt


def test_apply_fix_streams_agent_output_to_log(tmp_path, caplog):
    import logging
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_popen.return_value = _fake_proc(lines=("working on fix\n", "done\n"))
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            with caplog.at_level(logging.INFO, logger="src.fixer"):
                apply_fix(config, tmp_path, vuln)
    assert "[GHSA-test-1234] working on fix" in caplog.text
    assert "[GHSA-test-1234] done" in caplog.text


def test_apply_fix_direct_dep_no_transitive_rule(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    vuln.package_name = "lodash"
    vuln.dependency_relationship = "direct"
    with patch("subprocess.Popen") as mock_popen, patch("subprocess.run") as mock_run:
        mock_popen.return_value = _fake_proc()
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            apply_fix(config, tmp_path, vuln)
    prompt = _prompt_of_last_agent_call(mock_popen, config)
    assert "TRANSITIVE dependency" not in prompt
