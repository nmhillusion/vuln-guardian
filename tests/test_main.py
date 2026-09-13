# tests/test_main.py
import pytest
from unittest.mock import patch, MagicMock
from src.main import main, _batch_vulns, _batch_branch_name
from src.models import Vulnerability


def test_main_dry_run(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\nai_agent_args: ["kilo", "run", "--auto", "{prompt}"]\n')

    with patch("src.main.load_config") as mock_config, \
         patch("src.main.GitHubClient") as mock_client_cls, \
         patch("src.main.list_repos", return_value=[]), \
         patch("src.main.fetch_repo_advisories") as mock_fetch, \
         patch("src.main.webbrowser") as mock_browser, \
         patch("src.main.generate_report", return_value="<html></html>"):
        mock_config.return_value = MagicMock(
            org="test-org",
            clone_dir=str(tmp_path / ".repos"),
            report_path=str(tmp_path / "report.html"),
            github_pat="ghp_test",
        )
        mock_client_cls.return_value = MagicMock()
        main(["--dry-run", "--config", str(config_path)])
        mock_fetch.assert_not_called()
        mock_browser.open.assert_called_once()
        assert mock_browser.open.call_args.args[0].startswith("file://")


def _batch_vuln(advisory_id, manifest=None, affected=None):
    return Vulnerability(
        repo_full_name="test-org/repo1",
        advisory_id=advisory_id,
        severity="high",
        title=f"Title {advisory_id}",
        description="desc",
        affected_files=[affected] if affected else [],
        package_name=None,
        source="dependabot",
        state="open",
        manifest_path=manifest,
    )


def test_batch_vulns_groups_by_file_and_chunks():
    vulns = [
        _batch_vuln("GHSA-3", manifest="a/pom.xml"),
        _batch_vuln("GHSA-1", manifest="a/pom.xml"),
        _batch_vuln("GHSA-2", manifest="a/pom.xml"),
        _batch_vuln("GHSA-4", manifest="b/package.json"),
        _batch_vuln("GHSA-5"),
    ]
    batches = _batch_vulns(vulns, batch_size=2)
    assert [[v.advisory_id for v in b] for b in batches] == [
        ["GHSA-5"],
        ["GHSA-1", "GHSA-2"],
        ["GHSA-3"],
        ["GHSA-4"],
    ]


def test_batch_branch_name_deterministic():
    vulns = [_batch_vuln("GHSA-2"), _batch_vuln("GHSA-1")]
    assert _batch_branch_name(vulns) == _batch_branch_name(list(reversed(vulns)))
    assert _batch_branch_name(vulns).startswith("fix/batch-")
    other = [_batch_vuln("GHSA-9")]
    assert _batch_branch_name(vulns) != _batch_branch_name(other)


def _make_vuln(repo, advisory_id):
    return Vulnerability(
        repo_full_name=repo,
        advisory_id=advisory_id,
        severity="high",
        title="Test vuln",
        description="desc",
        affected_files=[],
        package_name=None,
        source="dependabot",
        state="open",
    )


def test_main_stops_after_max_fixes(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\nai_agent_args: ["kilo", "run", "--auto", "{prompt}"]\n')
    repos = [f"test-org/repo{i}" for i in range(7)]

    def fake_process_repo(client, config, repo_full_name, vulns, result, max_fixes=5, batch_size=5):
        result.fixes_attempted += 1

    with patch("src.main.load_config") as mock_config, \
         patch("src.main.GitHubClient") as mock_client_cls, \
         patch("src.main.list_repos", return_value=repos), \
         patch("src.main.fetch_repo_advisories") as mock_fetch, \
         patch("src.main.process_repo", side_effect=fake_process_repo), \
         patch("src.main.webbrowser"), \
         patch("builtins.input", return_value="y"), \
         patch("src.main.generate_report", return_value="<html></html>"):
        mock_config.return_value = MagicMock(
            org="test-org",
            clone_dir=str(tmp_path / ".repos"),
            report_path=str(tmp_path / "report.html"),
            github_pat="ghp_test",
        )
        mock_client_cls.return_value = MagicMock()
        mock_fetch.side_effect = lambda client, repo: [_make_vuln(repo, f"GHSA-{repo.split('/')[-1]}")]
        main(["--config", str(config_path)])
        assert mock_fetch.call_count == 5


def _fix_mode_config(tmp_path):
    from src.config import Config
    return Config(
        org="test-org",
        clone_dir=str(tmp_path / "clones"),
        report_path=str(tmp_path / "report.html"),
        github_pat="ghp_test",
    )


def _run_fix_mode(tmp_path, argv_extra, input_return="y"):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("org: test-org\n")
    with patch("src.main.load_config") as mock_config, \
         patch("src.main.GitHubClient") as mock_client_cls, \
         patch("src.main.list_repos", return_value=[]), \
         patch("src.main.webbrowser"), \
         patch("src.main.generate_report", return_value="<html></html>"), \
         patch("builtins.input", return_value=input_return) as mock_input:
        mock_config.return_value = _fix_mode_config(tmp_path)
        mock_client_cls.return_value = MagicMock()
        main(["--config", str(config_path), *argv_extra])
        return mock_input


def test_main_creates_clone_dir_on_approval(tmp_path):
    mock_input = _run_fix_mode(tmp_path, [])
    mock_input.assert_called_once()
    prompt = mock_input.call_args.args[0]
    assert "clone_dir" in prompt and "config.yaml" in prompt
    assert (tmp_path / "clones").is_dir()


def test_main_aborts_without_clone_dir_approval(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("org: test-org\n")
    with patch("src.main.load_config") as mock_config, \
         patch("src.main.GitHubClient") as mock_client_cls, \
         patch("src.main.list_repos", return_value=[]), \
         patch("src.main.webbrowser"), \
         patch("src.main.generate_report", return_value="<html></html>"), \
         patch("builtins.input", return_value="n"):
        mock_config.return_value = _fix_mode_config(tmp_path)
        mock_client_cls.return_value = MagicMock()
        with pytest.raises(SystemExit):
            main(["--config", str(config_path)])
    assert not (tmp_path / "clones").exists()


def test_main_yes_skips_clone_dir_prompt(tmp_path):
    mock_input = _run_fix_mode(tmp_path, ["--yes"])
    mock_input.assert_not_called()
    assert (tmp_path / "clones").is_dir()
