# tests/test_main.py
from unittest.mock import patch, MagicMock
from src.main import main
from src.models import Vulnerability


def test_main_dry_run(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\nai_agent_args: ["kilo", "run", "--auto", "{prompt}"]\n')

    with patch("src.main.load_config") as mock_config, \
         patch("src.main.GitHubClient") as mock_client_cls, \
         patch("src.main.list_repos", return_value=[]), \
         patch("src.main.fetch_repo_advisories") as mock_fetch, \
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

    def fake_process_repo(client, config, repo_full_name, vulns, result, max_fixes=5):
        result.fixes_attempted += 1

    with patch("src.main.load_config") as mock_config, \
         patch("src.main.GitHubClient") as mock_client_cls, \
         patch("src.main.list_repos", return_value=repos), \
         patch("src.main.fetch_repo_advisories") as mock_fetch, \
         patch("src.main.process_repo", side_effect=fake_process_repo), \
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
