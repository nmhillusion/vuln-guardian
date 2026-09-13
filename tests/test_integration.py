# tests/test_integration.py
"""Integration test — runs the full pipeline with mocked external services."""
from unittest.mock import patch, MagicMock
from src.main import main
from src.models import Vulnerability, RunResult


def test_full_dry_run_pipeline(tmp_path):
    """Test: fetch advisories -> generate report, no clone/fix/PR."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\nai_agent_args: ["kilo", "run", "--auto", "{prompt}"]\n')

    vulns = [
        Vulnerability(
            repo_full_name="test-org/repo1",
            advisory_id="GHSA-test-1111",
            severity="high",
            title="SQL Injection",
            description="SQL injection in login endpoint",
            affected_files=["src/auth.py"],
            package_name=None,
            source="ghsa",
            state="open",
        ),
        Vulnerability(
            repo_full_name="test-org/repo2",
            advisory_id="GHSA-test-2222",
            severity="critical",
            title="RCE via deserialization",
            description="Remote code execution",
            affected_files=["src/parser.py", "src/utils.py"],
            package_name="lodash",
            source="dependabot",
            state="open",
        ),
    ]

    with patch("src.main.load_config") as mock_config, \
         patch("src.main.GitHubClient") as mock_client_cls, \
         patch("src.main.list_repos", return_value=["test-org/repo1", "test-org/repo2"]), \
         patch("src.main.fetch_repo_advisories", side_effect=[[vulns[0]], [vulns[1]]]), \
         patch("src.main.generate_report") as mock_report:
        from src.config import Config
        mock_config.return_value = Config(
            org="test-org",
            clone_dir=str(tmp_path / ".repos"),
            report_path=str(tmp_path / "report.html"),
            ai_agent_args=["kilo", "run", "--auto", "{prompt}"],
            github_pat="ghp_test",
        )
        mock_client_cls.return_value = MagicMock()
        mock_report.return_value = "<html></html>"

        main(["--dry-run", "--config", str(config_path)])

        mock_report.assert_called_once()
        call_args = mock_report.call_args
        result = call_args[0][0]
        assert result.vulns_found == 2
