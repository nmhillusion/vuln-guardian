# tests/test_main.py
from unittest.mock import patch, MagicMock
from src.main import main


def test_main_dry_run(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\nopencode_binary: "opencode"\n')

    with patch("src.main.load_config") as mock_config, \
         patch("src.main.GitHubClient") as mock_client_cls, \
         patch("src.main.fetch_all_advisories", return_value=[]), \
         patch("src.main.generate_report", return_value="<html></html>"):
        mock_config.return_value = MagicMock(
            org="test-org",
            clone_dir=str(tmp_path / ".repos"),
            report_path=str(tmp_path / "report.html"),
            github_pat="ghp_test",
        )
        mock_client_cls.return_value = MagicMock()
        main(["--dry-run", "--config", str(config_path)])
