# tests/test_config.py
import os
import pytest
from src.config import load_config


def test_load_config_from_yaml(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\nopencode_binary: "opencode"\n')
    os.environ["GITHUB_PAT"] = "ghp_test_token"
    try:
        config = load_config(str(config_file))
        assert config.org == "test-org"
        assert config.github_pat == "ghp_test_token"
    finally:
        del os.environ["GITHUB_PAT"]


def test_load_config_missing_pat(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\nopencode_binary: "opencode"\n')
    os.environ.pop("GITHUB_PAT", None)
    with pytest.raises(ValueError, match="GITHUB_PAT"):
        load_config(str(config_file))


def test_load_config_missing_yaml(tmp_path):
    os.environ["GITHUB_PAT"] = "ghp_test_token"
    try:
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_path / "missing.yaml"))
    finally:
        del os.environ["GITHUB_PAT"]
