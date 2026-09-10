# tests/test_pr.py
from unittest.mock import MagicMock, patch
from src.pr import create_pull_request, pr_exists_for_branch
from src.models import Vulnerability


def test_pr_exists_true():
    client = MagicMock()
    client.get_paginated.return_value = [{"head": {"ref": "fix/GHSA-1234"}, "state": "open"}]
    assert pr_exists_for_branch(client, "myorg/myrepo", "fix/GHSA-1234") is True


def test_pr_exists_false():
    client = MagicMock()
    client.get_paginated.return_value = [{"head": {"ref": "fix/GHSA-other"}, "state": "open"}]
    assert pr_exists_for_branch(client, "myorg/myrepo", "fix/GHSA-1234") is False


def test_create_pull_request():
    client = MagicMock()
    client.post.return_value = {"html_url": "https://github.com/myorg/myrepo/pull/1", "number": 1}
    vuln = Vulnerability(
        repo_full_name="myorg/myrepo",
        advisory_id="GHSA-test-1234",
        severity="high",
        title="Test vuln",
        description="A test",
        affected_files=["src/app.py"],
        package_name=None,
        source="ghsa",
        state="open",
    )
    result = create_pull_request(client, "myorg/myrepo", vuln, "main")
    assert result is not None
    assert result["html_url"] == "https://github.com/myorg/myrepo/pull/1"
