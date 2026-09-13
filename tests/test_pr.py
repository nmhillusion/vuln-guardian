# tests/test_pr.py
from unittest.mock import MagicMock, patch
from src.pr import create_pull_request, pr_exists_for_branch, fetch_open_tool_prs
from src.models import Vulnerability


def test_pr_exists_true():
    client = MagicMock()
    client.get_paginated.return_value = [{"head": {"ref": "fix/GHSA-1234"}, "state": "open"}]
    assert pr_exists_for_branch(client, "myorg/myrepo", "fix/GHSA-1234") is True


def test_pr_exists_false():
    client = MagicMock()
    client.get_paginated.return_value = [{"head": {"ref": "fix/GHSA-other"}, "state": "open"}]
    assert pr_exists_for_branch(client, "myorg/myrepo", "fix/GHSA-1234") is False


def _make_vuln(advisory_id="GHSA-test-1234"):
    return Vulnerability(
        repo_full_name="myorg/myrepo",
        advisory_id=advisory_id,
        severity="high",
        title="Test vuln",
        description="A test",
        affected_files=["src/app.py"],
        package_name=None,
        source="ghsa",
        state="open",
    )


def test_create_pull_request():
    client = MagicMock()
    client.post.return_value = {"html_url": "https://github.com/myorg/myrepo/pull/1", "number": 1}
    batch = [_make_vuln("GHSA-test-1111"), _make_vuln("GHSA-test-2222")]
    result = create_pull_request(client, "myorg/myrepo", batch, "main", "fix/batch-abc123")
    assert result is not None
    assert result["html_url"] == "https://github.com/myorg/myrepo/pull/1"
    payload = client.post.call_args.kwargs["json"]
    assert payload["head"] == "fix/batch-abc123"
    assert payload["title"] == "Fix: 2 vulnerabilities (GHSA-test-1111, GHSA-test-2222)"
    assert "GHSA-test-1111" in payload["body"] and "GHSA-test-2222" in payload["body"]
    assert "[vuln-guardian](https://github.com/nmhillusion/vuln-guardian)" in payload["body"]


def test_fetch_open_tool_prs():
    client = MagicMock()
    client.get_paginated.return_value = [
        {"number": 1, "title": "Fix: brace-expansion DoS (GHSA-aaa)",
         "html_url": "https://github.com/o/r/pull/1",
         "head": {"ref": "fix/GHSA-aaa"}},
        {"number": 2, "title": "Fix: 2 vulnerabilities (GHSA-bbb, GHSA-ccc)",
         "html_url": "https://github.com/o/r/pull/2",
         "head": {"ref": "fix/batch-abc123"}},
        {"number": 3, "title": "My feature",
         "html_url": "https://github.com/o/r/pull/3",
         "head": {"ref": "feature/cool"}},
    ]
    rows = fetch_open_tool_prs(client, "o/r")
    assert len(rows) == 2
    assert rows[0]["advisory_id"] == "GHSA-aaa"
    assert rows[0]["pr_number"] == 1
    assert rows[1]["advisory_id"] == "GHSA-bbb, GHSA-ccc"
    assert rows[1]["pr_number"] == 2
