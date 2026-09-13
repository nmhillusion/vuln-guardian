# tests/test_reporter.py
from src.reporter import generate_report
from src.models import RunResult


def test_generate_report_returns_html():
    result = RunResult(
        repos_scanned=5,
        vulns_found=10,
        fixes_attempted=8,
        prs_created=6,
        skipped=2,
    )
    html = generate_report(result, "report.html")
    assert "<html" in html
    assert "vuln-guardian" in html
    assert "5" in html
    assert "10" in html


def test_generate_report_with_errors():
    result = RunResult(errors=["Failed to clone repo1", "OpenCode timeout on repo2"])
    html = generate_report(result, "report.html")
    assert "Failed to clone repo1" in html
    assert "OpenCode timeout on repo2" in html


def test_generate_report_saves_file(tmp_path):
    result = RunResult(repos_scanned=1)
    report_path = str(tmp_path / "test_report.html")
    generate_report(result, report_path)
    from pathlib import Path
    assert Path(report_path).exists()


def test_generate_report_lists_skipped_items(tmp_path):
    result = RunResult(
        repos_scanned=1,
        vulns_found=2,
        skipped=2,
        skipped_items=[
            {"repo": "o/r", "advisory_id": "GHSA-1", "reason": "PR already exists"},
            {"repo": "o/r", "advisory_id": "GHSA-2", "reason": "no fix produced"},
        ],
    )
    report_path = str(tmp_path / "test_report.html")
    html = generate_report(result, report_path)
    assert "GHSA-1" in html and "PR already exists" in html
    assert "GHSA-2" in html and "no fix produced" in html


def test_generate_report_skipped_branch_link(tmp_path):
    result = RunResult(
        repos_scanned=1,
        vulns_found=1,
        skipped=1,
        skipped_items=[
            {"repo": "o/r", "advisory_id": "GHSA-1", "reason": "batch branch already exists",
             "branch": "fix/batch-abc123", "url": "https://github.com/o/r/tree/fix/batch-abc123"},
        ],
    )
    report_path = str(tmp_path / "test_report.html")
    html = generate_report(result, report_path)
    assert '<a href="https://github.com/o/r/tree/fix/batch-abc123">fix/batch-abc123</a>' in html


def test_generate_report_lists_pending_prs(tmp_path):
    result = RunResult(
        repos_scanned=1,
        pending_prs=[
            {"repo": "o/r", "advisory_id": "GHSA-1", "title": "Fix: x (GHSA-1)",
             "pr_url": "https://github.com/o/r/pull/9", "pr_number": 9},
        ],
    )
    report_path = str(tmp_path / "test_report.html")
    html = generate_report(result, report_path)
    assert "Pending Tool PRs (1)" in html
    assert "https://github.com/o/r/pull/9" in html
    assert "GHSA-1" in html
