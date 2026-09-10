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
    assert "GitHub Advisor Agent" in html
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
