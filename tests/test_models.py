# tests/test_models.py
from src.models import Vulnerability, RunResult


def test_vulnerability_creation():
    v = Vulnerability(
        repo_full_name="myorg/myrepo",
        advisory_id="GHSA-xxxx-xxxx-xxxx",
        severity="high",
        title="Test vuln",
        description="A test vulnerability",
        affected_files=["src/app.py", "src/utils.py"],
        package_name=None,
        source="ghsa",
        state="open",
    )
    assert v.repo_full_name == "myorg/myrepo"
    assert len(v.affected_files) == 2
    assert v.package_name is None


def test_run_result_defaults():
    r = RunResult()
    assert r.repos_scanned == 0
    assert r.vulns_found == 0
    assert r.fixes_attempted == 0
    assert r.prs_created == 0
    assert r.skipped == 0
    assert r.errors == []
