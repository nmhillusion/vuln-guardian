# tests/test_fetcher.py
from unittest.mock import MagicMock, patch
from src.fetcher import (
    fetch_all_advisories,
    fetch_repo_advisories,
    _parse_dependabot_alerts,
    _parse_code_scanning_alerts,
)
from src.models import Vulnerability


def test_fetch_ghsa_advisories():
    client = MagicMock()
    with patch("src.fetcher._get_org_repos") as mock_repos:
        mock_repos.return_value = ["test-org/repo1"]
        with patch("src.fetcher._parse_ghsa_for_repo") as mock_ghsa:
            mock_ghsa.return_value = []
            with patch("src.fetcher._parse_dependabot_alerts") as mock_dep:
                mock_dep.return_value = []
                with patch("src.fetcher._parse_code_scanning_alerts") as mock_cs:
                    mock_cs.return_value = []
                    result = fetch_all_advisories(client, "test-org")
                    assert len(result) == 0


def test_parse_dependabot_alerts():
    alerts = [
        {
            "number": 1,
            "security_advisory": {
                "ghsa_id": "GHSA-dep-5678",
                "severity": "high",
                "summary": "Dependabot alert",
                "description": "A dependency vulnerability",
            },
            "security_vulnerability": {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "vulnerable_version_range": "< 4.17.21",
            },
            "state": "open",
        }
    ]
    result = _parse_dependabot_alerts("test-org/repo1", alerts)
    assert len(result) == 1
    assert result[0].advisory_id == "GHSA-dep-5678"


def test_parse_code_scanning_alerts():
    alerts = [
        {
            "number": 42,
            "rule": {
                "description": "SQL injection vulnerability",
                "security_severity_level": "high",
            },
            "location": {"path": "src/app.py"},
            "state": "open",
        }
    ]
    result = _parse_code_scanning_alerts("test-org/repo1", alerts)
    assert len(result) == 1
    assert result[0].advisory_id == "CS-42"
    assert result[0].affected_files == ["src/app.py"]


def test_parse_dependabot_alerts_enriched():
    alerts = [
        {
            "number": 7,
            "security_advisory": {
                "ghsa_id": "GHSA-dep-9999",
                "severity": "critical",
                "summary": "RCE in jackson",
                "description": "desc",
            },
            "security_vulnerability": {
                "package": {"name": "com.fasterxml.jackson.core:jackson-core", "ecosystem": "maven"},
                "vulnerable_version_range": "< 2.18.4.2",
                "first_patched_version": {"identifier": "2.18.4.2"},
            },
            "dependency": {
                "manifest_path": "backend/pom.xml",
                "scope": "runtime",
                "relationship": "transitive",
            },
            "state": "open",
        }
    ]
    result = _parse_dependabot_alerts("test-org/repo1", alerts)
    assert len(result) == 1
    assert result[0].patched_version == "2.18.4.2"
    assert result[0].vulnerable_range == "< 2.18.4.2"
    assert result[0].manifest_path == "backend/pom.xml"
    assert result[0].dependency_relationship == "transitive"
    assert result[0].dependency_scope == "runtime"


def test_parse_code_scanning_alerts_lines():
    alerts = [
        {
            "number": 43,
            "rule": {"description": "XSS", "security_severity_level": "medium"},
            "location": {"path": "src/view.py", "start_line": 12, "end_line": 15},
            "state": "open",
        }
    ]
    result = _parse_code_scanning_alerts("test-org/repo1", alerts)
    assert result[0].start_line == 12
    assert result[0].end_line == 15


def test_fetch_repo_advisories_resolves_transitive_chain():
    client = MagicMock()
    alert = {
        "number": 12,
        "security_advisory": {"ghsa_id": "GHSA-x", "severity": "high",
                              "summary": "S", "description": "D"},
        "security_vulnerability": {
            "package": {"name": "com.h2database:h2", "ecosystem": "maven"},
            "vulnerable_version_range": "< 2.2.220",
            "first_patched_version": {"identifier": "2.2.220"},
        },
        "dependency": {"manifest_path": "settings.gradle.kts", "scope": None,
                       "relationship": "transitive"},
        "state": "open",
    }
    client.get_paginated.side_effect = [[alert], [], []]
    sbom = {
        "packages": [
            {"SPDXID": "SPDXRef-R", "name": "r",
             "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:github/o/r@main"}]},
            {"SPDXID": "SPDXRef-H", "name": "h",
             "externalRefs": [{"referenceType": "purl",
                               "referenceLocator": "pkg:maven/com.h2database/h2@2.1.214"}]},
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-R",
             "relationshipType": "DESCRIBES"},
            {"spdxElementId": "SPDXRef-R", "relatedSpdxElement": "SPDXRef-H",
             "relationshipType": "DEPENDS_ON"},
        ],
    }
    with patch("src.fetcher.fetch_sbom", return_value=sbom) as mock_sbom:
        vulns = fetch_repo_advisories(client, "test-org/repo1")
    mock_sbom.assert_called_once()
    assert len(vulns) == 1
    assert vulns[0].ecosystem == "maven"
    assert vulns[0].dependency_chain == ["pkg:github/o/r@main", "com.h2database:h2@2.1.214"]
