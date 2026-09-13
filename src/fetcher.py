# src/fetcher.py
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.github_client import GitHubClient

from src.models import Vulnerability

logger = logging.getLogger(__name__)


def _get_org_repos(client: GitHubClient, org: str) -> list[str]:
    """Get all repos for an org or user, return list of full_name strings."""
    try:
        repos = client.get_paginated(f"/orgs/{org}/repos")
        return [repo["full_name"] for repo in repos]
    except Exception:
        logger.info(f"Not an org, trying as user: {org}")
        repos = client.get_paginated(f"/users/{org}/repos")
        return [repo["full_name"] for repo in repos]


def _parse_dependabot_alerts(repo_full_name: str, alerts: list[dict]) -> list[Vulnerability]:
    """Parse Dependabot alerts into Vulnerability objects."""
    vulns = []
    for alert in alerts:
        if alert.get("state") != "open":
            continue
        advisory = alert.get("security_advisory", {})
        vuln_info = alert.get("security_vulnerability", {})
        package = vuln_info.get("package", {})
        vulns.append(
            Vulnerability(
                repo_full_name=repo_full_name,
                advisory_id=advisory.get("ghsa_id", f"DEP-{alert.get('number', 'unknown')}"),
                severity=advisory.get("severity", "unknown"),
                title=advisory.get("summary", "Unknown vulnerability"),
                description=advisory.get("description", ""),
                affected_files=[],
                package_name=package.get("name"),
                source="dependabot",
                state="open",
            )
        )
    return vulns


def _parse_code_scanning_alerts(repo_full_name: str, alerts: list[dict]) -> list[Vulnerability]:
    """Parse Code Scanning alerts into Vulnerability objects."""
    vulns = []
    for alert in alerts:
        if alert.get("state") != "open":
            continue
        rule = alert.get("rule", {})
        location = alert.get("location", {})
        file_path = location.get("path", "")
        vulns.append(
            Vulnerability(
                repo_full_name=repo_full_name,
                advisory_id=f"CS-{alert.get('number', 'unknown')}",
                severity=rule.get("security_severity_level", "unknown"),
                title=rule.get("description", "Unknown code scanning alert"),
                description=rule.get("description", ""),
                affected_files=[file_path] if file_path else [],
                package_name=None,
                source="code_scanning",
                state="open",
            )
        )
    return vulns


def list_repos(client: GitHubClient, org: str) -> list[str]:
    """List all repo full names for an org or user."""
    return _get_org_repos(client, org)


def fetch_repo_advisories(client: GitHubClient, repo_full_name: str) -> list[Vulnerability]:
    """Fetch all open advisories (Dependabot, Code Scanning, GHSA) for a single repo."""
    vulns: list[Vulnerability] = []
    logger.info(f"Scanning {repo_full_name}...")

    try:
        dependabot_alerts = client.get_paginated(f"/repos/{repo_full_name}/dependabot/alerts")
        vulns.extend(_parse_dependabot_alerts(repo_full_name, dependabot_alerts))
    except Exception as e:
        logger.warning(f"Failed to fetch Dependabot alerts for {repo_full_name}: {e}")

    try:
        code_scanning_alerts = client.get_paginated(f"/repos/{repo_full_name}/code-scanning/alerts")
        vulns.extend(_parse_code_scanning_alerts(repo_full_name, code_scanning_alerts))
    except Exception as e:
        logger.warning(f"Failed to fetch Code Scanning alerts for {repo_full_name}: {e}")

    vulns.extend(_parse_ghsa_for_repo(client, repo_full_name))
    return vulns


def _parse_ghsa_for_repo(client: GitHubClient, repo_full_name: str) -> list[Vulnerability]:
    """Fetch GHSA advisories that affect a specific repo."""
    vulns = []
    try:
        advisories = client.get_paginated(f"/repos/{repo_full_name}/security-advisories")
        for adv in advisories:
            vulns.append(
                Vulnerability(
                    repo_full_name=repo_full_name,
                    advisory_id=adv.get("ghsa_id", "unknown"),
                    severity=adv.get("severity", "unknown"),
                    title=adv.get("summary", "Unknown advisory"),
                    description=adv.get("description", ""),
                    affected_files=[],
                    package_name=None,
                    source="ghsa",
                    state="open",
                )
            )
    except Exception as e:
        logger.warning(f"Failed to fetch GHSA advisories for {repo_full_name}: {e}")
    return vulns


def fetch_all_advisories(client: GitHubClient, org: str) -> list[Vulnerability]:
    """Fetch all open advisories from GHSA, Dependabot, and Code Scanning for an org."""
    all_vulns: list[Vulnerability] = []
    try:
        repos = list_repos(client, org)
    except Exception as e:
        logger.error(f"Failed to fetch repos for org {org}: {e}")
        logger.error("Check your GITHUB_PAT has 'repo' and 'security_events' scopes")
        return []
    logger.info(f"Found {len(repos)} repos in org {org}")

    for repo_full_name in repos:
        all_vulns.extend(fetch_repo_advisories(client, repo_full_name))

    logger.info(f"Total vulnerabilities found: {len(all_vulns)}")
    return all_vulns
