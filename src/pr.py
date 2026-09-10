# src/pr.py
from __future__ import annotations

import logging

from src.github_client import GitHubClient
from src.models import Vulnerability

logger = logging.getLogger(__name__)


def pr_exists_for_branch(client: GitHubClient, repo_full_name: str, branch_name: str) -> bool:
    """Check if a PR already exists for the given branch."""
    prs = client.get_paginated(f"/repos/{repo_full_name}/pulls")
    for pr in prs:
        if pr.get("head", {}).get("ref") == branch_name:
            return True
    return False


def create_pull_request(
    client: GitHubClient,
    repo_full_name: str,
    vuln: Vulnerability,
    base_branch: str,
) -> dict | None:
    """Create a pull request for the fix. Returns PR info dict or None on failure."""
    branch_name = f"fix/{vuln.advisory_id}"
    title = f"Fix: {vuln.title} ({vuln.advisory_id})"
    body = (
        f"Security advisory: {vuln.description}\n\n"
        f"**Source:** {vuln.source}\n"
        f"**Severity:** {vuln.severity}\n"
        f"**Advisory ID:** {vuln.advisory_id}"
    )

    try:
        pr = client.post(
            f"/repos/{repo_full_name}/pulls",
            json={
                "title": title,
                "body": body,
                "head": branch_name,
                "base": base_branch,
            },
        )
        logger.info(f"Created PR: {pr.get('html_url')}")
        return pr
    except Exception as e:
        logger.error(f"Failed to create PR for {vuln.advisory_id}: {e}")
        return None
