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
    batch: list[Vulnerability],
    base_branch: str,
    branch_name: str,
) -> dict | None:
    """Create a pull request fixing a batch of vulns. Returns PR info dict or None on failure."""
    ids = [v.advisory_id for v in batch]
    id_list = ", ".join(ids[:3]) + ("..." if len(ids) > 3 else "")
    title = f"Fix: {len(batch)} vulnerabilities ({id_list})"
    lines = "\n".join(f"- **{v.advisory_id}** ({v.severity}): {v.title}" for v in batch)
    body = f"Security fixes for {len(batch)} advisories in this batch:\n\n{lines}"

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
        logger.error(f"Failed to create PR for batch [{', '.join(ids)}]: {e}")
        return None
