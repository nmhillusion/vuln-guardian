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


def _advisory_ids_from_pr(head_ref: str, title: str) -> str:
    """Extract advisory IDs from a tool PR (legacy single-ID or batch title)."""
    if head_ref.startswith("fix/") and not head_ref.startswith("fix/batch-"):
        return head_ref[len("fix/"):]
    if title.rstrip().endswith(")") and "(" in title:
        return title.rsplit("(", 1)[-1].rstrip(")").rstrip(".")
    return head_ref


def fetch_open_tool_prs(client: GitHubClient, repo_full_name: str) -> list[dict]:
    """List open PRs created by this tool (fix/* heads) for a repo."""
    rows = []
    try:
        prs = client.get_paginated(f"/repos/{repo_full_name}/pulls?state=open")
    except Exception as e:
        logger.warning(f"Failed to fetch open PRs for {repo_full_name}: {e}")
        return []
    for pr in prs:
        head_ref = pr.get("head", {}).get("ref", "")
        if not head_ref.startswith("fix/"):
            continue
        title = pr.get("title", "")
        rows.append({
            "repo": repo_full_name,
            "advisory_id": _advisory_ids_from_pr(head_ref, title),
            "title": title,
            "pr_url": pr.get("html_url", ""),
            "pr_number": pr.get("number", ""),
            "head": head_ref,
        })
    return rows


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
    body = (
        "> 🛡️ This pull request was automatically created by "
        "[vuln-guardian](https://github.com/nmhillusion/vuln-guardian).\n"
        "> Please review the changes carefully before merging.\n\n"
        f"Security fixes for {len(batch)} advisories in this batch:\n\n{lines}"
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
        logger.error(f"Failed to create PR for batch [{', '.join(ids)}]: {e}")
        return None
