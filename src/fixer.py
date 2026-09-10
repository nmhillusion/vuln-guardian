# src/fixer.py
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from src.config import Config
from src.models import Vulnerability

logger = logging.getLogger(__name__)


def _has_changes(repo_path: Path) -> bool:
    """Check if there are uncommitted changes in the repo."""
    result = subprocess.run(
        ["git", "-C", str(repo_path), "status", "--porcelain"],
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


def _commit_changes(repo_path: Path, message: str) -> bool:
    """Stage and commit all changes."""
    subprocess.run(["git", "-C", str(repo_path), "add", "-A"], check=True)
    result = subprocess.run(
        ["git", "-C", str(repo_path), "commit", "-m", message],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def apply_fix(config: Config, repo_path: Path, vuln: Vulnerability) -> bool:
    """Invoke OpenCode CLI to fix a vulnerability. Returns True if fix applied."""
    affected = ", ".join(vuln.affected_files) if vuln.affected_files else "affected files"
    prompt = (
        f"Fix security vulnerability {vuln.advisory_id}: {vuln.title}. "
        f"Affected files: {affected}. "
        f"{vuln.description}"
    )

    logger.info(f"Invoking OpenCode for {vuln.advisory_id}...")

    result = subprocess.run(
        [config.opencode_binary, "apply", "--yes", "--message", prompt],
        capture_output=True,
        text=True,
        cwd=str(repo_path),
    )

    if result.returncode != 0:
        logger.warning(f"OpenCode failed for {vuln.advisory_id}: {result.stderr}")
        return False

    if not _has_changes(repo_path):
        logger.info(f"No changes after OpenCode run for {vuln.advisory_id}")
        return False

    commit_msg = f"fix: {vuln.title} ({vuln.advisory_id})"
    if not _commit_changes(repo_path, commit_msg):
        logger.warning(f"Failed to commit fix for {vuln.advisory_id}")
        return False

    return True
