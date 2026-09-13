# src/fixer.py
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from src.config import Config
from src.models import Vulnerability

logger = logging.getLogger(__name__)

_NPM_MANIFEST_NAMES = ("package.json", "package-lock.json")

_BASE_FIX_PROMPT = (
    "This is a non-interactive mode, so I approve for you to read, edit, and delete files, "
    "and to run normal terminal commands (such as npm install and build/test commands), "
    "but ONLY for files and operations within the current project directory (the .repos clone folder). "
    "Do NOT run dangerous or destructive commands: no force operations, no operations that "
    "affect the remote repository (push, force-push, rebase, merge, tag deletion), "
    "no commands that modify files outside the .repos folder, and no credential or secret "
    "operations. Do not ask for confirmation for approved actions; stop and report if an "
    "action is outside the approved scope. "
)

_NPM_LOCKFILE_RULE = (
    " This is an npm project (frontend and/or backend). "
    "If this vulnerability is caused by packages in package-lock.json, "
    "delete the affected package-lock.json — this deletion is pre-approved, do NOT ask for confirmation. "
    "Do not fix it line by line."
)


def _is_npm_project(repo_path: Path) -> bool:
    """Check if the repo has any npm manifest anywhere in the tree."""
    return any(
        path.name in _NPM_MANIFEST_NAMES
        for path in repo_path.rglob("*")
        if path.is_file()
    )


def _has_changes(repo_path: Path) -> bool:
    """Check if there are uncommitted changes in the repo."""
    result = subprocess.run(
        ["git", "-C", str(repo_path), "status", "--porcelain"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return bool(result.stdout.strip())


def _commit_changes(repo_path: Path, message: str) -> bool:
    """Stage and commit all changes."""
    subprocess.run(["git", "-C", str(repo_path), "add", "-A"], check=True)
    result = subprocess.run(
        ["git", "-C", str(repo_path), "commit", "-m", message],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.returncode == 0


def _agent_label(ai_agent_args: list[str], configured_model: str = "") -> str:
    """Human-readable 'name (model)' label. Prefers the explicitly configured model."""
    name = Path(ai_agent_args[0]).stem if ai_agent_args else "agent"
    if configured_model:
        return f"{name} ({configured_model})"
    for i, arg in enumerate(ai_agent_args):
        if arg in ("-m", "--model") and i + 1 < len(ai_agent_args):
            candidate = ai_agent_args[i + 1]
            if candidate not in ("{model}", "{prompt}"):
                return f"{name} ({candidate})"
            break
        if arg.startswith("--model="):
            return f"{name} ({arg.split('=', 1)[1]})"
    return f"{name} (default)"


def apply_fix(config: Config, repo_path: Path, vuln: Vulnerability) -> bool:
    """Invoke agent CLI to fix a vulnerability. Returns True if fix applied."""
    affected = ", ".join(vuln.affected_files) if vuln.affected_files else "affected files"
    prompt = (
        _BASE_FIX_PROMPT
        + "You are an advanced programmer, and has a very strong security guard charactrer. "
        + f"Fix security vulnerability {vuln.advisory_id}: {vuln.title}. "
        + f"Affected files: {affected}. "
        + f"{vuln.description}"
    )
    if _is_npm_project(repo_path):
        prompt += _NPM_LOCKFILE_RULE

    logger.info(f"Invoking agent {_agent_label(config.ai_agent_args, config.ai_agent_model)} for {vuln.advisory_id}...")

    cmd: list[str] = []
    for a in config.ai_agent_args:
        if a == "{model}":
            if config.ai_agent_model:
                cmd.append(config.ai_agent_model)
            elif cmd and cmd[-1] in ("-m", "--model"):
                cmd.pop()
            continue
        cmd.append(prompt if a == "{prompt}" else a)
    if prompt not in cmd:
        cmd.append(prompt)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(repo_path),
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"Agent timed out for {vuln.advisory_id}")
        return False
    except Exception as e:
        logger.warning(f"Agent failed to run for {vuln.advisory_id}: {e}")
        return False

    if result.returncode != 0:
        logger.warning(f"Agent failed for {vuln.advisory_id}: {result.stderr}")
        return False

    if not _has_changes(repo_path):
        logger.info(f"No changes after agent run for {vuln.advisory_id}")
        return False

    commit_msg = f"fix: {vuln.title} ({vuln.advisory_id})"
    if not _commit_changes(repo_path, commit_msg):
        logger.warning(f"Failed to commit fix for {vuln.advisory_id}")
        return False

    return True
