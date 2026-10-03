# src/repo.py
from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# GitHub owner/repo names: letters, digits, hyphen, underscore, dot
_REPO_FULL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _safe_repo_name(repo_full_name: str) -> str:
    """Validate an owner/repo name and return the repo name.

    Rejects dot segments (``.``/``..``) including percent-encoded forms such as
    ``%2e``/``%2E`` to prevent path traversal of the clone directory.
    """
    if not _REPO_FULL_NAME_RE.match(repo_full_name):
        raise ValueError(f"Invalid repo full name: {repo_full_name!r}")

    owner, repo_name = repo_full_name.split("/", 1)
    for component in (owner, repo_name):
        if unquote(component) in (".", ".."):
            raise ValueError(f"Invalid repo full name (dot segment): {repo_full_name!r}")

    return repo_name


def _run_git(repo_path: Path, *args: str) -> subprocess.CompletedProcess:
    """Run a git command in the given repo directory."""
    cmd = ["git", "-C", str(repo_path)] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")


def clone_or_update(clone_dir: str, repo_full_name: str, token: str = "") -> Path:
    """Clone a repo or update it if it already exists. Returns the local path."""
    repo_name = _safe_repo_name(repo_full_name)
    clone_root = Path(clone_dir).resolve()
    repo_path = clone_root / repo_name
    if not repo_path.resolve().is_relative_to(clone_root):
        raise ValueError(f"Clone path escapes clone dir for {repo_full_name!r}")

    auth_prefix = f"https://{token}@github.com/" if token else "https://github.com/"

    if repo_path.exists():
        logger.info(f"Updating existing repo: {repo_full_name}")
        _run_git(repo_path, "remote", "set-url", "origin", f"{auth_prefix}{repo_full_name}.git")
        _run_git(repo_path, "fetch", "--all", "--prune")
        _run_git(repo_path, "pull")
    else:
        logger.info(f"Cloning {repo_full_name}...")
        repo_path.parent.mkdir(parents=True, exist_ok=True)
        clone_url = f"{auth_prefix}{repo_full_name}.git"
        subprocess.run(["git", "clone", clone_url, str(repo_path)], check=True)

    return repo_path


def detect_default_branch(repo_path: Path) -> str:
    """Detect the default branch: origin/HEAD -> main -> master."""
    result = _run_git(repo_path, "branch", "-r")
    if result.returncode == 0:
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if "origin/HEAD ->" in line:
                return line.split("->")[-1].strip().replace("origin/", "")

    result = _run_git(repo_path, "rev-parse", "--verify", "origin/main")
    if result.returncode == 0:
        return "main"

    result = _run_git(repo_path, "rev-parse", "--verify", "origin/master")
    if result.returncode == 0:
        return "master"

    return "main"


def update_default_branch(repo_path: Path, default_branch: str) -> None:
    """Sync the local default branch to the latest origin state.

    Checks out the default branch, fetches it, and hard-resets to
    origin/<default> so every fix starts from the latest source.
    Raises RuntimeError on failure — callers must not fix on stale code.
    """
    result = _run_git(repo_path, "checkout", default_branch)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to checkout {default_branch}: {result.stderr}")
    result = _run_git(repo_path, "fetch", "--prune", "origin", default_branch)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to fetch origin/{default_branch}: {result.stderr}")
    result = _run_git(repo_path, "reset", "--hard", f"origin/{default_branch}")
    if result.returncode != 0:
        raise RuntimeError(f"Failed to reset to origin/{default_branch}: {result.stderr}")


def branch_exists(repo_path: Path, branch_name: str) -> bool:
    """Check if a branch exists locally."""
    result = _run_git(repo_path, "branch")
    if result.returncode == 0:
        for line in result.stdout.strip().split("\n"):
            if branch_name in line:
                return True
    return False


def remote_branch_exists(repo_path: Path, branch_name: str) -> bool:
    """Check if origin/<branch> exists (after prune, missing means deleted on GitHub)."""
    result = _run_git(repo_path, "rev-parse", "--verify", f"origin/{branch_name}")
    return result.returncode == 0


def sync_prune_fix_branch(repo_path: Path, branch_name: str) -> bool:
    """Delete stale local fix/* branch whose remote is gone. Returns True if pruned.

    Only touches fix/* branches. Returns False when nothing to do (no local
    branch, remote still exists, or non-fix branch).
    """
    if not branch_name.startswith("fix/"):
        return False
    if not branch_exists(repo_path, branch_name):
        return False
    if remote_branch_exists(repo_path, branch_name):
        return False
    logger.info(f"Pruning stale local branch {branch_name} (remote deleted)")
    _run_git(repo_path, "branch", "-D", branch_name)
    return True


def create_branch(repo_path: Path, branch_name: str, base_branch: str) -> None:
    """Create and checkout a new branch from the base branch."""
    _run_git(repo_path, "checkout", base_branch)
    result = _run_git(repo_path, "checkout", "-b", branch_name)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to create branch {branch_name}: {result.stderr}")


def checkout(repo_path: Path, branch: str) -> None:
    """Checkout a branch."""
    result = _run_git(repo_path, "checkout", branch)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to checkout {branch}: {result.stderr}")
