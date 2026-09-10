# src/repo.py
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def _run_git(repo_path: Path, *args: str) -> subprocess.CompletedProcess:
    """Run a git command in the given repo directory."""
    cmd = ["git", "-C", str(repo_path)] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True)


def clone_or_update(clone_dir: str, repo_full_name: str) -> Path:
    """Clone a repo or update it if it already exists. Returns the local path."""
    repo_name = repo_full_name.split("/")[-1]
    repo_path = Path(clone_dir) / repo_name

    if repo_path.exists():
        logger.info(f"Updating existing repo: {repo_full_name}")
        _run_git(repo_path, "fetch", "--all")
        _run_git(repo_path, "pull")
    else:
        logger.info(f"Cloning {repo_full_name}...")
        repo_path.parent.mkdir(parents=True, exist_ok=True)
        clone_url = f"https://github.com/{repo_full_name}.git"
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


def branch_exists(repo_path: Path, branch_name: str) -> bool:
    """Check if a branch exists locally."""
    result = _run_git(repo_path, "branch")
    if result.returncode == 0:
        for line in result.stdout.strip().split("\n"):
            if branch_name in line:
                return True
    return False


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
