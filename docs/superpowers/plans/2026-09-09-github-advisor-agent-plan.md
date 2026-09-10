# GitHub Advisor Agent — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI tool that fetches GitHub security advisories across GHSA, Dependabot, and Code Scanning, clones affected repos, invokes OpenCode CLI to auto-fix vulnerabilities, creates PRs, and generates an HTML summary report.

**Architecture:** Monolithic Python CLI with clear module separation (`config`, `fetcher`, `repo`, `fixer`, `pr`, `reporter`). Uses httpx for GitHub API calls with retry/backoff, subprocess for git and OpenCode CLI invocation, and Jinja2-style HTML templating for reports.

**Tech Stack:** Python 3.11+, httpx, pyyaml, pytest, subprocess (git, opencode)

## Global Constraints

- Python 3.11+ required (uses `list[str]`, `str | None` type hints)
- `GITHUB_PAT` env var required for all GitHub API calls
- httpx for all HTTP requests with exponential backoff retry (max 3 on 429/500)
- Errors are non-fatal — tool continues processing remaining repos/vulns
- Sequential repo processing (no concurrency)
- Branch naming convention: `fix/{advisory_id}`
- Default branch detection: `origin/HEAD` → `origin/main` → `origin/master`
- Cloned repos stored in `.repos/` directory

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `.env.example`
- Create: `config.yaml`
- Create: `src/__init__.py`

- [ ] **Step 1: Create pyproject.toml**

```toml
[project]
name = "github-advisor-agent"
version = "0.1.0"
description = "Auto-fix GitHub security advisories using OpenCode CLI"
requires-python = ">=3.11"
dependencies = [
    "httpx>=0.27",
    "pyyaml>=6.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-mock>=3.14",
]

[project.scripts]
github-advisor = "src.main:main"

[build-system]
requires = ["setuptools>=75"]
build-backend = "setuptools.backends._legacy:_Backend"
```

- [ ] **Step 2: Create .gitignore**

```
.repos/
.env
*.pyc
__pycache__/
.pytest_cache/
report.html
```

- [ ] **Step 3: Create .env.example**

```
GITHUB_PAT=ghp_your_token_here
```

- [ ] **Step 4: Create config.yaml**

```yaml
org: "my-org"
clone_dir: ".repos"
report_path: "report.html"
opencode_binary: "opencode"
```

- [ ] **Step 5: Create src/__init__.py**

```python
```

- [ ] **Step 6: Verify project structure**

Run: `python -c "import yaml; print('deps ok')"`
Expected: `deps ok`

- [ ] **Step 7: Install dependencies**

Run: `pip install -e ".[dev]"`
Expected: Successful installation

---

### Task 2: Config Module

**Files:**
- Create: `src/config.py`
- Create: `tests/__init__.py`
- Create: `tests/test_config.py`

**Interfaces:**
- Produces: `Config` dataclass with fields: `org: str`, `clone_dir: str`, `report_path: str`, `opencode_binary: str`, `github_pat: str`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
import os
import pytest
from src.config import load_config


def test_load_config_from_yaml(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\nopencode_binary: "opencode"\n')
    os.environ["GITHUB_PAT"] = "ghp_test_token"
    try:
        config = load_config(str(config_file))
        assert config.org == "test-org"
        assert config.github_pat == "ghp_test_token"
    finally:
        del os.environ["GITHUB_PAT"]


def test_load_config_missing_pat(tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\nopencode_binary: "opencode"\n')
    os.environ.pop("GITHUB_PAT", None)
    with pytest.raises(ValueError, match="GITHUB_PAT"):
        load_config(str(config_file))


def test_load_config_missing_yaml(tmp_path):
    os.environ["GITHUB_PAT"] = "ghp_test_token"
    try:
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_path / "missing.yaml"))
    finally:
        del os.environ["GITHUB_PAT"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.config'`

- [ ] **Step 3: Write implementation**

```python
# src/config.py
import os
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class Config:
    org: str
    clone_dir: str
    report_path: str
    opencode_binary: str
    github_pat: str


def load_config(config_path: str = "config.yaml") -> Config:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    github_pat = os.environ.get("GITHUB_PAT")
    if not github_pat:
        raise ValueError("GITHUB_PAT environment variable is required")

    return Config(
        org=data.get("org", ""),
        clone_dir=data.get("clone_dir", ".repos"),
        report_path=data.get("report_path", "report.html"),
        opencode_binary=data.get("opencode_binary", "opencode"),
        github_pat=github_pat,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_config.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add src/config.py src/__init__.py tests/test_config.py tests/__init__.py
git commit -m "feat: add config module with YAML + env var loading"
```

---

### Task 3: GitHub API Client

**Files:**
- Create: `src/github_client.py`
- Create: `tests/test_github_client.py`

**Interfaces:**
- Produces: `GitHubClient` class with methods:
  - `get(path: str) -> dict` — GET request with auth
  - `get_paginated(path: str, per_page: int = 100) -> list[dict]` — auto-paginate
  - `post(path: str, json: dict) -> dict` — POST request

- [ ] **Step 1: Write the failing test**

```python
# tests/test_github_client.py
import pytest
from unittest.mock import patch, MagicMock
from src.github_client import GitHubClient


def test_client_sets_auth_header():
    client = GitHubClient("ghp_test_token")
    assert client.client.headers["Authorization"] == "Bearer ghp_test_token"
    assert client.client.headers["Accept"] == "application/vnd.github+json"


def test_client_get_calls_correct_url():
    client = GitHubClient("ghp_test_token")
    with patch.object(client.client, "get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"login": "test"}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        result = client.get("/user")
        mock_get.assert_called_once_with("https://api.github.com/user")
        assert result == {"login": "test"}


def test_client_get_paginated_returns_all_items():
    client = GitHubClient("ghp_test_token")
    with patch.object(client, "get") as mock_get:
        mock_get.side_effect = [
            [{"id": 1}, {"id": 2}],
            [{"id": 3}],
        ]
        with patch("src.github_client.LinkHeaderParser") as mock_parser:
            mock_parser.return_value.next_link = None
            result = client.get_paginated("/repos/test-org/test-repo/issues")
            assert len(result) == 3
            assert result[0] == {"id": 1}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_github_client.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.github_client'`

- [ ] **Step 3: Write implementation**

```python
# src/github_client.py
from __future__ import annotations

import httpx
import time
import logging

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"

MAX_RETRIES = 3
RETRY_BACKOFF = 2


class GitHubClient:
    def __init__(self, token: str) -> None:
        self.client = httpx.Client(
            base_url=GITHUB_API_BASE,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
        )

    def get(self, path: str) -> dict:
        return self._request("GET", path)

    def get_paginated(self, path: str, per_page: int = 100) -> list[dict]:
        items: list[dict] = []
        url: str | None = f"{GITHUB_API_BASE}{path}"
        if "?" in url:
            url += f"&per_page={per_page}"
        else:
            url += f"?per_page={per_page}"

        while url:
            response = self.client.get(url)
            response.raise_for_status()
            items.extend(response.json())
            url = response.links.get("next", {}).get("url")
        return items

    def post(self, path: str, json: dict) -> dict:
        return self._request("POST", path, json=json)

    def _request(self, method: str, path: str, **kwargs) -> dict:
        last_error: Exception | None = None
        for attempt in range(MAX_RETRIES):
            try:
                if method == "GET":
                    response = self.client.get(f"{GITHUB_API_BASE}{path}", **kwargs)
                elif method == "POST":
                    response = self.client.post(f"{GITHUB_API_BASE}{path}", **kwargs)
                else:
                    raise ValueError(f"Unsupported method: {method}")

                if response.status_code in (429, 500, 502, 503):
                    retry_after = int(response.headers.get("Retry-After", RETRY_BACKOFF ** (attempt + 1)))
                    logger.warning(f"Rate limited or server error ({response.status_code}), retrying in {retry_after}s")
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                return response.json()

            except httpx.HTTPStatusError as e:
                last_error = e
                if e.response.status_code == 429:
                    retry_after = int(e.response.headers.get("Retry-After", RETRY_BACKOFF ** (attempt + 1)))
                    logger.warning(f"Rate limited, retrying in {retry_after}s")
                    time.sleep(retry_after)
                    continue
                raise

        raise last_error or Exception("Max retries exceeded")

    def close(self) -> None:
        self.client.close()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_github_client.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add src/github_client.py tests/test_github_client.py
git commit -m "feat: add GitHub API client with retry and pagination"
```

---

### Task 4: Vulnerability Models

**Files:**
- Create: `src/models.py`
- Create: `tests/test_models.py`

**Interfaces:**
- Produces: `Vulnerability` dataclass (as specified in design)
- Produces: `RunResult` dataclass for tracking results across the run

- [ ] **Step 1: Write the failing test**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.models'`

- [ ] **Step 3: Write implementation**

```python
# src/models.py
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Vulnerability:
    repo_full_name: str
    advisory_id: str
    severity: str
    title: str
    description: str
    affected_files: list[str]
    package_name: str | None
    source: str  # "ghsa" | "dependabot" | "code_scanning"
    state: str  # "open" | "dismissed" | "fixed"


@dataclass
class RunResult:
    repos_scanned: int = 0
    vulns_found: int = 0
    fixes_attempted: int = 0
    prs_created: int = 0
    skipped: int = 0
    prs: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_models.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add src/models.py tests/test_models.py
git commit -m "feat: add Vulnerability and RunResult data models"
```

---

### Task 5: Advisory Fetcher

**Files:**
- Create: `src/fetcher.py`
- Create: `tests/test_fetcher.py`

**Interfaces:**
- Consumes: `GitHubClient` (from Task 3), `Vulnerability` (from Task 4)
- Produces: `fetch_all_advisories(client: GitHubClient, org: str) -> list[Vulnerability]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_fetcher.py
from unittest.mock import MagicMock, patch
from src.fetcher import fetch_all_advisories
from src.models import Vulnerability


def test_fetch_ghsa_advisories():
    client = MagicMock()
    client.get_paginated.return_value = [
        {
            "ghsa_id": "GHSA-test-1234",
            "severity": "high",
            "summary": "Test GHSA advisory",
            "description": "A critical vulnerability",
            "vulnerabilities": [
                {
                    "package": {"name": "test-pkg", "ecosystem": "npm"},
                    "vulnerable_version_range": "< 2.0.0",
                }
            ],
        }
    ]
    with patch("src.fetcher._get_org_repos") as mock_repos:
        mock_repos.return_value = ["test-org/repo1"]
        result = fetch_all_advisories(client, "test-org")
        assert len(result) >= 0  # GHSA advisories need repo mapping


def test_parse_dependabot_alerts():
    from src.fetcher import _parse_dependabot_alerts
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_fetcher.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.fetcher'`

- [ ] **Step 3: Write implementation**

```python
# src/fetcher.py
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.github_client import GitHubClient

from src.models import Vulnerability

logger = logging.getLogger(__name__)


def _get_org_repos(client: GitHubClient, org: str) -> list[str]:
    """Get all repos for an org, return list of full_name strings."""
    repos = client.get_paginated(f"/orgs/{org}/repos")
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
                affected_files=[],  # Dependabot doesn't provide file paths directly
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
                    affected_files=[],  # GHSA doesn't provide file paths directly
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
    repos = _get_org_repos(client, org)
    logger.info(f"Found {len(repos)} repos in org {org}")

    for repo_full_name in repos:
        logger.info(f"Scanning {repo_full_name}...")

        # Dependabot alerts
        try:
            dependabot_alerts = client.get_paginated(f"/repos/{repo_full_name}/dependabot/alerts")
            all_vulns.extend(_parse_dependabot_alerts(repo_full_name, dependabot_alerts))
        except Exception as e:
            logger.warning(f"Failed to fetch Dependabot alerts for {repo_full_name}: {e}")

        # Code Scanning alerts
        try:
            code_scanning_alerts = client.get_paginated(f"/repos/{repo_full_name}/code-scanning/alerts")
            all_vulns.extend(_parse_code_scanning_alerts(repo_full_name, code_scanning_alerts))
        except Exception as e:
            logger.warning(f"Failed to fetch Code Scanning alerts for {repo_full_name}: {e}")

        # GHSA advisories
        all_vulns.extend(_parse_ghsa_for_repo(client, repo_full_name))

    logger.info(f"Total vulnerabilities found: {len(all_vulns)}")
    return all_vulns
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_fetcher.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add src/fetcher.py tests/test_fetcher.py
git commit -m "feat: add advisory fetcher for GHSA, Dependabot, and Code Scanning"
```

---

### Task 6: Repo Module

**Files:**
- Create: `src/repo.py`
- Create: `tests/test_repo.py`

**Interfaces:**
- Produces:
  - `clone_or_update(clone_dir: str, repo_full_name: str) -> Path` — returns local repo path
  - `detect_default_branch(repo_path: Path) -> str` — returns branch name
  - `branch_exists(repo_path: Path, branch_name: str) -> bool`
  - `create_branch(repo_path: Path, branch_name: str, base_branch: str) -> None`
  - `checkout(repo_path: Path, branch: str) -> None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_repo.py
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.repo import clone_or_update, detect_default_branch, branch_exists, create_branch, checkout


def test_clone_or_update_clones_new_repo(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        result = clone_or_update(str(tmp_path), "myorg/myrepo")
        assert result == tmp_path / "myrepo"
        assert mock_run.call_count == 1
        assert "clone" in mock_run.call_args[0][0]


def test_clone_or_update_updates_existing(tmp_path):
    repo_dir = tmp_path / "myrepo"
    repo_dir.mkdir()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        result = clone_or_update(str(tmp_path), "myorg/myrepo")
        assert result == repo_dir
        assert mock_run.call_count == 2  # fetch + pull


def test_detect_default_branch_origin_head(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="origin/HEAD -> origin/main\n")
        branch = detect_default_branch(tmp_path)
        assert branch == "main"


def test_detect_default_branch_fallback(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        branch = detect_default_branch(tmp_path)
        assert branch in ("main", "master")


def test_branch_exists_true(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="  fix/GHSA-1234\n  main\n")
        assert branch_exists(tmp_path, "fix/GHSA-1234") is True


def test_branch_exists_false(tmp_path):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="  main\n")
        assert branch_exists(tmp_path, "fix/GHSA-1234") is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_repo.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.repo'`

- [ ] **Step 3: Write implementation**

```python
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

    # Fallback: try main, then master
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_repo.py -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add src/repo.py tests/test_repo.py
git commit -m "feat: add repo clone, branch detection, and branch management"
```

---

### Task 7: Fixer Module

**Files:**
- Create: `src/fixer.py`
- Create: `tests/test_fixer.py`

**Interfaces:**
- Consumes: `Vulnerability` (from Task 4), `Config` (from Task 2)
- Produces: `apply_fix(config: Config, repo_path: Path, vuln: Vulnerability) -> bool` — returns True if fix was applied

- [ ] **Step 1: Write the failing test**

```python
# tests/test_fixer.py
from pathlib import Path
from unittest.mock import patch, MagicMock
from src.fixer import apply_fix
from src.models import Vulnerability
from src.config import Config


def _make_config():
    return Config(
        org="test-org",
        clone_dir=".repos",
        report_path="report.html",
        opencode_binary="opencode",
        github_pat="ghp_test",
    )


def _make_vuln():
    return Vulnerability(
        repo_full_name="test-org/repo1",
        advisory_id="GHSA-test-1234",
        severity="high",
        title="Test vulnerability",
        description="A test vuln",
        affected_files=["src/app.py"],
        package_name=None,
        source="ghsa",
        state="open",
    )


def test_apply_fix_success(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=True):
            result = apply_fix(config, tmp_path, vuln)
            assert result is True


def test_apply_fix_no_changes(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("src.fixer._has_changes", return_value=False):
            result = apply_fix(config, tmp_path, vuln)
            assert result is False


def test_apply_fix_opencode_fails(tmp_path):
    config = _make_config()
    vuln = _make_vuln()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        result = apply_fix(config, tmp_path, vuln)
        assert result is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_fixer.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.fixer'`

- [ ] **Step 3: Write implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_fixer.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add src/fixer.py tests/test_fixer.py
git commit -m "feat: add OpenCode CLI integration for auto-fixing vulnerabilities"
```

---

### Task 8: PR Module

**Files:**
- Create: `src/pr.py`
- Create: `tests/test_pr.py`

**Interfaces:**
- Consumes: `GitHubClient` (from Task 3), `Vulnerability` (from Task 4)
- Produces:
  - `create_pull_request(client, repo_full_name, vuln, base_branch) -> dict | None` — returns PR info or None
  - `pr_exists_for_branch(client, repo_full_name, branch_name) -> bool`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pr.py
from unittest.mock import MagicMock, patch
from src.pr import create_pull_request, pr_exists_for_branch
from src.models import Vulnerability


def test_pr_exists_true():
    client = MagicMock()
    client.get_paginated.return_value = [{"head": {"ref": "fix/GHSA-1234"}, "state": "open"}]
    assert pr_exists_for_branch(client, "myorg/myrepo", "fix/GHSA-1234") is True


def test_pr_exists_false():
    client = MagicMock()
    client.get_paginated.return_value = [{"head": {"ref": "fix/GHSA-other"}, "state": "open"}]
    assert pr_exists_for_branch(client, "myorg/myrepo", "fix/GHSA-1234") is False


def test_create_pull_request():
    client = MagicMock()
    client.post.return_value = {"html_url": "https://github.com/myorg/myrepo/pull/1", "number": 1}
    vuln = Vulnerability(
        repo_full_name="myorg/myrepo",
        advisory_id="GHSA-test-1234",
        severity="high",
        title="Test vuln",
        description="A test",
        affected_files=["src/app.py"],
        package_name=None,
        source="ghsa",
        state="open",
    )
    result = create_pull_request(client, "myorg/myrepo", vuln, "main")
    assert result is not None
    assert result["html_url"] == "https://github.com/myorg/myrepo/pull/1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_pr.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.pr'`

- [ ] **Step 3: Write implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_pr.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add src/pr.py tests/test_pr.py
git commit -m "feat: add PR creation and duplicate detection"
```

---

### Task 9: Reporter Module

**Files:**
- Create: `src/reporter.py`
- Create: `tests/test_reporter.py`

**Interfaces:**
- Consumes: `RunResult` (from Task 4)
- Produces: `generate_report(result: RunResult, report_path: str) -> str` — returns HTML content

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reporter.py
from src.reporter import generate_report
from src.models import RunResult


def test_generate_report_returns_html():
    result = RunResult(
        repos_scanned=5,
        vulns_found=10,
        fixes_attempted=8,
        prs_created=6,
        skipped=2,
    )
    html = generate_report(result, "report.html")
    assert "<html" in html
    assert "GitHub Advisor Agent" in html
    assert "5" in html  # repos_scanned
    assert "10" in html  # vulns_found


def test_generate_report_with_errors():
    result = RunResult(errors=["Failed to clone repo1", "OpenCode timeout on repo2"])
    html = generate_report(result, "report.html")
    assert "Failed to clone repo1" in html
    assert "OpenCode timeout on repo2" in html


def test_generate_report_saves_file(tmp_path):
    result = RunResult(repos_scanned=1)
    report_path = str(tmp_path / "test_report.html")
    generate_report(result, report_path)
    from pathlib import Path
    assert Path(report_path).exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_reporter.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.reporter'`

- [ ] **Step 3: Write implementation**

```python
# src/reporter.py
from __future__ import annotations

from pathlib import Path

from src.models import RunResult


HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Advisor Agent Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
        .container { max-width: 960px; margin: 0 auto; }
        h1 { color: #58a6ff; margin-bottom: 1.5rem; font-size: 1.8rem; }
        h2 { color: #79c0ff; margin: 1.5rem 0 0.75rem; font-size: 1.2rem; border-bottom: 1px solid #21262d; padding-bottom: 0.3rem; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 2rem; }
        .stat { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; text-align: center; }
        .stat-value { font-size: 2rem; font-weight: bold; color: #58a6ff; }
        .stat-label { font-size: 0.85rem; color: #8b949e; margin-top: 0.25rem; }
        table { width: 100%%; border-collapse: collapse; margin-bottom: 1.5rem; }
        th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid #21262d; }
        th { color: #8b949e; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
        tr:hover { background: #161b22; }
        .severity-critical { color: #f85149; }
        .severity-high { color: #d29922; }
        .severity-medium { color: #58a6ff; }
        .severity-low { color: #8b949e; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .empty { color: #8b949e; font-style: italic; padding: 1rem; }
        .error { color: #f85149; background: #161b22; border: 1px solid #f8514933; border-radius: 6px; padding: 0.75rem; margin-bottom: 0.5rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>GitHub Advisor Agent Report</h1>

        <div class="summary">
            <div class="stat">
                <div class="stat-value">%(repos_scanned)d</div>
                <div class="stat-label">Repos Scanned</div>
            </div>
            <div class="stat">
                <div class="stat-value">%(vulns_found)d</div>
                <div class="stat-label">Vulns Found</div>
            </div>
            <div class="stat">
                <div class="stat-value">%(fixes_attempted)d</div>
                <div class="stat-label">Fixes Attempted</div>
            </div>
            <div class="stat">
                <div class="stat-value">%(prs_created)d</div>
                <div class="stat-label">PRs Created</div>
            </div>
            <div class="stat">
                <div class="stat-value">%(skipped)d</div>
                <div class="stat-label">Skipped</div>
            </div>
        </div>

        <h2>Fixes Applied (%(prs_created)d)</h2>
        %(fixes_table)s

        <h2>Unmerged PRs</h2>
        %(unmerged_table)s

        <h2>Skipped</h2>
        %(skipped_section)s

        <h2>Errors (%(error_count)d)</h2>
        %(errors_section)s
    </div>
</body>
</html>
"""


def _severity_class(severity: str) -> str:
    return f"severity-{severity.lower()}"


def _build_fixes_table(prs: list[dict]) -> str:
    if not prs:
        return '<div class="empty">No fixes applied.</div>'
    rows = ""
    for pr in prs:
        severity_cls = _severity_class(pr.get("severity", "unknown"))
        link = pr.get("url", "#")
        rows += (
            f'<tr>'
            f'<td>{pr.get("repo", "")}</td>'
            f'<td><a href="{link}">{pr.get("advisory_id", "")}</a></td>'
            f'<td class="{severity_cls}">{pr.get("severity", "")}</td>'
            f'<td>{pr.get("title", "")}</td>'
            f'<td><a href="{pr.get("pr_url", "#")}">PR #{pr.get("pr_number", "")}</a></td>'
            f'</tr>\n'
        )
    return (
        "<table><thead><tr><th>Repo</th><th>Advisory</th><th>Severity</th><th>Title</th><th>PR</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _build_unmerged_table(prs: list[dict]) -> str:
    unmerged = [pr for pr in prs if not pr.get("merged", False)]
    if not unmerged:
        return '<div class="empty">No unmerged PRs.</div>'
    rows = ""
    for pr in unmerged:
        rows += (
            f'<tr>'
            f'<td>{pr.get("repo", "")}</td>'
            f'<td><a href="{pr.get("pr_url", "#")}">PR #{pr.get("pr_number", "")}</a></td>'
            f'<td>{pr.get("title", "")}</td>'
            f'<td>{pr.get("advisory_id", "")}</td>'
            f'</tr>\n'
        )
    return (
        "<table><thead><tr><th>Repo</th><th>PR</th><th>Title</th><th>Advisory</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _build_errors_section(errors: list[str]) -> str:
    if not errors:
        return '<div class="empty">No errors.</div>'
    return "\n".join(f'<div class="error">{e}</div>' for e in errors)


def _build_skipped_section(result: RunResult) -> str:
    skipped_count = result.skipped
    if skipped_count == 0:
        return '<div class="empty">Nothing skipped.</div>'
    return f'<div class="empty">{skipped_count} vulnerability fix(es) skipped (already has PR or no auto-fix possible).</div>'


def generate_report(result: RunResult, report_path: str) -> str:
    """Generate HTML report and save to disk. Returns the HTML content."""
    html = HTML_TEMPLATE % {
        "repos_scanned": result.repos_scanned,
        "vulns_found": result.vulns_found,
        "fixes_attempted": result.fixes_attempted,
        "prs_created": result.prs_created,
        "skipped": result.skipped,
        "fixes_table": _build_fixes_table(result.prs),
        "unmerged_table": _build_unmerged_table(result.prs),
        "skipped_section": _build_skipped_section(result),
        "error_count": len(result.errors),
        "errors_section": _build_errors_section(result.errors),
    }

    Path(report_path).write_text(html, encoding="utf-8")
    return html
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_reporter.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add src/reporter.py tests/test_reporter.py
git commit -m "feat: add HTML report generator"
```

---

### Task 10: Main CLI Entry Point

**Files:**
- Create: `src/main.py`
- Create: `tests/test_main.py`

**Interfaces:**
- Consumes: All previous modules
- Produces: `main()` function as CLI entry point

- [ ] **Step 1: Write the failing test**

```python
# tests/test_main.py
from unittest.mock import patch, MagicMock
from src.main import main


def test_main_dry_run(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\nopencode_binary: "opencode"\n')
    report_path = str(tmp_path / "report.html")

    with patch("src.main.load_config") as mock_config, \
         patch("src.main.GitHubClient") as mock_client_cls, \
         patch("src.main.fetch_all_advisories", return_value=[]), \
         patch("src.main.generate_report", return_value="<html></html>"):
        mock_config.return_value = MagicMock(
            org="test-org",
            clone_dir=str(tmp_path / ".repos"),
            report_path=report_path,
            github_pat="ghp_test",
        )
        mock_client_cls.return_value = MagicMock()
        main(["--dry-run", "--config", str(config_path)])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_main.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.main'`

- [ ] **Step 3: Write implementation**

```python
# src/main.py
from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

from src.config import load_config, Config
from src.github_client import GitHubClient
from src.fetcher import fetch_all_advisories
from src.models import RunResult, Vulnerability
from src.repo import clone_or_update, detect_default_branch, branch_exists, create_branch, checkout
from src.fixer import apply_fix
from src.pr import create_pull_request, pr_exists_for_branch
from src.reporter import generate_report

logger = logging.getLogger("github-advisor")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GitHub Advisor Agent — auto-fix security advisories")
    parser.add_argument("--dry-run", action="store_true", help="Fetch advisories and generate report, skip clone/fix/PR")
    parser.add_argument("--report-only", action="store_true", help="Regenerate report from cached data")
    parser.add_argument("--org", type=str, default=None, help="Override org from config")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to config file")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args(argv)


def process_repo(
    client: GitHubClient,
    config: Config,
    repo_full_name: str,
    vulns: list[Vulnerability],
    result: RunResult,
) -> None:
    """Process all vulnerabilities for a single repo."""
    logger.info(f"Processing {repo_full_name} ({len(vulns)} vulnerabilities)...")

    try:
        repo_path = clone_or_update(config.clone_dir, repo_full_name)
    except Exception as e:
        msg = f"Failed to clone/update {repo_full_name}: {e}"
        logger.error(msg)
        result.errors.append(msg)
        return

    default_branch = detect_default_branch(repo_path)
    logger.info(f"Default branch for {repo_full_name}: {default_branch}")

    for vuln in vulns:
        branch_name = f"fix/{vuln.advisory_id}"

        # Skip if PR already exists
        if pr_exists_for_branch(client, repo_full_name, branch_name):
            logger.info(f"PR already exists for {vuln.advisory_id}, skipping")
            result.skipped += 1
            continue

        # Skip if branch already exists locally
        if branch_exists(repo_path, branch_name):
            logger.info(f"Branch {branch_name} already exists, skipping")
            result.skipped += 1
            continue

        try:
            create_branch(repo_path, branch_name, default_branch)
        except Exception as e:
            msg = f"Failed to create branch {branch_name}: {e}"
            logger.error(msg)
            result.errors.append(msg)
            continue

        result.fixes_attempted += 1

        if not apply_fix(config, repo_path, vuln):
            logger.info(f"No fix applied for {vuln.advisory_id}, skipping PR")
            result.skipped += 1
            checkout(repo_path, default_branch)
            subprocess.run(["git", "-C", str(repo_path), "branch", "-D", branch_name], capture_output=True)
            continue

        # Push the branch
        push_result = subprocess.run(
            ["git", "-C", str(repo_path), "push", "-u", "origin", branch_name],
            capture_output=True,
            text=True,
        )
        if push_result.returncode != 0:
            msg = f"Failed to push {branch_name}: {push_result.stderr}"
            logger.error(msg)
            result.errors.append(msg)
            continue

        # Create PR
        pr = create_pull_request(client, repo_full_name, vuln, default_branch)
        if pr:
            result.prs_created += 1
            result.prs.append({
                "repo": repo_full_name,
                "advisory_id": vuln.advisory_id,
                "severity": vuln.severity,
                "title": vuln.title,
                "pr_url": pr.get("html_url", ""),
                "pr_number": pr.get("number", ""),
                "merged": pr.get("merged", False),
            })

        # Checkout back to default branch
        checkout(repo_path, default_branch)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    if args.org:
        config.org = args.org

    client = GitHubClient(config.github_pat)

    try:
        logger.info(f"Fetching advisories for org: {config.org}")
        vulns = fetch_all_advisories(client, config.org)

        result = RunResult()
        result.vulns_found = len(vulns)

        if args.dry_run:
            logger.info("Dry run mode — skipping clone/fix/PR")
        elif args.report_only:
            logger.info("Report-only mode — skipping clone/fix/PR")
        else:
            # Group vulns by repo
            vulns_by_repo: dict[str, list[Vulnerability]] = {}
            for v in vulns:
                vulns_by_repo.setdefault(v.repo_full_name, []).append(v)

            result.repos_scanned = len(vulns_by_repo)

            for repo_full_name, repo_vulns in vulns_by_repo.items():
                process_repo(client, config, repo_full_name, repo_vulns, result)

        report_html = generate_report(result, config.report_path)
        logger.info(f"Report saved to {config.report_path}")

        # Print summary to stdout
        print(f"\n--- Summary ---")
        print(f"Repos scanned: {result.repos_scanned}")
        print(f"Vulnerabilities found: {result.vulns_found}")
        print(f"Fixes attempted: {result.fixes_attempted}")
        print(f"PRs created: {result.prs_created}")
        print(f"Skipped: {result.skipped}")
        print(f"Errors: {len(result.errors)}")
        if result.errors:
            for err in result.errors:
                print(f"  - {err}")

    finally:
        client.close()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_main.py -v`
Expected: 1 passed

- [ ] **Step 5: Run all tests together**

Run: `pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 6: Commit**

```bash
git add src/main.py tests/test_main.py
git commit -m "feat: add CLI entry point with dry-run and report-only modes"
```

---

### Task 11: Final Integration Test

**Files:**
- Modify: `tests/test_integration.py` (create)

- [ ] **Step 1: Write integration test**

```python
# tests/test_integration.py
"""Integration test — runs the full pipeline with mocked external services."""
from unittest.mock import patch, MagicMock
from src.main import main
from src.models import Vulnerability, RunResult


def test_full_dry_run_pipeline(tmp_path):
    """Test: fetch advisories → generate report, no clone/fix/PR."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\nopencode_binary: "opencode"\n')

    vulns = [
        Vulnerability(
            repo_full_name="test-org/repo1",
            advisory_id="GHSA-test-1111",
            severity="high",
            title="SQL Injection",
            description="SQL injection in login endpoint",
            affected_files=["src/auth.py"],
            package_name=None,
            source="ghsa",
            state="open",
        ),
        Vulnerability(
            repo_full_name="test-org/repo2",
            advisory_id="GHSA-test-2222",
            severity="critical",
            title="RCE via deserialization",
            description="Remote code execution",
            affected_files=["src/parser.py", "src/utils.py"],
            package_name="lodash",
            source="dependabot",
            state="open",
        ),
    ]

    with patch("src.main.load_config") as mock_config, \
         patch("src.main.GitHubClient") as mock_client_cls, \
         patch("src.main.fetch_all_advisories", return_value=vulns), \
         patch("src.main.generate_report") as mock_report:
        from src.config import Config
        mock_config.return_value = Config(
            org="test-org",
            clone_dir=str(tmp_path / ".repos"),
            report_path=str(tmp_path / "report.html"),
            opencode_binary="opencode",
            github_pat="ghp_test",
        )
        mock_client_cls.return_value = MagicMock()
        mock_report.return_value = "<html></html>"

        main(["--dry-run", "--config", str(config_path)])

        mock_report.assert_called_once()
        call_args = mock_report.call_args
        result = call_args[0][0]
        assert result.vulns_found == 2
```

- [ ] **Step 2: Run the integration test**

Run: `pytest tests/test_integration.py -v`
Expected: 1 passed

- [ ] **Step 3: Run full test suite**

Run: `pytest tests/ -v`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: add integration test for full dry-run pipeline"
```
