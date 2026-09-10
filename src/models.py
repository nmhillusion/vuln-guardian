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
