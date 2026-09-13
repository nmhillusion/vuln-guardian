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
    ecosystem: str | None = None  # "maven" | "npm" | ...
    dependency_chain: list[str] | None = None  # root -> ... -> package
    parent_version: str | None = None  # latest release of the direct parent
    patched_version: str | None = None  # first version containing a fix
    vulnerable_range: str | None = None  # e.g. "< 4.17.21"
    manifest_path: str | None = None  # e.g. "backend/pom.xml"
    dependency_relationship: str | None = None  # "direct" | "transitive"
    dependency_scope: str | None = None  # "runtime" | "development"
    start_line: int | None = None  # code-scanning location
    end_line: int | None = None  # code-scanning location
    introduced_at: str | None = None  # multi-line snippet with context


@dataclass
class RunResult:
    repos_scanned: int = 0
    vulns_found: int = 0
    fixes_attempted: int = 0
    prs_created: int = 0
    skipped: int = 0
    prs: list[dict] = field(default_factory=list)
    pending_prs: list[dict] = field(default_factory=list)  # open tool PRs from any run
    skipped_items: list[dict] = field(default_factory=list)  # {repo, advisory_id, reason}
    errors: list[str] = field(default_factory=list)
