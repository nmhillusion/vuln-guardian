# src/sbom.py
"""Resolve transitive dependency chains via the GitHub Dependency Graph SBOM."""
from __future__ import annotations

import logging
from collections import deque
from typing import TYPE_CHECKING
from urllib.parse import unquote

if TYPE_CHECKING:
    from src.github_client import GitHubClient

logger = logging.getLogger(__name__)


def _purl(pkg: dict) -> str:
    for ref in pkg.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator", "")
    return pkg.get("name", "")


def _short_name(purl: str) -> str:
    """pkg:maven/com.h2database/h2@2.1.214?... -> com.h2database:h2@2.1.214"""
    loc = purl.split("?", 1)[0]
    if loc.startswith("pkg:maven/"):
        rest = loc[len("pkg:maven/"):]
        group_path, _, artifact_version = rest.rpartition("/")
        group = group_path.replace("/", ".")
        artifact, _, version = artifact_version.partition("@")
        label = f"{group}:{artifact}" if group else artifact
        return f"{label}@{version}" if version else label
    return unquote(loc)


def _purl_matches(purl: str, ecosystem: str, package_name: str) -> bool:
    loc = purl.split("?", 1)[0]
    if ecosystem == "maven":
        if not loc.startswith("pkg:maven/"):
            return False
        rest = loc[len("pkg:maven/"):]
        group_path, _, artifact_version = rest.rpartition("/")
        artifact = artifact_version.split("@")[0]
        group = group_path.replace("/", ".")
        return package_name in (f"{group}:{artifact}", artifact)
    if ecosystem == "npm":
        if not loc.startswith("pkg:npm/"):
            return False
        rest = unquote(loc[len("pkg:npm/"):])
        if rest.startswith("@"):
            name, _, _version = rest[1:].partition("@")
            name = "@" + name
        else:
            name, _, _version = rest.partition("@")
        return package_name == name
    return package_name in loc


def find_chain(sbom: dict, ecosystem: str, package_name: str) -> list[str] | None:
    """BFS from SBOM roots to the package. Returns short-name path or None."""
    pkgs = {p.get("SPDXID", ""): p for p in sbom.get("packages", [])}
    adj: dict[str, list[str]] = {}
    roots: list[str] = []
    for rel in sbom.get("relationships", []):
        if rel.get("relationshipType") == "DESCRIBES":
            roots.append(rel.get("relatedSpdxElement", ""))
        elif rel.get("relationshipType") == "DEPENDS_ON":
            adj.setdefault(rel.get("spdxElementId", ""), []).append(rel.get("relatedSpdxElement", ""))

    target = next(
        (pid for pid, p in pkgs.items() if _purl_matches(_purl(p), ecosystem, package_name)),
        None,
    )
    if target is None:
        return None

    prev: dict[str, str | None] = {r: None for r in roots}
    queue: deque[str] = deque(roots)
    found = False
    while queue:
        cur = queue.popleft()
        if cur == target:
            found = True
            break
        for nxt in adj.get(cur, []):
            if nxt not in prev:
                prev[nxt] = cur
                queue.append(nxt)
    if not found:
        return None

    path: list[str] = []
    cur: str | None = target
    while cur is not None:
        path.append(_short_name(_purl(pkgs.get(cur, {}))))
        cur = prev.get(cur)
    path.reverse()
    return path


def fetch_sbom(client: GitHubClient, repo_full_name: str) -> dict | None:
    """Fetch the repo SBOM document. Returns None when unavailable."""
    try:
        data = client.get(f"/repos/{repo_full_name}/dependency-graph/sbom")
    except Exception as e:
        logger.warning(f"Failed to fetch SBOM for {repo_full_name}: {e}")
        return None
    return data.get("sbom", data)


def get_dependency_chain(
    client: GitHubClient, repo_full_name: str, ecosystem: str, package_name: str
) -> list[str] | None:
    """Fetch repo SBOM and resolve the dependency chain. Returns None when unavailable."""
    sbom = fetch_sbom(client, repo_full_name)
    if not sbom:
        return None
    try:
        return find_chain(sbom, ecosystem, package_name)
    except Exception as e:
        logger.warning(f"Failed to resolve chain for {package_name} in {repo_full_name}: {e}")
        return None
