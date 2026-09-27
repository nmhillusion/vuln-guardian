# src/maven.py
"""Resolve latest releases from Maven Central (plain HTTP, no tokens)."""
from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET

import httpx

logger = logging.getLogger(__name__)

MAVEN_CENTRAL = "https://repo.maven.apache.org/maven2"
_TIMEOUT = 15.0

_UNSTABLE_TOKEN_RE = re.compile(
    r"^(snapshot|snapshot-.+|m\d+|rc\d*|cr\d*|alpha.*|beta.*|eap.*|preview.*|milestone.*)$"
)


def is_stable_version(version: str) -> bool:
    """True for stable releases (e.g. 6.2.19, 7.0.9, 3.0.0.RELEASE).

    Rejects milestones, snapshots, alphas, betas, RCs and similar
    pre-releases (e.g. 7.1.0-M2, 5.7-alpha1, 7.0.0-RC1, 2.0-SNAPSHOT).
    """
    low = version.strip().lower()
    if not low or "snapshot" in low:
        return False
    tokens = re.split(r"[.\-_+]", low)
    return not any(_UNSTABLE_TOKEN_RE.match(t) for t in tokens if t)


def _fetch_versioning(group: str, artifact: str) -> ET.Element | None:
    """Fetch and parse maven-metadata.xml <versioning>. None on any failure."""
    url = f"{MAVEN_CENTRAL}/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
    try:
        response = httpx.get(url, timeout=_TIMEOUT)
        response.raise_for_status()
        root = ET.fromstring(response.text)
    except Exception as e:
        logger.warning(f"Failed to fetch maven metadata for {group}:{artifact}: {e}")
        return None
    versioning = root.find("versioning")
    if versioning is None:
        logger.warning(f"No <versioning> in maven metadata for {group}:{artifact}")
    return versioning


def get_latest_version(group: str, artifact: str) -> str | None:
    """Return the newest STABLE version from maven-metadata.xml.

    Prefers <release> when stable, then <latest> when stable, then falls
    back to the newest stable entry in <versions>. Returns None when only
    pre-releases are available (caller must treat as unfixable-by-bump).
    """
    versioning = _fetch_versioning(group, artifact)
    if versioning is None:
        return None
    release = (versioning.findtext("release") or "").strip()
    if release and is_stable_version(release):
        return release
    latest = (versioning.findtext("latest") or "").strip()
    if latest and is_stable_version(latest):
        return latest
    versions = [v.text.strip() for v in versioning.findall("versions/version") if v.text and v.text.strip()]
    for v in reversed(versions):
        if is_stable_version(v):
            return v
    logger.warning(f"No stable version found for {group}:{artifact}")
    return None


def version_exists_on_central(group: str, artifact: str, version: str) -> bool | None:
    """Check a version against Maven Central's <versions> list.

    Returns True (exists), False (confirmed missing — do NOT use it), or
    None when Central is unreachable (unknown — caller must not block on it).
    """
    try:
        url = f"{MAVEN_CENTRAL}/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
        response = httpx.get(url, timeout=_TIMEOUT)
        response.raise_for_status()
        root = ET.fromstring(response.text)
    except Exception as e:
        logger.warning(f"Could not verify {group}:{artifact}:{version} on Central: {e}")
        return None
    versioning = root.find("versioning")
    if versioning is None:
        return None
    known = {
        v.text.strip()
        for v in versioning.findall("versions/version")
        if v.text and v.text.strip()
    }
    return version.strip() in known


def parse_maven_parent(label: str) -> tuple[str, str] | None:
    """'org.owasp:dependency-check-core@9.2.0' -> ('org.owasp', 'dependency-check-core')."""
    if label.startswith("pkg:") or ":" not in label:
        return None
    group, _, rest = label.rpartition(":")
    artifact = rest.split("@")[0]
    if not group or not artifact:
        return None
    return group, artifact
