# src/maven.py
"""Resolve latest releases from Maven Central (plain HTTP, no tokens)."""
from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

import httpx

logger = logging.getLogger(__name__)

MAVEN_CENTRAL = "https://repo.maven.apache.org/maven2"
_TIMEOUT = 15.0


def get_latest_version(group: str, artifact: str) -> str | None:
    """Return <latest> from maven-metadata.xml, falling back to last listed version."""
    url = f"{MAVEN_CENTRAL}/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
    try:
        response = httpx.get(url, timeout=_TIMEOUT)
        response.raise_for_status()
    except Exception as e:
        logger.warning(f"Failed to fetch maven metadata for {group}:{artifact}: {e}")
        return None
    try:
        root = ET.fromstring(response.text)
    except ET.ParseError as e:
        logger.warning(f"Failed to parse maven metadata for {group}:{artifact}: {e}")
        return None
    versioning = root.find("versioning")
    if versioning is None:
        return None
    latest = versioning.findtext("latest")
    if latest and latest.strip():
        return latest.strip()
    versions = [v.text.strip() for v in versioning.findall("versions/version") if v.text and v.text.strip()]
    return versions[-1] if versions else None


def parse_maven_parent(label: str) -> tuple[str, str] | None:
    """'org.owasp:dependency-check-core@9.2.0' -> ('org.owasp', 'dependency-check-core')."""
    if label.startswith("pkg:") or ":" not in label:
        return None
    group, _, rest = label.rpartition(":")
    artifact = rest.split("@")[0]
    if not group or not artifact:
        return None
    return group, artifact
