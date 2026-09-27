# src/state.py
"""Persistent memory of definitively-unfixable advisories.

A JSON state file records (repo, advisory) verdicts that the agent or the
Python guards declared unfixable. Entries expire after
CANNOT_FIX_TTL_SECONDS (3 days) so entries are retried, and are keyed by a
hash of the fix logic so prompt/code changes invalidate old verdicts.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

CANNOT_FIX_TTL_SECONDS = 3 * 24 * 3600
_CODE_VERSION_FILES = ("fixer.py", "maven.py")


def current_code_version() -> str:
    """Short hash of the fix-logic sources; changes invalidate cached verdicts."""
    digest = hashlib.sha1()
    base = Path(__file__).resolve().parent
    for name in _CODE_VERSION_FILES:
        try:
            digest.update((base / name).read_bytes())
        except OSError:
            digest.update(name.encode())
    return digest.hexdigest()[:12]


def load_state(state_path: str) -> dict:
    """Load state; {} when missing/unusable (never raises). Empty path disables."""
    if not state_path:
        return {}
    try:
        return json.loads(Path(state_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        if Path(state_path).exists():
            logger.warning(f"Ignoring malformed state file {state_path}: {e}")
        return {}


def save_state(state_path: str, state: dict) -> None:
    """Persist state; warns instead of raising. Empty path disables."""
    if not state_path:
        return
    try:
        Path(state_path).write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as e:
        logger.warning(f"Failed to save state file {state_path}: {e}")


def is_definitive_refusal(reason: str) -> bool:
    """True for agent/Python verdicts that will not change on retry.

    Infra failures (timeouts, agent errors, commit failures) and silent
    no-change runs are NOT definitive and keep retrying every run.
    """
    low = (reason or "").strip().lower()
    return low.startswith("cannot fix:") or low.startswith("nonexistent version")


def is_unfixable_cached(
    state: dict, repo_full_name: str, advisory_id: str, now: float | None = None
) -> tuple[bool, str]:
    """Check for a live cached verdict. Returns (hit, reason)."""
    entry = state.get(repo_full_name, {}).get(advisory_id)
    if not isinstance(entry, dict):
        return False, ""
    if entry.get("code_version") != current_code_version():
        return False, ""
    at = entry.get("ts", 0)
    now = time.time() if now is None else now
    if now - at >= CANNOT_FIX_TTL_SECONDS:
        return False, ""
    return True, entry.get("reason", "")


def record_unfixable(
    state: dict, repo_full_name: str, advisory_id: str, reason: str, now: float | None = None
) -> None:
    """Stamp a verdict (overwrites expired/stale entries)."""
    state.setdefault(repo_full_name, {})[advisory_id] = {
        "reason": reason,
        "ts": now if now is not None else time.time(),
        "code_version": current_code_version(),
    }


def record_batch_unfixable(state_path: str, repo_full_name: str, advisory_ids: list[str], reason: str) -> None:
    """Load, stamp every advisory in a refused batch, save. No-op when disabled."""
    if not state_path:
        return
    state = load_state(state_path)
    for advisory_id in advisory_ids:
        record_unfixable(state, repo_full_name, advisory_id, reason)
    save_state(state_path, state)
