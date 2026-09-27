# tests/test_state.py
import time
from src.state import (
    CANNOT_FIX_TTL_SECONDS,
    current_code_version,
    is_definitive_refusal,
    is_unfixable_cached,
    load_state,
    record_batch_unfixable,
    record_unfixable,
    save_state,
)


def test_code_version_stable_and_short():
    assert current_code_version() == current_code_version()
    assert len(current_code_version()) == 12


def test_record_and_hit(tmp_path):
    state_path = str(tmp_path / "state.json")
    state = load_state(state_path)
    record_unfixable(state, "o/r", "GHSA-1", "cannot fix: no release")
    save_state(state_path, state)
    reloaded = load_state(state_path)
    hit, reason = is_unfixable_cached(reloaded, "o/r", "GHSA-1")
    assert hit is True
    assert reason == "cannot fix: no release"


def test_expired_after_ttl():
    assert CANNOT_FIX_TTL_SECONDS == 3 * 24 * 3600
    state: dict = {}
    old = time.time() - CANNOT_FIX_TTL_SECONDS - 1
    record_unfixable(state, "o/r", "GHSA-1", "cannot fix: x", now=old)
    hit, _ = is_unfixable_cached(state, "o/r", "GHSA-1")
    assert hit is False


def test_code_version_change_invalidates():
    state: dict = {}
    record_unfixable(state, "o/r", "GHSA-1", "cannot fix: x")
    state["o/r"]["GHSA-1"]["code_version"] = "stale-version"
    hit, _ = is_unfixable_cached(state, "o/r", "GHSA-1")
    assert hit is False


def test_unknown_advisory_misses():
    hit, _ = is_unfixable_cached({}, "o/r", "GHSA-9")
    assert hit is False


def test_malformed_file_tolerated(tmp_path):
    bad = tmp_path / "state.json"
    bad.write_text("{not json", encoding="utf-8")
    assert load_state(str(bad)) == {}


def test_missing_file_loads_empty(tmp_path):
    assert load_state(str(tmp_path / "nope.json")) == {}


def test_empty_path_disables(tmp_path):
    assert load_state("") == {}
    save_state("", {"o/r": {}})  # must not raise
    assert is_unfixable_cached({}, "o/r", "GHSA-1") == (False, "")


def test_record_batch_unfixable(tmp_path):
    state_path = str(tmp_path / "state.json")
    record_batch_unfixable(state_path, "o/r", ["GHSA-1", "GHSA-2"], "nonexistent version 1.0 for g:a")
    state = load_state(state_path)
    for adv in ("GHSA-1", "GHSA-2"):
        hit, reason = is_unfixable_cached(state, "o/r", adv)
        assert hit is True
        assert "nonexistent version" in reason


def test_is_definitive_refusal():
    assert is_definitive_refusal("cannot fix: parent has no release") is True
    assert is_definitive_refusal("CANNOT FIX: only pre-release") is True
    assert is_definitive_refusal("nonexistent version 3.4.17 for g:a") is True
    assert is_definitive_refusal("no changes produced") is False
    assert is_definitive_refusal("agent timed out") is False
    assert is_definitive_refusal("agent exit 1") is False
    assert is_definitive_refusal("") is False
