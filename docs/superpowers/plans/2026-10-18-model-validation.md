# AI Model Validation Before Fixing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fail fast at startup — before any cloning or fixing — when the configured AI model is invalid or cannot be verified against the agent, exiting with a clear error message.

**Architecture:** A new pure module `src/modelcheck.py` exposes `validate_model(config) -> str | None` (reason or None). It runs static checks (placeholder present, model non-empty, no whitespace/control chars), then one live probe against the agent binary's model-list command with a 10s timeout. `main()` calls it once in fix mode after `load_config`; on failure it logs `AI model validation failed: <reason>` at ERROR and `sys.exit(1)` — no cloning, no report, no browser.

**Tech Stack:** Python 3.14, stdlib only (`subprocess`, no new dependencies), pytest with `unittest.mock.patch` (matching existing test style).

**Spec:** `docs/superpowers/specs/2026-10-18-model-validation-design.md`

## Global Constraints

- Fail closed: any outcome other than a positive model match stops the app (spec decision table).
- Validation runs **once at startup**, only in fix mode — skipped for `--dry-run` and `--report-only` (spec: Decisions).
- On failure the app exits **immediately**: log ERROR + `sys.exit(1)`; no cloning, no fix attempts, no report file, no browser open (spec: Decisions).
- Live probe timeout: **10 seconds**, injectable as a function parameter for tests (spec: Live verification).
- Error message shape: `AI model validation failed: <reason>` where `<reason>` ends with a remedy clause naming `config.yaml` (spec: Error message format) — exact strings pinned in task Interfaces below.
- No new `config.yaml` fields; no new dependencies.
- **Git commits require explicit user approval before every commit** (user's AGENTS.md absolute rule — overrides the default commit steps; see each task's final step). Note: GPG signing is enabled globally on this machine; a commit from an unattended shell may hang on pinentry — surface this to the user rather than bypassing signing.
- Follow existing code style: `# src/<file>.py` header comment, logger name `"github-advisor"`, f-string log messages.

## Review Focus

Five input/failure modes the spec implies but that are easiest to get wrong; each has its test pinned to the task that owns the code:

1. **Model matched only as a token in multi-column CLI output** (e.g. `kilo/stepfun/step-3.7-flash:free  128k  free`): a person would expect verification to succeed — token matching, not whole-line. → `test_validate_model_matches_token_in_table_row` (Task 2)
2. **Agent binary missing/not runnable** (bad path in `ai_agent_args[0]`): expect fail-closed with a reason naming the binary, not a traceback. → `test_validate_model_agent_not_runnable` (Task 2)
3. **All probe patterns exit non-zero** (agent has no model-list): expect fail-closed "no model-list capability" with exit details, not a false pass. → `test_validate_model_all_probes_fail_closed` (Task 2)
4. **`--dry-run` / `--report-only` runs**: expect validation NOT to run (no fixing happens) — an unverifiable model must not block report generation. → `test_main_validation_skipped_in_dry_run_and_report_only` (Task 3)
5. **`{model}` absent from `ai_agent_args`**: expect the whole validation (including the live probe — subprocess must never be invoked) to be skipped. → `test_validate_model_skips_all_checks_without_placeholder` (Task 1)

---

### Task 1: Static validation in `src/modelcheck.py`

**Files:**
- Create: `src/modelcheck.py`
- Test: `tests/test_modelcheck.py`

**Interfaces:**
- Consumes: `src.config.Config` (fields `ai_agent_args: list[str]`, `ai_agent_model: str`).
- Produces (relied on by Tasks 2 and 3):
  - `validate_model(config: Config, timeout: float = 10.0) -> str | None` — returns the full failure reason (including its remedy clause, ending with `.`) or `None` on success. Task 3 prefixes it with `AI model validation failed: `.
  - Contract: if `config.ai_agent_args` is empty or `"{"model"}"` is not in it, `validate_model` returns `None` without invoking subprocess (Review Focus #5).
  - Static reasons pinned verbatim:
    - empty: `ai_agent_args uses {model} but ai_agent_model is empty. Fix 'ai_agent_model' in config.yaml.`
    - malformed: `model '<value>' contains whitespace or control characters. Fix 'ai_agent_model' in config.yaml.`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_modelcheck.py`:

```python
# tests/test_modelcheck.py
from unittest.mock import patch
from src.config import Config
from src.modelcheck import validate_model


def _config(args=None, model=""):
    return Config(
        org="test-org", clone_dir=".repos", report_path="report.html",
        github_pat="ghp_test",
        ai_agent_args=args if args is not None else ["kilo", "run", "-m", "{model}", "{prompt}"],
        ai_agent_model=model,
    )


def test_validate_model_empty_when_placeholder_required():
    reason = validate_model(_config(model=""))
    assert reason is not None
    assert "ai_agent_args uses {model} but ai_agent_model is empty" in reason
    assert "Fix 'ai_agent_model' in config.yaml." in reason


def test_validate_model_rejects_whitespace():
    reason = validate_model(_config(model="bad model"))
    assert reason is not None
    assert "'bad model' contains whitespace" in reason


def test_validate_model_rejects_control_chars():
    reason = validate_model(_config(model="kilo\x00model"))
    assert reason is not None
    assert "control characters" in reason


def test_validate_model_skips_all_checks_without_placeholder():
    cfg = _config(args=["kilo", "run", "{prompt}"], model="")
    with patch("src.modelcheck.subprocess.run") as mock_run:
        assert validate_model(cfg) is None
    mock_run.assert_not_called()


def test_validate_model_empty_args_skipped():
    with patch("src.modelcheck.subprocess.run") as mock_run:
        assert validate_model(_config(args=[])) is None
    mock_run.assert_not_called()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_modelcheck.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'src.modelcheck'`

- [ ] **Step 3: Implement static checks**

Create `src/modelcheck.py` with header comment `# src/modelcheck.py`, `import subprocess`, `from src.config import Config`, and:

```python
def validate_model(config: Config, timeout: float = 10.0) -> str | None:
    """Static + live check of ai_agent_model. Returns a failure reason or None."""
```

Body order: guard (`not config.ai_agent_args` or `"{model}" not in config.ai_agent_args` → `None`); empty/whitespace-only model → pinned empty reason; any char in the model that is whitespace (`str.isspace()`) or a control char (`ord(c) < 32 or ord(c) == 127`) → pinned malformed reason with the value quoted; then call the (not-yet-existing) live path — for this task, stub `return None` after static checks with a `# TODO Task 2` marker so Task 1 tests pass in isolation.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_modelcheck.py -v`
Expected: all 5 PASS

- [ ] **Step 5: Commit (REQUIRES EXPLICIT USER APPROVAL)**

Do not commit automatically. Present the user with:
`git add src/modelcheck.py tests/test_modelcheck.py && git commit -m "feat: static AI model validation (NMHK-22)"` and wait for an explicit yes.

---

### Task 2: Live model-list probe

**Files:**
- Modify: `src/modelcheck.py` (replace the Task 1 TODO stub)
- Test: `tests/test_modelcheck.py` (append)

**Interfaces:**
- Consumes: `validate_model` from Task 1 (same signature; `timeout` parameter now used).
- Produces:
  - `_list_models(agent: str, timeout: float) -> tuple[list[str] | None, str | None]` — `(tokens, None)` on success, `(None, reason)` on fail-closed. Private helper; tests go through `validate_model`.
  - Probe pattern order (first exit-0 probe is authoritative): `[agent, "models"]`, then `[agent, "--model-list"]`.
  - Subprocess invocation: `subprocess.run(probe, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)`.
  - Matching: split successful probe's **stdout** on whitespace → token set; configured model (trimmed) must equal a token exactly (Review Focus #1).
  - Live reasons pinned verbatim (`<x>` = configured model, `<y>` = `ai_agent_args[0]`):
    - not offered: `model '<x>' not offered by agent '<y>'. Fix 'ai_agent_model' in config.yaml.`
    - timeout: `cannot verify model '<x>' — agent model-list timed out after <timeout:g>s. Fix 'ai_agent_model' in config.yaml or check the agent binary.`
    - not runnable: `cannot verify model '<x>' — agent binary '<y>' is not runnable. Fix 'ai_agent_args' in config.yaml.`
    - all probes failed: `cannot verify model '<x>' — agent '<y>' has no model-list capability (<details>). Fix 'ai_agent_model' in config.yaml or check the agent binary.` where `<details>` = comma-joined `'<probe arg>: exit <n>'` (e.g. `'models': exit 1, '--model-list': exit 2`).
  - `FileNotFoundError`/`OSError` on any probe → not-runnable reason (Review Focus #2); `subprocess.TimeoutExpired` → timeout reason.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_modelcheck.py`. Each test patches `src.modelcheck.subprocess.run`; the valid-static config used throughout is `_config(model="kilo/stepfun/step-3.7-flash:free")`:

```python
def _completed(stdout="", returncode=0):
    import subprocess as sp
    return sp.CompletedProcess(["probe"], returncode, stdout=stdout, stderr="")


def test_validate_model_match_passes():
    with patch("src.modelcheck.subprocess.run",
               return_value=_completed("kilo/stepfun/step-3.7-flash:free\nother/model\n")):
        assert validate_model(_config(model="kilo/stepfun/step-3.7-flash:free")) is None


def test_validate_model_matches_token_in_table_row():
    out = "kilo/stepfun/step-3.7-flash:free  128k  free\nkilo/other/model  32k  paid\n"
    with patch("src.modelcheck.subprocess.run", return_value=_completed(out)):
        assert validate_model(_config(model="kilo/stepfun/step-3.7-flash:free")) is None


def test_validate_model_not_offered_fail_closed():
    with patch("src.modelcheck.subprocess.run",
               return_value=_completed("kilo/other/model\n")):
        reason = validate_model(_config(model="kilo/stepfun/step-3.7-flas"))
    assert reason is not None
    assert "not offered by agent 'kilo'" in reason
    assert "Fix 'ai_agent_model' in config.yaml." in reason


def test_validate_model_timeout_fail_closed():
    import subprocess as sp
    with patch("src.modelcheck.subprocess.run", side_effect=sp.TimeoutExpired(cmd="kilo", timeout=10)):
        reason = validate_model(_config(model="kilo/stepfun/step-3.7-flash:free"), timeout=10)
    assert reason is not None
    assert "timed out after 10s" in reason


def test_validate_model_agent_not_runnable():
    with patch("src.modelcheck.subprocess.run", side_effect=FileNotFoundError("kilo")):
        reason = validate_model(_config(model="kilo/stepfun/step-3.7-flash:free"))
    assert reason is not None
    assert "agent binary 'kilo' is not runnable" in reason
    assert "Fix 'ai_agent_args' in config.yaml." in reason


def test_validate_model_all_probes_fail_closed():
    with patch("src.modelcheck.subprocess.run",
               side_effect=[_completed(returncode=1), _completed(returncode=2)]):
        reason = validate_model(_config(model="kilo/stepfun/step-3.7-flash:free"))
    assert reason is not None
    assert "has no model-list capability" in reason
    assert "'models': exit 1" in reason and "'--model-list': exit 2" in reason
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_modelcheck.py -v`
Expected: the 6 new tests FAIL (live path currently stubbed to `None`); the 5 Task 1 tests still PASS.

- [ ] **Step 3: Implement `_list_models` and wire it into `validate_model`**

In `src/modelcheck.py`, add `_list_models(agent: str, timeout: float) -> tuple[list[str] | None, str | None]` per the Interfaces reasons above, looping the two probe patterns; on exit 0 split stdout whitespace and return tokens; collect `'<arg>: exit <n>'` details for the all-failed reason. Replace the Task 1 TODO stub with: build the live reason strings using the configured model and `config.ai_agent_args[0]`, call `_list_models`, return `None` if tokens is not None and the trimmed model is in the token set, else the appropriate reason.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_modelcheck.py -v`
Expected: all 11 PASS

- [ ] **Step 5: Commit (REQUIRES EXPLICIT USER APPROVAL)**

Present: `git add src/modelcheck.py tests/test_modelcheck.py && git commit -m "feat: live AI model verification probe (NMHK-22)"` and wait for an explicit yes.

---

### Task 3: Wire into `main()`, integration tests, README

**Files:**
- Modify: `src/main.py` (import + call site after the `if args.org:` block, before the clone-directory check)
- Modify: `tests/test_main.py` (append)
- Modify: `README.md` (config table row for `ai_agent_model` + troubleshooting line)

**Interfaces:**
- Consumes: `validate_model(config: Config, timeout: float = 10.0) -> str | None` (Tasks 1–2).
- Produces: startup behavior — in fix mode (`not args.dry_run and not args.report_only`):

```python
reason = validate_model(config)
if reason:
    logger.error(f"AI model validation failed: {reason}")
    sys.exit(1)
```

The reason already ends with its remedy clause, so the logged line reads e.g. `AI model validation failed: model '...' not offered by agent 'kilo'. Fix 'ai_agent_model' in config.yaml.` (`src/main.py` already imports `sys`.)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_main.py`:

```python
def test_main_invalid_model_exits_before_any_work(tmp_path):
    from src.config import Config
    config_path = tmp_path / "config.yaml"
    config_path.write_text("org: test-org\n")
    cfg = Config(org="test-org", clone_dir=str(tmp_path / "clones"),
                 report_path=str(tmp_path / "report.html"), github_pat="ghp_test")
    with patch("src.main.load_config", return_value=cfg), \
         patch("src.main.validate_model",
               return_value="model 'bad' not offered by agent 'kilo'. Fix 'ai_agent_model' in config.yaml."), \
         patch("src.main.logger") as mock_logger, \
         patch("src.main.GitHubClient") as mock_client, \
         patch("src.main.list_repos") as mock_list:
        with pytest.raises(SystemExit) as exc:
            main(["--config", str(config_path)])
    assert exc.value.code == 1
    logged = " ".join(str(c.args[0]) for c in mock_logger.error.call_args_list)
    assert "AI model validation failed: model 'bad' not offered" in logged
    mock_client.assert_not_called()
    mock_list.assert_not_called()
    assert not (tmp_path / "clones").exists()


def test_main_validation_skipped_in_dry_run_and_report_only(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text('org: "test-org"\nclone_dir: ".repos"\nreport_path: "report.html"\n')
    for extra in (["--dry-run"], ["--report-only"]):
        with patch("src.main.load_config") as mock_config, \
             patch("src.main.validate_model",
                   side_effect=AssertionError("validation must not run")), \
             patch("src.main.GitHubClient") as mock_client_cls, \
             patch("src.main.list_repos", return_value=[]), \
             patch("src.main.fetch_repo_advisories"), \
             patch("src.main.webbrowser"), \
             patch("src.main.generate_report", return_value="<html></html>"):
            mock_config.return_value = MagicMock(
                org="test-org", clone_dir=str(tmp_path / ".repos"),
                report_path=str(tmp_path / "report.html"), github_pat="ghp_test")
            mock_client_cls.return_value = MagicMock()
            main(["--config", str(config_path), *extra])
```

Note: existing fix-mode tests (`test_main_stops_after_max_fixes`, `_run_fix_mode` helpers) use `MagicMock`/default `Config` without `{model}` in `ai_agent_args`, so real `validate_model` returns `None` at the placeholder guard — no patching needed, they keep passing unchanged.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_main.py -v`
Expected: `test_main_invalid_model_exits_before_any_work` FAILS (`AttributeError: module 'src.main' has no attribute 'validate_model'`); the skipped-validation test also FAILS for the same reason.

- [ ] **Step 3: Implement the call site**

In `src/main.py`: add `from src.modelcheck import validate_model` to imports (alphabetical position after `from src.models import ...`), and insert the three-line block from the Interfaces section after the `if args.org:` override, before the `if not args.dry_run and not args.report_only:` clone-directory block.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_main.py -v`
Expected: all tests PASS, including pre-existing ones.

- [ ] **Step 5: Update README**

In the config table, extend the `ai_agent_model` row with: validated at startup in fix mode (static + one live agent model-list probe, 10s); invalid or unverifiable ⇒ the run stops immediately with `AI model validation failed: ...` before any cloning/fixing. Add a matching one-liner to the troubleshooting list (`Agent timed out / exit N` entry area).

- [ ] **Step 6: Run the full suite**

Run: `python -m pytest -v`
Expected: all tests PASS (existing 100+ plus the 13 new ones).

- [ ] **Step 7: Commit (REQUIRES EXPLICIT USER APPROVAL)**

Present: `git add src/main.py tests/test_main.py README.md && git commit -m "feat: fail fast on invalid AI model before fixing (NMHK-22)"` and wait for an explicit yes.
