# Design: AI Model Validation Before Fixing

- **Jira:** NMHK-22 (Story under epic NMHK-21)
- **Date:** 2026-10-18
- **Status:** Approved

## Problem

The app does not validate `ai_agent_model` before invoking the fix agent. `load_config` accepts any string, and `src/fixer.py` only substitutes it into the `{model}` placeholder of `ai_agent_args`. An invalid model name fails only *after* the agent runs: the CLI exits non-zero, the batch is marked `agent exit N`, and time and repo work are wasted across batches.

## Goal

Fail fast at startup when the configured AI model is not valid or cannot be verified, before any cloning or fixing begins. Stop the app immediately with a clear error message naming the offending value and the config key to fix.

## Decisions (confirmed with user)

| Decision | Choice |
|---|---|
| Validation depth | Static checks **plus** live verification against the agent |
| When | Once at startup, only in fix mode (skipped for `--dry-run` / `--report-only`) |
| Policy | **Fail closed**: any outcome other than a positive match stops the app |
| On failure | Exit immediately with a clear error message — no cloning, no fix attempts, no report generation, no browser open |
| Probe strategy | Try common model-list patterns against the configured agent binary; none works ⇒ unverifiable ⇒ fail closed |

## Design

### Flow

```text
main() → load_config → [fix mode] validate_model(config)
             ├─ None → proceed (clone/fix as today)
             └─ reason → logger.error(...) → sys.exit(1)
```

Validation runs in `main()` immediately after a successful `load_config` and only when the run will actually fix (`not args.dry_run and not args.report_only`). On failure the app stops before clone-directory checks, GitHub client creation, or any advisory fetching.

### Static checks (offline, always)

Fail with a specific reason if:

1. `ai_agent_args` contains the `{model}` placeholder but `ai_agent_model` is empty or whitespace-only.
2. `ai_agent_model` is malformed: contains whitespace or control characters, or is otherwise not a clean identifier-like string (conservative check; do not over-constrain the shape).

If `{model}` is absent from `ai_agent_args`, the model is irrelevant to the command — static model checks are skipped (the model may still be used for logging labels only).

### Live verification (once, startup)

- Extract the agent binary from `ai_agent_args[0]`.
- Probe a small set of common model-list mechanisms against it, e.g.:
  - `<agent> models`
  - `<agent> --model-list`-style flags
  - a `--help` sniff only if needed to detect a models subcommand
- Use a **10-second timeout** (injectable in tests).
- Match the configured `ai_agent_model` (trimmed) against the returned model IDs (exact match).
- **Fail-closed outcomes**, each with distinct wording:
  - model not in list → model is not offered by the agent
  - no probe pattern supported / list command exits non-zero → unverifiable (agent has no model-list capability)
  - timeout → unverifiable (timed out)
  - probe could not run (binary missing) → unverifiable (agent binary not runnable)

Definite-not-found vs unverifiable are worded distinctly, but both stop the app.

### Error message format

A single clear line, always naming the offending value and the config key:

```text
AI model validation failed: model 'kilo/stepfun/step-3.7-flas' not offered by agent 'kilo'. Fix 'ai_agent_model' in config.yaml.
AI model validation failed: cannot verify model 'kilo/stepfun/step-3.7-flash:free' — agent model-list timed out after 10s. Fix 'ai_agent_model' in config.yaml or check the agent binary.
```

Logged at ERROR level (red console output, also written to `vuln-guardian.log` via the existing handlers), then `sys.exit(1)`.

### Out of scope

- Per-batch re-verification (model availability will not change within one run).
- `--dry-run` / `--report-only` validation (no fixing occurs).
- Report surfacing of the failure (app exits before any report exists).
- A configurable lenient mode (strict fail-closed only).

## Files touched

| File | Change |
|---|---|
| `src/modelcheck.py` (new) | `validate_model(config) -> str \| None` — static + live checks, reason strings |
| `src/main.py` | call site after `load_config` in fix mode; log error + `sys.exit(1)` |
| `tests/test_modelcheck.py` (new) | unit tests for static and live paths |
| `README.md` | document validation behavior and fail-closed semantics |

## Testing

- **Static:** empty model with `{model}` present → fail; whitespace/control chars → fail; valid string → pass; no `{model}` in `ai_agent_args` → skipped.
- **Live (mocked subprocess):** model in list → pass; not in list → fail with not-offered reason; unsupported probe → fail with unverifiable reason; timeout → fail with timeout reason; timeout value injectable for fast tests.
- **Integration:** `main()` exits 1 (SystemExit) when validation fails; exits 0 path unchanged when validation passes; `--dry-run` skips validation.
- Follow existing test style in `tests/test_config.py` and `tests/test_fixer.py`.

## Risks / notes

- Agent-agnostic probe may not find a list command for every agent; fail-closed means such agents cannot run fixes until a supported probe is added. The error message must say exactly why.
- If `kilo`'s model-list output format differs from assumed ID lines, matching may need adjustment after first real run — tests keep the parser injectable.
