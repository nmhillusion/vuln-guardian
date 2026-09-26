# github-advisor-agent

Auto-fix GitHub security advisories using an external AI coding agent CLI.

Scans all repos in a GitHub org/user for open vulnerabilities (Dependabot, Code Scanning, GHSA), groups them into per-file batches, clones each repo, invokes a configured AI agent to apply fixes, pushes `fix/batch-*` branches, opens PRs, and generates an HTML report.

## Features

- Multi-source advisory fetch: Dependabot alerts, Code Scanning alerts, repo security advisories
- Org or user repo enumeration (`/orgs/{org}/repos` with fallback to `/users/{org}/repos`)
- Deterministic per-file batching (`--batch-size`, default 5) with content-derived branch names (`fix/batch-<sha8>`) for safe resume
- Transitive dependency resolution via Dependency Graph SBOM + Maven Central latest-version lookup
- External AI-agent fix loop (configurable CLI, stdin or argv prompt, 600s timeout, live log streaming)
- npm `package-lock.json`-only fast path: delete + regenerate instead of agent edit
- Idempotency: skips batches where a PR or branch already exists (including legacy `fix/<advisory-id>` branches)
- PR automation with advisory summary body
- Self-contained HTML report (`report.html`) with fixes, unmerged, pending tool PRs, skipped, errors
- Colored console logs + `vuln-guardian.log` file log

## How it works

1. `list_repos` → all `full_name`s for `org`
2. Per repo `fetch_repo_advisories` → `Vulnerability` list
3. `_batch_vulns` → group by `manifest_path` / first affected file, chunk by `--batch-size`
4. `clone_or_update` → clone into `clone_dir/<repo>`
5. `create_branch(fix/batch-<digest>)` from default branch
6. `apply_fix` → build prompt with exact manifest lines / code snippets, invoke `ai_agent_args`, commit on change
7. Push branch, `create_pull_request`
8. `generate_report` → `report.html`, auto-open in browser unless `--no-browser`

Transitive Maven deps: SBOM BFS finds `root -> ... -> package` chain, `parse_maven_parent` + `get_latest_version` suggests upgrading the direct parent. Prompt forbids adding the transitive package as a new direct dep and requires `CANNOT FIX: <reason>` when unfixable.

## Requirements

- Python >= 3.11
- `git` on PATH
- GitHub PAT with `repo` + `security_events` scopes (Dependabot / code-scanning / SBOM APIs)
- An AI agent CLI (default config uses `kilo run --auto`)

## Install

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
copy .env.example .env  # then edit GITHUB_PAT
# or: $env:GITHUB_PAT="ghp_..."
```

## Configuration

`config.yaml`:

| Key | Default | Description |
|-----|---------|-------------|
| `org` | `"nmhillusion"` | Org or username to scan |
| `clone_dir` | `"../.repos"` | Where repos are cloned |
| `report_path` | `"report.html"` | HTML report output |
| `ai_agent_args` | `["kilo.cmd","run","--auto","-m","{model}","--variant","minimal","--dir","{repo_dir}"]` | Agent command template. Placeholders: `{repo_dir}`, `{model}`, `{prompt}` |
| `ai_agent_model` | `"kilo/stepfun/step-3.7-flash:free"` | Substituted for `{model}` |
| `ai_agent_stdin` | `true` | Pipe prompt via stdin (`true`) or argv `{prompt}` (`false`) |

Auth: `GITHUB_PAT` or `GITHUB_TOKEN` env var (see `.env.example`).

## Usage

```powershell
# full run (clone + fix + PR + report)
python -m src --yes

# preview only — fetch advisories + report, no clone/fix/PR
python -m src --dry-run --no-browser

# regenerate report without clone/fix/PR
python -m src --report-only

# scan different org, limit work
python -m src --org my-org --max-fixes 3 --batch-size 5 --verbose

# installed script equivalent
github-advisor --dry-run
```

CLI flags (`src/main.py:parse_args`):

| Flag | Description |
|------|-------------|
| `--dry-run` | Fetch advisories + report, skip clone/fix/PR |
| `--report-only` | Regenerate report from cached data |
| `--org` | Override `org` from config |
| `--config` | Path to config file (default `config.yaml`) |
| `--verbose` | Debug logging |
| `--no-browser` | Don't auto-open HTML report |
| `--no-color` | Disable colored logs |
| `--log-file` | Log file path, reset every run (default `vuln-guardian.log`, empty disables) |
| `--max-fixes` | Max fix batches per run (default 5) |
| `--batch-size` | Max vulns per batch/PR (default 5) |
| `--yes` | Auto-approve clone-dir creation |

First non-dry run prompts to create `clone_dir` unless `--yes` is passed.

## AI agent prompt & safety

`src/fixer.py` builds a non-interactive prompt scoped to the `.repos` clone folder: read/edit/delete + run build/test commands allowed inside the repo only; no push/rebase/merge, no operations outside the clone, no credential ops, no subagents, ~10 tool calls max.

Agent output streams to the log as `[<advisory-ids>] <line>`. No git changes + `CANNOT FIX:` marker → batch recorded as skipped with reason. Changes are committed as `fix: N vulnerabilities (<ids>)`; npm lockfile-only batches commit `fix: remove lockfile(s) [...]`.

## Report

`src/reporter.py:generate_report` writes a single-file HTML page:

- Verdict line: `N found · M fixed this run · K awaiting review`
- Stats: repos scanned, vulns found, fixes attempted, PRs created, skipped
- Tables: Fixes Applied, Unmerged PRs, Pending Tool PRs (`fix/*` open PRs), Skipped (repo/advisory/reason + branch link), Errors

## Project structure

```
config.yaml        org / clone_dir / report_path / ai_agent_args
src/
  main.py          CLI, batching, process_repo orchestration
  fetcher.py       Dependabot / code-scanning / GHSA parsing
  github_client.py httpx client, pagination, 429/5xx retry
  sbom.py          SBOM fetch + BFS dependency chain
  maven.py         Maven Central latest-version lookup
  repo.py          safe clone/update, branch helpers
  fixer.py         prompt build + agent invocation + commit
  pr.py            PR dedup, open tool-PR listing, PR creation
  reporter.py      HTML report generation
  models.py        Vulnerability, RunResult dataclasses
  config.py        load_config()
tests/             pytest suite per module + integration
report.html        generated output (gitignored likely)
vuln-guardian.log  per-run log (reset each run)
```

## Testing

```powershell
pytest -q
pytest tests/test_fixer.py -q
pytest tests/test_main.py -q
```

## Troubleshooting

- `Configuration error: GITHUB_PAT ... required` → set `$env:GITHUB_PAT` or `GITHUB_TOKEN`.
- `Failed to fetch repos` → PAT missing `repo` / `security_events` scopes.
- `Agent timed out / exit N` → check `ai_agent_args` binary path, model name, and `ai_agent_stdin` setting; tail is logged (last 20 lines).
- `No changes after agent run` → agent emitted `CANNOT FIX:` or produced no diff; reason appears in Skipped table.
- SBOM `None` → Dependency Graph disabled or no permission; transitive chains are skipped gracefully.
