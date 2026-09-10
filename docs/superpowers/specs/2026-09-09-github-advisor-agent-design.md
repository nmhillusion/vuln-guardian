# GitHub Advisor Agent — Design Spec

## Overview

A Python CLI tool that fetches GitHub security advisories (GHSA, Dependabot, Code Scanning), clones affected repos, invokes OpenCode CLI to auto-fix vulnerabilities, creates PRs, and generates an HTML summary report.

## Project Structure

```
github-advisor-agent/
├── pyproject.toml          # Python project config
├── config.yaml             # Settings file
├── .env.example            # Documents required env vars
├── src/
│   ├── __init__.py
│   ├── main.py             # CLI entry point
│   ├── config.py           # Load config + env vars
│   ├── fetcher.py          # Fetch advisories from all 3 sources
│   ├── repo.py             # Clone, branch, detect default branch
│   ├── fixer.py            # Invoke OpenCode CLI per file/advisory
│   ├── pr.py               # Create GitHub PRs
│   └── reporter.py         # Generate HTML summary report
└── .repos/                 # Cloned repos (gitignored)
```

## Configuration

### config.yaml

```yaml
org: "my-org"
clone_dir: ".repos"
report_path: "report.html"
opencode_binary: "opencode"
```

### Environment Variables

- `GITHUB_PAT` — GitHub personal access token (required)

## Advisory Fetching

### Vulnerability Dataclass

```python
@dataclass
class Vulnerability:
    repo_full_name: str       # e.g. "myorg/myrepo"
    advisory_id: str          # GHSA ID or advisory URL
    severity: str             # critical/high/medium/low
    title: str
    description: str
    affected_files: list[str] # file paths from the advisory
    package_name: str | None  # for Dependabot/package advisories
    source: str               # "ghsa" | "dependabot" | "code_scanning"
    state: str                # "open" | "dismissed" | "fixed"
```

### Endpoints

- **GHSA**: `GET /advisories` with ecosystem filter, cross-reference with org repos
- **Dependabot**: `GET /repos/{owner}/{repo}/dependabot/alerts` per repo
- **Code Scanning**: `GET /repos/{owner}/{repo}/code-scanning/alerts` per repo

### Rate Limiting

httpx with exponential backoff (max 3 retries on 429/500).

### Filtering

Only `state=open` advisories. Skip repos already processed (tracked via a processed set).

## Clone & Branch

### Clone Logic

- Existing repo in `.repos/` → `git fetch --all` + `git pull`
- New repo → `git clone` into `.repos/{repo_name}`
- Default branch detection: `origin/HEAD` → `origin/main` → `origin/master`

### Branch Naming

`fix/{advisory_id}` (e.g., `fix/GHSA-xxxx-xxxx-xxxx`)

### Duplicate Skip

Before creating a branch:
- Branch `fix/{advisory_id}` already exists locally → skip
- PR with that branch name already exists on GitHub → skip

### Workflow Per Repo

1. Detect default branch, checkout
2. For each vulnerability:
   a. Check if branch/PR exists → skip if yes
   b. Create branch from default
   c. Pass affected files + advisory to OpenCode CLI
   d. Commit (OpenCode handles this)
   e. Push branch
   f. Create PR
3. Move to next repo

## OpenCode CLI Integration

### Invocation

```python
subprocess.run([
    opencode_binary, "apply", "--yes", "--message",
    f"Fix security vulnerability {vuln.advisory_id}: {vuln.title}. "
    f"Affected files: {', '.join(vuln.affected_files)}. "
    f"{vuln.description}"
])
```

### Post-Fix Verification

- Check `git diff` after OpenCode runs
- No changes → log "no auto-fix possible", abandon branch
- Changes → commit if needed, push

### Error Handling

All errors are non-fatal — continue processing remaining repos/vulns:
- OpenCode failure → skip vulnerability
- Push failure → skip repo
- PR failure → log, continue

## PR Creation

### PR Payload

```python
POST /repos/{owner}/{repo}/pulls
{
    "title": f"Fix: {vuln.title} ({vuln.advisory_id})",
    "body": f"Security advisory: {vuln.description}\n\nSource: {vuln.source}\nSeverity: {vuln.severity}",
    "head": f"fix/{vuln.advisory_id}",
    "base": detected_default_branch
}
```

## Report Generation

### HTML Report Sections

1. **Summary**: total repos scanned, vulns found, fixes attempted, PRs created, skips
2. **Fixes applied**: table with repo, advisory, severity, PR link, status
3. **Unmerged PRs**: list of PRs still open
4. **Skipped**: vulns with no auto-fix or existing PR
5. **Errors**: failures during the run

### Report Output

- Saved to `config.report_path` (default: `report.html`)
- Summary also printed to stdout

## CLI Interface

```
python -m src.main [OPTIONS]

Options:
  --dry-run          Fetch advisories, skip clone/fix/PR, generate report
  --report-only      Regenerate report from cached run data
  --org OVERRIDE     Override org from config
  --verbose          Enable debug logging
  --help             Show help
```

### Main Flow

1. Load config + env vars
2. Validate GitHub PAT
3. Fetch all open advisories (GHSA + Dependabot + Code Scanning)
4. If `--dry-run`: skip to report generation
5. For each repo (sequentially):
   a. Clone or update
   b. Detect default branch
   c. For each vulnerability: create branch, invoke OpenCode, push, create PR
6. Generate HTML report
7. Print summary to stdout
