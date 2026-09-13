# src/main.py
from __future__ import annotations

import argparse
import hashlib
import logging
import subprocess
import sys
import webbrowser
from pathlib import Path

from src.config import load_config, Config
from src.github_client import GitHubClient
from src.fetcher import list_repos, fetch_repo_advisories
from src.models import RunResult, Vulnerability
from src.repo import clone_or_update, detect_default_branch, branch_exists, create_branch, checkout
from src.fixer import apply_fix
from src.pr import create_pull_request, pr_exists_for_branch, fetch_open_tool_prs
from src.reporter import generate_report

logger = logging.getLogger("github-advisor")


class _ColorFormatter(logging.Formatter):
    """ANSI-color log lines by level. No-op when colors are disabled."""

    COLORS = {
        logging.DEBUG: "\033[36m",  # cyan
        logging.INFO: "\033[32m",  # green
        logging.WARNING: "\033[33m",  # yellow
        logging.ERROR: "\033[31m",  # red
        logging.CRITICAL: "\033[35m",  # magenta
    }
    RESET = "\033[0m"

    def __init__(self, fmt: str, use_color: bool = True):
        super().__init__(fmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        text = super().format(record)
        if not self.use_color:
            return text
        color = self.COLORS.get(record.levelno, "")
        if record.getMessage().startswith("====="):
            color = "\033[35m"  # magenta for START/END fix banners
        elif record.getMessage().startswith("SKIP"):
            color = "\033[38;5;208m"  # orange for SKIP lines
        return f"{color}{text}{self.RESET}"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GitHub Advisor Agent — auto-fix security advisories")
    parser.add_argument("--dry-run", action="store_true", help="Fetch advisories and generate report, skip clone/fix/PR")
    parser.add_argument("--report-only", action="store_true", help="Regenerate report from cached data")
    parser.add_argument("--org", type=str, default=None, help="Override org from config")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to config file")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open the HTML report")
    parser.add_argument("--no-color", action="store_true", help="Disable colored log output")
    parser.add_argument("--log-file", type=str, default="vuln-guardian.log", help="Log file path (reset every run, empty disables)")
    parser.add_argument("--max-fixes", type=int, default=5, help="Max fix batches per run (default: 5)")
    parser.add_argument("--batch-size", type=int, default=5, help="Max vulnerabilities per fix batch/PR (default: 5)")
    parser.add_argument("--yes", action="store_true", help="Auto-approve prompts (e.g. clone directory creation)")
    return parser.parse_args(argv)


def _vuln_file_key(vuln: Vulnerability) -> str:
    """File a vuln belongs to: manifest, first affected file, or misc bucket."""
    if vuln.manifest_path:
        return vuln.manifest_path
    if vuln.affected_files:
        return vuln.affected_files[0]
    return "__misc__"


def _batch_vulns(vulns: list[Vulnerability], batch_size: int) -> list[list[Vulnerability]]:
    """Group vulns by file and chunk into batches. Deterministic for stable resume."""
    groups: dict[str, list[Vulnerability]] = {}
    for v in sorted(vulns, key=lambda v: (_vuln_file_key(v), v.advisory_id)):
        groups.setdefault(_vuln_file_key(v), []).append(v)
    batches: list[list[Vulnerability]] = []
    for key in sorted(groups):
        group = groups[key]
        batches.extend(group[i:i + batch_size] for i in range(0, len(group), batch_size))
    return batches


def _batch_branch_name(batch: list[Vulnerability]) -> str:
    """Content-derived branch name so identical batches resume to the same branch."""
    digest = hashlib.sha1(",".join(sorted(v.advisory_id for v in batch)).encode()).hexdigest()[:8]
    return f"fix/batch-{digest}"


def _record_skip(
    result: RunResult,
    repo_full_name: str,
    vulns: list[Vulnerability],
    reason: str,
    branch: str | None = None,
) -> None:
    """Count a skip and record what was skipped for the report."""
    result.skipped += len(vulns)
    for v in vulns:
        item: dict[str, str] = {"repo": repo_full_name, "advisory_id": v.advisory_id, "reason": reason}
        if branch:
            item["branch"] = branch
            item["url"] = f"https://github.com/{repo_full_name}/tree/{branch}"
        result.skipped_items.append(item)


def process_repo(
    client: GitHubClient,
    config: Config,
    repo_full_name: str,
    vulns: list[Vulnerability],
    result: RunResult,
    max_fixes: int = 5,
    batch_size: int = 5,
) -> None:
    """Process all vulnerabilities for a single repo, in per-file batches."""
    logger.info(f"Processing {repo_full_name} ({len(vulns)} vulnerabilities)...")

    try:
        repo_path = clone_or_update(config.clone_dir, repo_full_name, config.github_pat)
    except Exception as e:
        msg = f"Failed to clone/update {repo_full_name}: {e}"
        logger.error(msg)
        result.errors.append(msg)
        return

    default_branch = detect_default_branch(repo_path)
    logger.info(f"Default branch for {repo_full_name}: {default_branch}")

    # Pre-filter vulns already handled (previous runs / one-by-one era branches).
    pending: list[Vulnerability] = []
    for vuln in vulns:
        legacy_branch = f"fix/{vuln.advisory_id}"
        if pr_exists_for_branch(client, repo_full_name, legacy_branch):
            logger.info(f"PR already exists for {vuln.advisory_id}, skipping")
            _record_skip(result, repo_full_name, [vuln], "PR already exists")
            continue
        if branch_exists(repo_path, legacy_branch):
            logger.info(f"Branch {legacy_branch} already exists, skipping")
            _record_skip(result, repo_full_name, [vuln], "branch already exists")
            continue
        pending.append(vuln)

    for batch in _batch_vulns(pending, batch_size):
        if result.fixes_attempted >= max_fixes:
            logger.info(f"Reached max fix attempts ({max_fixes}), stopping")
            break

        ids = sorted(v.advisory_id for v in batch)
        branch_name = _batch_branch_name(batch)
        logger.info(f"Batch {branch_name} ({len(batch)} vulns): {', '.join(ids)}")

        if pr_exists_for_branch(client, repo_full_name, branch_name):
            logger.info(f"PR already exists for {branch_name}, skipping batch")
            _record_skip(result, repo_full_name, batch, "batch PR already exists")
            continue

        if branch_exists(repo_path, branch_name):
            logger.info(f"Branch {branch_name} already exists, skipping batch")
            _record_skip(result, repo_full_name, batch, "batch branch already exists", branch=branch_name)
            continue

        try:
            create_branch(repo_path, branch_name, default_branch)
        except Exception as e:
            msg = f"Failed to create branch {branch_name}: {e}"
            logger.error(msg)
            result.errors.append(msg)
            continue

        result.fixes_attempted += 1

        if not apply_fix(config, repo_path, batch, fix_number=result.fixes_attempted, max_fixes=max_fixes):
            logger.info(f"No fix applied for batch {branch_name}, skipping PR")
            _record_skip(result, repo_full_name, batch, "no fix produced")
            checkout(repo_path, default_branch)
            subprocess.run(["git", "-C", str(repo_path), "branch", "-D", branch_name], capture_output=True)
            continue

        push_result = subprocess.run(
            ["git", "-C", str(repo_path), "push", "-u", "origin", branch_name],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if push_result.returncode != 0:
            msg = f"Failed to push {branch_name}: {push_result.stderr}"
            logger.error(msg)
            result.errors.append(msg)
            continue

        pr = create_pull_request(client, repo_full_name, batch, default_branch, branch_name)
        if pr:
            result.prs_created += 1
            for v in batch:
                result.prs.append({
                    "repo": repo_full_name,
                    "advisory_id": v.advisory_id,
                    "severity": v.severity,
                    "title": v.title,
                    "pr_url": pr.get("html_url", ""),
                    "pr_number": pr.get("number", ""),
                    "merged": pr.get("merged", False),
                })

        checkout(repo_path, default_branch)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    use_color = sys.stdout.isatty() and not args.no_color
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    handlers: list[logging.Handler] = []
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(_ColorFormatter(fmt, use_color=use_color))
    handlers.append(console_handler)
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file, mode="w", encoding="utf-8")
        file_handler.setFormatter(_ColorFormatter(fmt, use_color=False))
        handlers.append(file_handler)
    logging.basicConfig(level=log_level, handlers=handlers, force=True)

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    if args.org:
        config.org = args.org

    if not args.dry_run and not args.report_only:
        clone_path = Path(config.clone_dir).resolve()
        if not clone_path.exists():
            if args.yes:
                approved = True
            else:
                answer = input(
                    f"Clone directory does not exist:\n"
                    f"  {clone_path}\n"
                    f"(You can change this path with 'clone_dir' in {args.config}.)\n"
                    f"Create this directory? [y/N]: "
                )
                approved = answer.strip().lower() in ("y", "yes")
            if not approved:
                logger.error("Aborted: clone directory not approved")
                sys.exit(1)
            clone_path.mkdir(parents=True, exist_ok=True)
            config.clone_dir = str(clone_path)

    client = GitHubClient(config.github_pat)

    try:
        logger.info(f"Fetching advisories for org: {config.org}")
        repos = list_repos(client, config.org)
        logger.info(f"Found {len(repos)} repos in org {config.org}")

        result = RunResult()
        result.repos_scanned = len(repos)

        for repo_full_name in repos:
            vulns = fetch_repo_advisories(client, repo_full_name)
            result.vulns_found += len(vulns)
            result.pending_prs.extend(fetch_open_tool_prs(client, repo_full_name))

            if not vulns:
                logger.info(f"SKIP {repo_full_name} — no open vulnerabilities")
                continue
            if args.dry_run:
                logger.info("Dry run mode — skipping clone/fix/PR")
                continue
            if args.report_only:
                logger.info("Report-only mode — skipping clone/fix/PR")
                continue

            process_repo(client, config, repo_full_name, vulns, result, args.max_fixes, args.batch_size)
            if result.fixes_attempted >= args.max_fixes:
                logger.info(f"Reached max fix attempts ({args.max_fixes}), stopping run")
                break

        report_html = generate_report(result, config.report_path)
        logger.info(f"Report saved to {config.report_path}")

        report_uri = Path(config.report_path).resolve().as_uri()
        if not args.no_browser:
            logger.info(f"Opening report in browser: {report_uri}")
            webbrowser.open(report_uri)

        print(f"\n--- Summary ---")
        print(f"Repos scanned: {result.repos_scanned}")
        print(f"Vulnerabilities found: {result.vulns_found}")
        print(f"Fixes attempted: {result.fixes_attempted}")
        print(f"PRs created: {result.prs_created}")
        print(f"Skipped: {result.skipped}")
        print(f"Errors: {len(result.errors)}")
        print(f"Report: {report_uri}")
        if result.errors:
            for err in result.errors:
                print(f"  - {err}")

    finally:
        client.close()
