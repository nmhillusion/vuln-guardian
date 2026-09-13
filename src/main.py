# src/main.py
from __future__ import annotations

import argparse
import logging
import subprocess
import sys
from pathlib import Path

from src.config import load_config, Config
from src.github_client import GitHubClient
from src.fetcher import list_repos, fetch_repo_advisories
from src.models import RunResult, Vulnerability
from src.repo import clone_or_update, detect_default_branch, branch_exists, create_branch, checkout
from src.fixer import apply_fix
from src.pr import create_pull_request, pr_exists_for_branch
from src.reporter import generate_report

logger = logging.getLogger("github-advisor")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GitHub Advisor Agent — auto-fix security advisories")
    parser.add_argument("--dry-run", action="store_true", help="Fetch advisories and generate report, skip clone/fix/PR")
    parser.add_argument("--report-only", action="store_true", help="Regenerate report from cached data")
    parser.add_argument("--org", type=str, default=None, help="Override org from config")
    parser.add_argument("--config", type=str, default="config.yaml", help="Path to config file")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--max-fixes", type=int, default=5, help="Max fix attempts per run (default: 5)")
    return parser.parse_args(argv)


def process_repo(
    client: GitHubClient,
    config: Config,
    repo_full_name: str,
    vulns: list[Vulnerability],
    result: RunResult,
    max_fixes: int = 5,
) -> None:
    """Process all vulnerabilities for a single repo."""
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

    for vuln in vulns:
        if result.fixes_attempted >= max_fixes:
            logger.info(f"Reached max fix attempts ({max_fixes}), stopping")
            break

        branch_name = f"fix/{vuln.advisory_id}"

        if pr_exists_for_branch(client, repo_full_name, branch_name):
            logger.info(f"PR already exists for {vuln.advisory_id}, skipping")
            result.skipped += 1
            continue

        if branch_exists(repo_path, branch_name):
            logger.info(f"Branch {branch_name} already exists, skipping")
            result.skipped += 1
            continue

        try:
            create_branch(repo_path, branch_name, default_branch)
        except Exception as e:
            msg = f"Failed to create branch {branch_name}: {e}"
            logger.error(msg)
            result.errors.append(msg)
            continue

        result.fixes_attempted += 1

        if not apply_fix(config, repo_path, vuln, fix_number=result.fixes_attempted, max_fixes=max_fixes):
            logger.info(f"No fix applied for {vuln.advisory_id}, skipping PR")
            result.skipped += 1
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

        pr = create_pull_request(client, repo_full_name, vuln, default_branch)
        if pr:
            result.prs_created += 1
            result.prs.append({
                "repo": repo_full_name,
                "advisory_id": vuln.advisory_id,
                "severity": vuln.severity,
                "title": vuln.title,
                "pr_url": pr.get("html_url", ""),
                "pr_number": pr.get("number", ""),
                "merged": pr.get("merged", False),
            })

        checkout(repo_path, default_branch)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        force=True,
    )

    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    if args.org:
        config.org = args.org

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

            if not vulns:
                logger.info(f"SKIP {repo_full_name} — no open vulnerabilities")
                continue
            if args.dry_run:
                logger.info("Dry run mode — skipping clone/fix/PR")
                continue
            if args.report_only:
                logger.info("Report-only mode — skipping clone/fix/PR")
                continue

            process_repo(client, config, repo_full_name, vulns, result, args.max_fixes)
            if result.fixes_attempted >= args.max_fixes:
                logger.info(f"Reached max fix attempts ({args.max_fixes}), stopping run")
                break

        report_html = generate_report(result, config.report_path)
        logger.info(f"Report saved to {config.report_path}")

        print(f"\n--- Summary ---")
        print(f"Repos scanned: {result.repos_scanned}")
        print(f"Vulnerabilities found: {result.vulns_found}")
        print(f"Fixes attempted: {result.fixes_attempted}")
        print(f"PRs created: {result.prs_created}")
        print(f"Skipped: {result.skipped}")
        print(f"Errors: {len(result.errors)}")
        if result.errors:
            for err in result.errors:
                print(f"  - {err}")

    finally:
        client.close()
