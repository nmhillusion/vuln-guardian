# src/reporter.py
from __future__ import annotations

from pathlib import Path

from src.models import RunResult


HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Advisor Agent Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
        .container { max-width: 960px; margin: 0 auto; }
        h1 { color: #58a6ff; margin-bottom: 1.5rem; font-size: 1.8rem; }
        h2 { color: #79c0ff; margin: 1.5rem 0 0.75rem; font-size: 1.2rem; border-bottom: 1px solid #21262d; padding-bottom: 0.3rem; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 2rem; }
        .stat { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1rem; text-align: center; }
        .stat-value { font-size: 2rem; font-weight: bold; color: #58a6ff; }
        .stat-label { font-size: 0.85rem; color: #8b949e; margin-top: 0.25rem; }
        table { width: 100%%; border-collapse: collapse; margin-bottom: 1.5rem; }
        th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid #21262d; }
        th { color: #8b949e; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
        tr:hover { background: #161b22; }
        .severity-critical { color: #f85149; }
        .severity-high { color: #d29922; }
        .severity-medium { color: #58a6ff; }
        .severity-low { color: #8b949e; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .empty { color: #8b949e; font-style: italic; padding: 1rem; }
        .error { color: #f85149; background: #161b22; border: 1px solid #f8514933; border-radius: 6px; padding: 0.75rem; margin-bottom: 0.5rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1>GitHub Advisor Agent Report</h1>

        <div class="summary">
            <div class="stat">
                <div class="stat-value">%(repos_scanned)d</div>
                <div class="stat-label">Repos Scanned</div>
            </div>
            <div class="stat">
                <div class="stat-value">%(vulns_found)d</div>
                <div class="stat-label">Vulns Found</div>
            </div>
            <div class="stat">
                <div class="stat-value">%(fixes_attempted)d</div>
                <div class="stat-label">Fixes Attempted</div>
            </div>
            <div class="stat">
                <div class="stat-value">%(prs_created)d</div>
                <div class="stat-label">PRs Created</div>
            </div>
            <div class="stat">
                <div class="stat-value">%(skipped)d</div>
                <div class="stat-label">Skipped</div>
            </div>
        </div>

        <h2>Fixes Applied (%(prs_created)d)</h2>
        %(fixes_table)s

        <h2>Unmerged PRs</h2>
        %(unmerged_table)s

        <h2>Skipped</h2>
        %(skipped_section)s

        <h2>Errors (%(error_count)d)</h2>
        %(errors_section)s
    </div>
</body>
</html>
"""


def _severity_class(severity: str) -> str:
    return f"severity-{severity.lower()}"


def _build_fixes_table(prs: list[dict]) -> str:
    if not prs:
        return '<div class="empty">No fixes applied.</div>'
    rows = ""
    for pr in prs:
        severity_cls = _severity_class(pr.get("severity", "unknown"))
        link = pr.get("url", "#")
        rows += (
            f'<tr>'
            f'<td>{pr.get("repo", "")}</td>'
            f'<td><a href="{link}">{pr.get("advisory_id", "")}</a></td>'
            f'<td class="{severity_cls}">{pr.get("severity", "")}</td>'
            f'<td>{pr.get("title", "")}</td>'
            f'<td><a href="{pr.get("pr_url", "#")}">PR #{pr.get("pr_number", "")}</a></td>'
            f'</tr>\n'
        )
    return (
        "<table><thead><tr><th>Repo</th><th>Advisory</th><th>Severity</th><th>Title</th><th>PR</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _build_unmerged_table(prs: list[dict]) -> str:
    unmerged = [pr for pr in prs if not pr.get("merged", False)]
    if not unmerged:
        return '<div class="empty">No unmerged PRs.</div>'
    rows = ""
    for pr in unmerged:
        rows += (
            f'<tr>'
            f'<td>{pr.get("repo", "")}</td>'
            f'<td><a href="{pr.get("pr_url", "#")}">PR #{pr.get("pr_number", "")}</a></td>'
            f'<td>{pr.get("title", "")}</td>'
            f'<td>{pr.get("advisory_id", "")}</td>'
            f'</tr>\n'
        )
    return (
        "<table><thead><tr><th>Repo</th><th>PR</th><th>Title</th><th>Advisory</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _build_errors_section(errors: list[str]) -> str:
    if not errors:
        return '<div class="empty">No errors.</div>'
    return "\n".join(f'<div class="error">{e}</div>' for e in errors)


def _build_skipped_section(result: RunResult) -> str:
    skipped_count = result.skipped
    if skipped_count == 0:
        return '<div class="empty">Nothing skipped.</div>'
    return f'<div class="empty">{skipped_count} vulnerability fix(es) skipped (already has PR or no auto-fix possible).</div>'


def generate_report(result: RunResult, report_path: str) -> str:
    """Generate HTML report and save to disk. Returns the HTML content."""
    html = HTML_TEMPLATE % {
        "repos_scanned": result.repos_scanned,
        "vulns_found": result.vulns_found,
        "fixes_attempted": result.fixes_attempted,
        "prs_created": result.prs_created,
        "skipped": result.skipped,
        "fixes_table": _build_fixes_table(result.prs),
        "unmerged_table": _build_unmerged_table(result.prs),
        "skipped_section": _build_skipped_section(result),
        "error_count": len(result.errors),
        "errors_section": _build_errors_section(result.errors),
    }

    Path(report_path).write_text(html, encoding="utf-8")
    return html
