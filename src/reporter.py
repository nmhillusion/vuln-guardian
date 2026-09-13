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
    <title>vuln-guardian Report</title>
    <style>
        :root {
            --paper: #ffffff;
            --wash: #f8fafc;
            --ink: #0f172a;
            --muted: #64748b;
            --line: #e2e8f0;
            --guard: #0f766e;
            --link: #0f766e;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--wash); color: var(--ink); padding: 2rem; }
        .container { max-width: 960px; margin: 0 auto; }
        .masthead { background: var(--paper); border: 1px solid var(--line); border-top: 4px solid var(--guard); border-radius: 12px; padding: 1.5rem 1.75rem; margin-bottom: 1.5rem; }
        .masthead h1 { font-size: 1.6rem; letter-spacing: -0.01em; }
        .masthead h1 .shield { color: var(--guard); }
        .masthead .verdict { color: var(--muted); margin-top: 0.35rem; font-size: 0.95rem; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 0.5rem; }
        .stat { background: var(--paper); border: 1px solid var(--line); border-radius: 10px; padding: 1rem; text-align: center; }
        .stat-value { font-size: 2rem; font-weight: 700; color: var(--ink); }
        .stat-label { font-size: 0.85rem; color: var(--muted); margin-top: 0.25rem; }
        h2 { font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.09em; color: var(--muted); margin: 1.75rem 0 0.75rem; }
        table { width: 100%%; border-collapse: separate; border-spacing: 0; margin-bottom: 0.5rem; background: var(--paper); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; font-size: 0.9rem; }
        th, td { padding: 0.55rem 0.8rem; text-align: left; border-bottom: 1px solid var(--line); }
        tbody tr:last-child td { border-bottom: none; }
        th { color: var(--muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; background: var(--wash); }
        tbody tr:hover { background: #f1f5f9; }
        .pill { display: inline-block; padding: 0.12rem 0.6rem; border-radius: 999px; font-size: 0.76rem; font-weight: 700; white-space: nowrap; }
        .severity-critical { background: #fee2e2; color: #b91c1c; }
        .severity-high { background: #fef3c7; color: #b45309; }
        .severity-medium { background: #dbeafe; color: #1d4ed8; }
        .severity-low { background: #f1f5f9; color: #475569; }
        .severity-unknown { background: #f1f5f9; color: var(--muted); }
        a { color: var(--link); text-decoration: none; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.84em; }
        a:hover { text-decoration: underline; }
        .empty { color: var(--muted); font-style: italic; padding: 1rem; background: var(--paper); border: 1px dashed var(--line); border-radius: 10px; }
        .error { color: #b91c1c; background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 0.75rem; margin-bottom: 0.5rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="masthead">
            <h1><span class="shield">🛡️</span> vuln-guardian Report</h1>
            <div class="verdict">%(verdict)s</div>
        </div>

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

        <h2>Pending Tool PRs (%(pending_count)d)</h2>
        %(pending_table)s

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
            f'<td><span class="pill {severity_cls}">{pr.get("severity", "")}</span></td>'
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


def _build_pending_table(prs: list[dict]) -> str:
    if not prs:
        return '<div class="empty">No pending tool PRs.</div>'
    rows = ""
    for pr in prs:
        rows += (
            f'<tr>'
            f'<td>{pr.get("repo", "")}</td>'
            f'<td><a href="{pr.get("pr_url", "#")}">PR #{pr.get("pr_number", "")}</a></td>'
            f'<td>{pr.get("title", "")}</td>'
            f'<td>{pr.get("advisory_id", "")}</td>'
            f'</tr>\n'
        )
    return (
        "<table><thead><tr><th>Repo</th><th>PR</th><th>Title</th><th>Advisories</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _build_errors_section(errors: list[str]) -> str:
    if not errors:
        return '<div class="empty">No errors.</div>'
    return "\n".join(f'<div class="error">{e}</div>' for e in errors)


def _build_skipped_section(result: RunResult) -> str:
    if not result.skipped_items:
        if result.skipped == 0:
            return '<div class="empty">Nothing skipped.</div>'
        return f'<div class="empty">{result.skipped} vulnerability fix(es) skipped.</div>'
    rows = ""
    for item in result.skipped_items:
        reason = item.get("reason", "")
        if item.get("branch") and item.get("url"):
            reason += f' (<a href="{item["url"]}">{item["branch"]}</a>)'
        rows += (
            f'<tr>'
            f'<td>{item.get("repo", "")}</td>'
            f'<td>{item.get("advisory_id", "")}</td>'
            f'<td>{reason}</td>'
            f'</tr>\n'
        )
    return (
        f'<div class="empty">{result.skipped} vulnerability fix(es) skipped.</div>'
        "<table><thead><tr><th>Repo</th><th>Advisory</th><th>Reason</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def generate_report(result: RunResult, report_path: str) -> str:
    """Generate HTML report and save to disk. Returns the HTML content."""
    verdict = (
        f"{result.vulns_found} found · {result.prs_created} fixed this run · "
        f"{len(result.pending_prs)} awaiting review"
    )
    html = HTML_TEMPLATE % {
        "verdict": verdict,        "repos_scanned": result.repos_scanned,
        "vulns_found": result.vulns_found,
        "fixes_attempted": result.fixes_attempted,
        "prs_created": result.prs_created,
        "skipped": result.skipped,
        "fixes_table": _build_fixes_table(result.prs),
        "unmerged_table": _build_unmerged_table(result.prs),
        "pending_count": len(result.pending_prs),
        "pending_table": _build_pending_table(result.pending_prs),
        "skipped_section": _build_skipped_section(result),
        "error_count": len(result.errors),
        "errors_section": _build_errors_section(result.errors),
    }

    Path(report_path).write_text(html, encoding="utf-8")
    return html
