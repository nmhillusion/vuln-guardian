# src/fixer.py
from __future__ import annotations

import logging
import queue
import subprocess
import threading
import time
from pathlib import Path

from src.config import Config
from src.models import Vulnerability

logger = logging.getLogger(__name__)

_NPM_MANIFEST_NAMES = ("package.json", "package-lock.json")

_BASE_FIX_PROMPT = (
    "This is a non-interactive mode, so I approve for you to read, edit, and delete files, "
    "and to run normal terminal commands (such as npm install and build/test commands), "
    "but ONLY for files and operations within the current project directory (the .repos clone folder). "
    "Do NOT run dangerous or destructive commands: no force operations, no operations that "
    "affect the remote repository (push, force-push, rebase, merge, tag deletion), "
    "no commands that modify files outside the .repos folder, and no credential or secret "
    "operations. Do not ask for confirmation for approved actions; stop and report if an "
    "action is outside the approved scope. "
)

_TRANSITIVE_DEP_RULE = (
    " This is a TRANSITIVE dependency: {package} is pulled in by another dependency, "
    "not declared directly. {fix_instruction} "
    "Do NOT run dependency-tree exploration commands (mvn dependency:tree, npm ls, gradle dependencies) — "
    "apply the fix directly and stop."
)


def _is_npm_project(repo_path: Path) -> bool:
    """Check if the repo has any npm manifest anywhere in the tree."""
    return any(
        path.name in _NPM_MANIFEST_NAMES
        for path in repo_path.rglob("*")
        if path.is_file()
    )


def _has_changes(repo_path: Path) -> bool:
    """Check if there are uncommitted changes in the repo."""
    result = subprocess.run(
        ["git", "-C", str(repo_path), "status", "--porcelain"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return bool(result.stdout.strip())


def _commit_changes(repo_path: Path, message: str) -> bool:
    """Stage and commit all changes."""
    subprocess.run(["git", "-C", str(repo_path), "add", "-A"], check=True)
    result = subprocess.run(
        ["git", "-C", str(repo_path), "commit", "-m", message],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.returncode == 0


def _agent_label(ai_agent_args: list[str], configured_model: str = "") -> str:
    """Human-readable 'name (model)' label. Prefers the explicitly configured model."""
    name = Path(ai_agent_args[0]).stem if ai_agent_args else "agent"
    if configured_model:
        return f"{name} ({configured_model})"
    for i, arg in enumerate(ai_agent_args):
        if arg in ("-m", "--model") and i + 1 < len(ai_agent_args):
            candidate = ai_agent_args[i + 1]
            if candidate not in ("{model}", "{prompt}"):
                return f"{name} ({candidate})"
            break
        if arg.startswith("--model="):
            return f"{name} ({arg.split('=', 1)[1]})"
    return f"{name} (default)"


_SNIPPET_CONTEXT_LINES = 3
_SNIPPET_MAX_MATCHES = 2
_SNIPPET_MAX_LINE_LEN = 200


def _format_snippet(all_lines: list[str], match_idx: int) -> str:
    """Format one match with surrounding context lines; >>> marks the match."""
    start = max(0, match_idx - _SNIPPET_CONTEXT_LINES)
    end = min(len(all_lines), match_idx + _SNIPPET_CONTEXT_LINES + 1)
    out = []
    for i in range(start, end):
        text = all_lines[i].rstrip("\n")
        if len(text) > _SNIPPET_MAX_LINE_LEN:
            text = text[:_SNIPPET_MAX_LINE_LEN] + "..."
        marker = ">>>" if i == match_idx else "   "
        out.append(f"{marker} {i + 1}: {text}")
    return "\n".join(out)


def _find_manifest_lines(repo_path: Path, manifest_path: str, package_name: str) -> str | None:
    """Find dependency declaration lines in the manifest with context."""
    manifest = repo_path / manifest_path
    if not manifest.is_file():
        return None
    try:
        content = manifest.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    terms = [package_name.lower()]
    if ":" in package_name:  # maven group:artifact -> also match bare artifactId
        terms.append(package_name.split(":")[-1].lower())
    matches = [i for i, line in enumerate(content) if any(t in line.lower() for t in terms)]
    if not matches:
        return None
    blocks = [f"{manifest_path}:{i + 1}:\n{_format_snippet(content, i)}" for i in matches[:_SNIPPET_MAX_MATCHES]]
    return "\n".join(blocks)


def _read_code_snippet(repo_path: Path, file_path: str, start_line: int | None) -> str | None:
    """Read exact code-scanning alert lines from the cloned repo with context."""
    target = repo_path / file_path
    if not target.is_file() or start_line is None:
        return None
    try:
        content = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not content:
        return None
    match_idx = max(0, min(start_line - 1, len(content) - 1))
    return f"{file_path}:{start_line}:\n{_format_snippet(content, match_idx)}"


_AGENT_TIMEOUT_SECONDS = 600
_EOF = object()


def _run_agent_streaming(cmd: list[str], cwd: str, timeout: int, tag: str) -> tuple[int | None, str]:
    """Run the agent CLI, streaming each output line to the log live.

    Returns (returncode, full_output); returncode None means timed out (process killed).
    """
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        cwd=cwd,
    )
    line_queue: queue.Queue = queue.Queue()

    def _reader() -> None:
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                line_queue.put(line)
        finally:
            line_queue.put(_EOF)

    reader = threading.Thread(target=_reader, daemon=True)
    reader.start()

    out_lines: list[str] = []
    eof = False
    start = time.monotonic()
    while True:
        try:
            proc.wait(timeout=0.5)
            exited = True
        except subprocess.TimeoutExpired:
            exited = False
        while True:
            try:
                item = line_queue.get_nowait()
            except queue.Empty:
                break
            if item is _EOF:
                eof = True
            else:
                text = item.rstrip("\n")
                out_lines.append(text)
                logger.info(f"[{tag}] {text}")
        if exited and eof:
            break
        if time.monotonic() - start > timeout:
            proc.kill()
            proc.wait()
            return None, "\n".join(out_lines)
    return proc.returncode, "\n".join(out_lines)


def _delete_lockfiles(repo_path: Path, manifest_paths: list[str]) -> list[str]:
    """Delete lockfiles inside the repo. Returns manifests actually deleted."""
    deleted: list[str] = []
    repo_root = repo_path.resolve()
    for manifest in dict.fromkeys(manifest_paths):
        lockfile = (repo_path / manifest).resolve()
        if repo_root not in lockfile.parents or not lockfile.is_file():
            logger.warning(f"  Skipping lockfile delete: {manifest} is outside the repo or missing")
            continue
        lockfile.unlink()
        logger.info(f"  Deleted {manifest} before invoking agent")
        deleted.append(manifest)
    return deleted


def _commit_paths(repo_path: Path, paths: list[str], message: str) -> bool:
    """Stage paths and commit. Returns True on success."""
    subprocess.run(["git", "-C", str(repo_path), "add", "--", *paths], check=True)
    result = subprocess.run(
        ["git", "-C", str(repo_path), "commit", "-m", message],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.returncode == 0


def _prepare_vuln(repo_path: Path, vuln: Vulnerability) -> tuple[str, str]:
    """Compute snippet for one vuln. Returns (prompt section, suggestion)."""
    if vuln.source == "dependabot" and vuln.manifest_path and vuln.package_name:
        vuln.introduced_at = _find_manifest_lines(repo_path, vuln.manifest_path, vuln.package_name)
    elif vuln.source == "code_scanning" and vuln.affected_files:
        vuln.introduced_at = _read_code_snippet(repo_path, vuln.affected_files[0], vuln.start_line)

    affected = ", ".join(vuln.affected_files) if vuln.affected_files else "affected files"
    suggestion = ""
    if vuln.package_name and vuln.patched_version:
        suggestion = f"GitHub recommends upgrading {vuln.package_name} to version {vuln.patched_version}"
        suggestion += f" (vulnerable range: {vuln.vulnerable_range})." if vuln.vulnerable_range else "."

    section = (
        f"--- Vulnerability {vuln.advisory_id}: {vuln.title} ---\n"
        f"Affected files: {affected}. "
        f"{vuln.description}"
    )
    if suggestion:
        section += f" {suggestion}"
    if vuln.manifest_path:
        section += f" The dependency is declared in {vuln.manifest_path}."
    if vuln.introduced_at:
        section += f" Exact introducing location:\n{vuln.introduced_at}"
    if vuln.dependency_relationship == "transitive" and vuln.package_name:
        if vuln.patched_version:
            fix_instruction = (
                f"GitHub recommends version {vuln.patched_version}: "
                f"pin {vuln.package_name} to that version as a direct dependency."
            )
        else:
            fix_instruction = "Upgrade the direct dependency that introduces it to a fixed version."
        section += _TRANSITIVE_DEP_RULE.format(package=vuln.package_name, fix_instruction=fix_instruction)
    return section, suggestion


def _log_vuln_detail(vuln: Vulnerability, suggestion: str) -> None:
    logger.info(f"  [{vuln.advisory_id}] Severity: {vuln.severity} | Package: {vuln.package_name} | Source: {vuln.source}")
    if vuln.dependency_relationship or vuln.dependency_scope or vuln.manifest_path:
        logger.info(
            f"  [{vuln.advisory_id}] Dependency: {vuln.dependency_relationship or '?'}"
            f" | Scope: {vuln.dependency_scope or '?'}"
            f" | Manifest: {vuln.manifest_path or '?'}"
        )
    logger.info(f"  [{vuln.advisory_id}] Title: {vuln.title}")
    if suggestion:
        logger.info(f"  [{vuln.advisory_id}] Suggestion: {suggestion}")
    if vuln.introduced_at:
        logger.info(f"  [{vuln.advisory_id}] Introduced at:\n{vuln.introduced_at}")


def _fix_position(fix_number: int | None, max_fixes: int | None) -> str:
    if fix_number is not None and max_fixes is not None:
        return f" (fix {fix_number}/{max_fixes})"
    return ""


def apply_fix(
    config: Config,
    repo_path: Path,
    vulns: list[Vulnerability],
    fix_number: int | None = None,
    max_fixes: int | None = None,
) -> bool:
    """Fix a batch of vulnerabilities, logging START/END banners. Returns True if fix applied."""
    ids = ", ".join(v.advisory_id for v in vulns)
    position = _fix_position(fix_number, max_fixes)
    logger.info(f"===== START fix batch [{ids}]{position} =====")
    ok = _apply_fix_inner(config, repo_path, vulns, fix_number, max_fixes)
    logger.info(f"===== END fix batch [{ids}]{position}: {'FIXED' if ok else 'NO FIX'} =====")
    return ok


def _apply_fix_inner(
    config: Config,
    repo_path: Path,
    vulns: list[Vulnerability],
    fix_number: int | None = None,
    max_fixes: int | None = None,
) -> bool:
    """Invoke agent CLI to fix a batch of vulnerabilities. Returns True if fix applied."""
    if not vulns:
        return False
    position = _fix_position(fix_number, max_fixes)
    ids = [v.advisory_id for v in vulns]
    tag = ",".join(ids)

    is_npm = _is_npm_project(repo_path)
    lockfile_vulns: list[Vulnerability] = []
    agent_vulns: list[Vulnerability] = []
    for v in vulns:
        if is_npm and v.manifest_path and v.manifest_path.endswith("package-lock.json"):
            v.introduced_at = None
            lockfile_vulns.append(v)
        else:
            agent_vulns.append(v)

    deleted: list[str] = []
    lockfix_committed = False
    if lockfile_vulns:
        try:
            deleted = _delete_lockfiles(repo_path, [v.manifest_path for v in lockfile_vulns if v.manifest_path])
        except Exception as e:
            logger.warning(f"  Lockfile delete failed: {e}")
            deleted = []
        if deleted:
            msg = f"fix: remove lockfile(s) [{', '.join(deleted)}] ({', '.join(v.advisory_id for v in lockfile_vulns)})"
            try:
                lockfix_committed = _commit_paths(repo_path, deleted, msg)
            except Exception as e:
                logger.warning(f"  Lockfile removal commit failed: {e}")
                lockfix_committed = False
            if lockfix_committed:
                logger.info(f"  Lockfile-only fix committed for {', '.join(v.advisory_id for v in lockfile_vulns)}")

    if not agent_vulns:
        if lockfix_committed:
            return True
        # Commit failed: let the agent handle these vulns (lockfile already deleted).
        agent_vulns = lockfile_vulns
        lockfile_vulns = []

    prompt = (
        _BASE_FIX_PROMPT
        + "You are an advanced programmer, and has a very strong security guard charactrer. "
        + f"Fix the following {len(agent_vulns)} security vulnerabilities in this repo. "
        + "Fix ALL of them, then stop. "
    )
    for v in agent_vulns:
        section, suggestion = _prepare_vuln(repo_path, v)
        prompt += "\n\n" + section
        _log_vuln_detail(v, suggestion)
    if deleted:
        lock_ids = ", ".join(v.advisory_id for v in lockfile_vulns)
        prompt += (
            f"\n\nNote: {', '.join(deleted)} was already deleted to resolve {lock_ids}; "
            "run the package manager to regenerate it with fixed versions. Do not restore old versions."
        )

    logger.info(f"Invoking agent {_agent_label(config.ai_agent_args, config.ai_agent_model)} for batch [{tag}]{position}...")

    cmd: list[str] = []
    for a in config.ai_agent_args:
        if a == "{model}":
            if config.ai_agent_model:
                cmd.append(config.ai_agent_model)
            elif cmd and cmd[-1] in ("-m", "--model"):
                cmd.pop()
            continue
        cmd.append(prompt if a == "{prompt}" else a)
    if prompt not in cmd:
        cmd.append(prompt)

    try:
        returncode, output = _run_agent_streaming(cmd, str(repo_path), _AGENT_TIMEOUT_SECONDS, tag)
    except Exception as e:
        logger.warning(f"Agent failed to run for batch [{tag}]: {e}")
        return False

    if returncode is None:
        logger.warning(f"Agent timed out for batch [{tag}]")
        return False

    if returncode != 0:
        tail = "\n".join(output.splitlines()[-20:])
        logger.warning(f"Agent failed for batch [{tag}] (exit {returncode}), tail:\n{tail}")
        return False

    if not _has_changes(repo_path):
        logger.info(f"No changes after agent run for batch [{tag}]")
        return lockfix_committed

    commit_msg = f"fix: {len(agent_vulns)} vulnerabilities ({', '.join(v.advisory_id for v in agent_vulns)})"
    if not _commit_changes(repo_path, commit_msg):
        logger.warning(f"Failed to commit fix for batch [{tag}]")
        return False

    logger.info(f"Fixed batch [{tag}]{position} — fix committed")
    return True
