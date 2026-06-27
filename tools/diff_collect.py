#!/usr/bin/env python3
"""Collect a security-relevant view of a git diff (base..head). Data only.

Consumed by skills/01-recon/diff-review.md (the LLM does the triage/analysis).
Emits, per changed file: add/del counts, status, which security categories the
change touches, and the *removed* protection lines that are candidate
regressions (the LLM follows up with `git blame`). No judgment beyond a
mechanical `risk_hint` rollup (same spirit as incomplete_fix_scan's `score`).
"""
import argparse, json, os, re, subprocess
from pathlib import Path

# Security-relevant categories. "Protection" categories (authz/crypto/
# validation/agent) matter most when their lines are *removed* (regression).
CATEGORIES = {
    "authz": re.compile(
        r"auth|login|session|permission|\brole\b|\bacl\b|allow_?list|deny_?list|"
        r"is_?admin|authorize|access[_-]?control", re.I),
    "crypto": re.compile(
        r"encrypt|decrypt|hmac|hashlib|\bhash\b|signature|\bsign\b|\bsecret\b|"
        r"\bnonce\b|\biv\b|md5|sha1|\brandom\b|\btoken\b", re.I),
    "validation": re.compile(
        r"validate|saniti[sz]e|escape|\bwrap\b|\bcheck\b|\bassert\b|\bverify\b|"
        r"\bclean\b|\bfilter\b|normaliz", re.I),
    "exec_sink": re.compile(
        r"\bexec\b|\bspawn\b|subprocess|\beval\b|os\.system|child_process|"
        r"write_?file|\bpopen\b|\bshell\b|\bcommand\b", re.I),
    "agent": re.compile(
        r"wrapExternalContent|wrapWebContent|ask_?before|auto_?approve|sandbox|"
        r"human_input_mode|permission_mode|approve|guardrail|allowed_?tools|"
        r"tool_?result|register_?tool|@tool\b|@function_tool", re.I),
}
PROTECTION = ("authz", "crypto", "validation", "agent")
CODE_EXT = {".py", ".ts", ".js", ".tsx", ".jsx", ".mjs", ".go", ".rb", ".java",
            ".rs", ".php", ".yml", ".yaml"}


def git(args: list[str], cwd: str) -> str:
    env = dict(os.environ)
    env.setdefault("GIT_CONFIG_NOSYSTEM", "1")
    try:
        return subprocess.check_output(
            ["git", *args], cwd=cwd, env=env,
            stderr=subprocess.DEVNULL, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def resolve_base(repo: str, base: str | None) -> str:
    if base:
        return base
    # Prefer the previous tag (release-to-HEAD review), else HEAD~1.
    tag = git(["describe", "--tags", "--abbrev=0", "HEAD^"], repo).strip()
    if tag:
        return tag
    return "HEAD~1"


def categorize(line: str) -> list[str]:
    return [name for name, rx in CATEGORIES.items() if rx.search(line)]


def collect(repo: str, base: str, head: str, limit: int) -> dict:
    rng = f"{base}..{head}"

    name_status = git(["diff", "--name-status", "-M", rng], repo)
    if not name_status.strip():
        return {"repo": repo, "base": base, "head": head,
                "error": "empty diff — bad base/head ref, shallow clone "
                         "(no history), or no changes in range",
                "files": []}

    status_by_file: dict[str, str] = {}
    for ln in name_status.splitlines():
        cols = ln.split("\t")
        if len(cols) < 2:
            continue
        code = cols[0][0]
        path = cols[-1]  # for renames, the new path is last
        status_by_file[path] = {
            "A": "added", "D": "deleted", "M": "modified",
            "R": "renamed", "C": "copied"}.get(code, code)

    counts: dict[str, tuple] = {}
    for ln in git(["diff", "--numstat", "-M", rng], repo).splitlines():
        cols = ln.split("\t")
        if len(cols) >= 3:
            added = 0 if cols[0] == "-" else int(cols[0])
            deleted = 0 if cols[1] == "-" else int(cols[1])
            counts[cols[2]] = (added, deleted)

    # Line-level pass: which categories each file touches, and removed
    # protection lines (regression candidates).
    cats_added: dict[str, set] = {}
    cats_removed: dict[str, set] = {}
    removed_protection: dict[str, list] = {}
    cur = None
    for raw in git(["diff", "--unified=0", "-M", rng], repo).splitlines():
        if raw.startswith("+++ b/"):
            cur = raw[6:]
            continue
        if raw.startswith("diff --git") or raw.startswith("--- ") or raw.startswith("@@"):
            continue
        if cur is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            for c in categorize(raw[1:]):
                cats_added.setdefault(cur, set()).add(c)
        elif raw.startswith("-") and not raw.startswith("---"):
            cats = categorize(raw[1:])
            for c in cats:
                cats_removed.setdefault(cur, set()).add(c)
            prot = [c for c in cats if c in PROTECTION]
            if prot:
                bucket = removed_protection.setdefault(cur, [])
                if len(bucket) < 12:
                    bucket.append({"category": prot, "code": raw[1:].strip()[:160]})

    files = []
    for path, status in status_by_file.items():
        added, deleted = counts.get(path, (0, 0))
        touched = sorted(cats_added.get(path, set()) | cats_removed.get(path, set()))
        removed = removed_protection.get(path, [])
        is_code = Path(path).suffix in CODE_EXT
        # Mechanical risk rollup (signal, not a verdict).
        risk = "low"
        if is_code and (removed or {"authz", "crypto"} & set(touched)):
            risk = "high"
        elif is_code and ({"validation", "exec_sink", "agent"} & set(touched)):
            risk = "medium"
        # Refactor heuristic: large two-sided change.
        is_refactor = added >= 30 and deleted >= 30
        files.append({
            "file": path,
            "status": status,
            "added": added,
            "deleted": deleted,
            "categories_touched": touched,
            "removed_protection_lines": removed,
            "is_possible_refactor": is_refactor,
            "risk_hint": risk,
        })

    files.sort(key=lambda f: ({"high": 0, "medium": 1, "low": 2}[f["risk_hint"]],
                              -(f["added"] + f["deleted"])))
    files = files[:limit]

    commits = []
    log = git(["log", "--pretty=format:%H%x09%s", rng], repo)
    for ln in log.splitlines():
        sha, _, subject = ln.partition("\t")
        if sha:
            commits.append({"sha": sha, "subject": subject[:160]})

    return {
        "repo": repo,
        "base": base,
        "head": head,
        "commit_count": len(commits),
        "commits": commits[:100],
        "file_count": len(files),
        "high_risk_count": sum(1 for f in files if f["risk_hint"] == "high"),
        "removed_protection_total": sum(len(f["removed_protection_lines"]) for f in files),
        "files": files,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", help="Local repository path")
    parser.add_argument("--base", default=None,
                        help="Base ref (default: previous tag, else HEAD~1)")
    parser.add_argument("--head", default="HEAD", help="Head ref (default: HEAD)")
    parser.add_argument("--limit", type=int, default=200, help="Max files")
    args = parser.parse_args()
    base = resolve_base(args.repo, args.base)
    print(json.dumps(collect(args.repo, base, args.head, args.limit), indent=2))


if __name__ == "__main__":
    main()
