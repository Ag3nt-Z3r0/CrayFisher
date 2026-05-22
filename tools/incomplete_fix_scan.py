#!/usr/bin/env python3
"""Scan a repo's recent history for incomplete-fix candidates.

Applies Agent-Zero-DB heuristics H1 + H2 to `git log`:

  H1: commit message matches `incomplete fix | incomplete patch
      | bypass for | variant of` (case-insensitive)
  H2: commit message contains a GHSA id (`GHSA-xxxx-xxxx-xxxx`) other
      than the current commit

For each H1/H2 hit, also list the files touched by that commit and
emit them as candidates with `score` (higher = more confident) and
`pattern` (A/B/C/D/E or "unknown" when only H2 / H1 alone fires).

Optional cross-reference against
`skills/knowledge/openclaw-ghsa-seed.json` — when the referenced GHSA
appears in the seed under one of `incomplete_fix_patterns.*`, the
pattern is reported.
"""
import argparse, json, os, re, subprocess, sys
from pathlib import Path

SEED_PATH = Path(__file__).resolve().parent.parent / "skills" / "knowledge" / "openclaw-ghsa-seed.json"

H1 = re.compile(r"\b(incomplete fix|incomplete patch|bypass for|variant of)\b", re.I)
GHSA = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.I)
CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def git(args: list[str], cwd: str) -> str:
    env = dict(os.environ)
    env.setdefault("GIT_CONFIG_NOSYSTEM", "1")
    try:
        return subprocess.check_output(
            ["git", *args], cwd=cwd, env=env,
            stderr=subprocess.DEVNULL, text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def load_seed_patterns() -> dict[str, str]:
    """Return ghsa_id → pattern name from the seed."""
    if not SEED_PATH.exists():
        return {}
    try:
        seed = json.loads(SEED_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    out = {}
    for pattern, ids in seed.get("incomplete_fix_patterns", {}).items():
        # pattern looks like "A_re_emergence" — keep the leading letter.
        letter = pattern.split("_", 1)[0].upper() if "_" in pattern else pattern
        for gid in ids:
            out[gid] = letter
    return out


def scan(repo: str, since: str, limit: int) -> dict:
    seed_patterns = load_seed_patterns()

    # We use a literal sentinel `<<<CF_REC>>>` between commits and `<<<CF_FILES>>>`
    # between the message and the file list. Simpler than mixing -z with RS;
    # avoids platform-specific NUL handling.
    REC = "<<<CF_REC>>>"
    SEP = "<<<CF_FILES>>>"
    log = git(
        ["log", f"--since={since}",
         f"--pretty=format:%H%n%s%n%b{SEP}",
         "--name-only", f"--max-count={limit}"],
        cwd=repo,
    )
    if not log.strip():
        return {"repo": repo, "since": since,
                "error": "git log empty — not a git repo, no recent commits, or git unavailable",
                "candidates": []}

    candidates = []
    # Split on the file-list sentinel. Each chunk after the first contains
    # the trailing file list of the *previous* commit + the start of the next.
    # We process commit-by-commit by joining adjacent fragments.
    # Easier strategy: re-split on the sentinel and pair (commit-header, files).
    parts = log.split(SEP)
    # parts[i] (for i >= 0) ends with files of commit i and starts with header
    # of commit i+1 (except parts[0] which is header of commit 0 only).
    headers = [parts[0]]
    files_list = []
    for i in range(1, len(parts)):
        # parts[i] begins with file list of commit (i-1), then header of commit i
        # The first non-empty line that does not contain "/" or "." in a
        # filename-shape is ambiguous; instead we rely on a blank line that
        # git inserts between the file list and the next commit's hash (since
        # commits with no parent get no blank, fallback to first 40-hex line).
        chunk = parts[i]
        lines = chunk.split("\n")
        # File list ends just before the line that looks like a commit hash
        # (40 hex chars), which is the start of the next commit.
        files_for_prev = []
        next_header_start = None
        for j, ln in enumerate(lines):
            stripped = ln.strip()
            if len(stripped) == 40 and all(c in "0123456789abcdef" for c in stripped):
                next_header_start = j
                break
            if stripped:
                files_for_prev.append(stripped)
        files_list.append(files_for_prev)
        if next_header_start is not None:
            headers.append("\n".join(lines[next_header_start:]))
        # If no next_header_start, parts[i] is just the trailing files of the
        # last commit (file list with no next commit).
    # Trailing files of the last commit
    if len(parts) > 1 and len(files_list) < len(headers):
        # last chunk had files but no following header
        files_list.append([])  # placeholder; actual files handled below
    # Fallback: ensure files_list has same length as headers (last commit's files)
    if len(files_list) < len(headers):
        files_list.extend([[] for _ in range(len(headers) - len(files_list))])

    for idx, header in enumerate(headers):
        if not header.strip():
            continue
        lines = header.split("\n", 2)
        sha = lines[0].strip() if lines else ""
        subject = lines[1].strip() if len(lines) > 1 else ""
        body = lines[2] if len(lines) > 2 else ""
        if not sha or len(sha) != 40:
            continue
        msg = subject + "\n" + body

        h1_hit = bool(H1.search(msg))
        ghsa_refs = [g for g in GHSA.findall(msg)]
        cve_refs = [c for c in CVE.findall(msg)]
        h2_hit = bool(ghsa_refs)

        if not (h1_hit or h2_hit):
            continue

        # Cross-reference seed.
        pattern = "unknown"
        for gid in ghsa_refs:
            if gid in seed_patterns:
                pattern = seed_patterns[gid]
                break
        if pattern == "unknown" and h1_hit and h2_hit:
            pattern = "A"  # H1 + H2 = strong A signal

        score = 0.4
        if h1_hit:
            score += 0.3
        if h2_hit:
            score += 0.2
        if pattern != "unknown":
            score += 0.1
        score = round(min(score, 1.0), 2)

        files = files_list[idx] if idx < len(files_list) else []

        candidates.append({
            "commit": sha,
            "subject": subject[:160],
            "h1": h1_hit,
            "h2": h2_hit,
            "ghsa_refs": ghsa_refs,
            "cve_refs": cve_refs,
            "pattern": pattern,
            "files": files[:30],
            "score": score,
        })

    candidates.sort(key=lambda c: -c["score"])
    return {
        "repo": repo,
        "since": since,
        "scanned_records": len(headers),
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", help="Local repository path")
    parser.add_argument("--since", default="6 months ago",
                        help="git log --since= argument (default: '6 months ago')")
    parser.add_argument("--limit", type=int, default=2000,
                        help="Max commits to inspect")
    args = parser.parse_args()
    print(json.dumps(scan(args.repo, args.since, args.limit), indent=2))


if __name__ == "__main__":
    main()
