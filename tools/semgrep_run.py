#!/usr/bin/env python3
"""Run Semgrep on a repository and output findings as JSON."""
import argparse, json, subprocess, sys
from pathlib import Path

SEMGREP_BIN_CANDIDATES = [
    ".venv/bin/semgrep",
    "semgrep",
]

OFFICIAL_RULESETS = ["p/typescript", "p/nodejs", "p/python", "p/security-audit"]

CWE_MAP = {
    "CWE-89": "SQL_INJECTION",
    "CWE-78": "COMMAND_INJECTION",
    "CWE-22": "PATH_TRAVERSAL",
    "CWE-79": "XSS",
    "CWE-918": "SSRF",
    "CWE-502": "INSECURE_DESERIALIZATION",
    "CWE-400": "DENIAL_OF_SERVICE",
    "CWE-1333": "DENIAL_OF_SERVICE",
    "CWE-1427": "PROMPT_INJECTION",
    "CWE-346": "LOGIC_BUG",
    "CWE-310": "LOGIC_BUG",
}


def find_semgrep(project_root: str) -> str:
    for candidate in SEMGREP_BIN_CANDIDATES:
        p = Path(project_root) / candidate
        if p.exists():
            return str(p)
    return "semgrep"


def extract_snippet(r: dict) -> str:
    """Return the matched source text.

    Semgrep's OSS tier sometimes puts the placeholder string "requires login"
    in extra.lines (the real code needs a Pro login to render). When that
    happens — or when lines is empty — re-read the matched line range from the
    file so the snippet is always the actual code, not a placeholder.
    """
    lines = (r.get("extra", {}).get("lines", "") or "").strip()
    if lines and lines.lower() != "requires login":
        return lines
    try:
        start = r["start"]["line"]
        end = r.get("end", {}).get("line", start)
        with open(r["path"], errors="ignore") as fh:
            src = fh.readlines()
        return "".join(src[start - 1:end]).strip()
    except (OSError, KeyError, IndexError):
        return ""


def run_semgrep(target: str, rules_dir: str, official: bool = False) -> list[dict]:
    script_dir = str(Path(__file__).parent.parent)
    semgrep = find_semgrep(script_dir)

    cmd = [semgrep, "scan", "--json", "--no-rewrite-rule-ids",
           "--config", rules_dir, target]

    if official:
        for rs in OFFICIAL_RULESETS:
            cmd += ["--config", rs]

    result = subprocess.run(cmd, capture_output=True, text=True)

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        cwe_list = meta.get("cwe", [])
        cwe = (cwe_list[0] if isinstance(cwe_list, list) and cwe_list
               else cwe_list if isinstance(cwe_list, str) else "")
        cwe_id = cwe.split(":")[0].strip() if ":" in cwe else cwe

        findings.append({
            "rule_id": r.get("check_id", ""),
            "file": r["path"],
            "line": r["start"]["line"],
            "message": r.get("extra", {}).get("message", ""),
            "severity": r.get("extra", {}).get("severity", "WARNING").upper(),
            "cwe": cwe_id,
            "vuln_type": CWE_MAP.get(cwe_id, "UNKNOWN"),
            # Chain-primitive tag from rules/semgrep/chain-primitives.yaml.
            # None for ordinary rules; the recon agent (Phase 3-C, Step 7) drops
            # non-null values straight into the capability graph.
            "chain_primitive": meta.get("chain_primitive"),
            "snippet": extract_snippet(r),
        })

    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Repository path to scan")
    parser.add_argument("--rules", default=None, help="Custom rules directory")
    parser.add_argument("--official", action="store_true",
                        help="Also run official rulesets (requires network)")
    args = parser.parse_args()

    script_dir = Path(__file__).parent.parent
    rules_dir = args.rules or str(script_dir / "rules" / "semgrep")

    findings = run_semgrep(args.path, rules_dir, args.official)
    print(json.dumps({"count": len(findings), "findings": findings}, indent=2))

if __name__ == "__main__":
    main()
