#!/usr/bin/env python3
"""GHSA lookup with offline seed + optional online fallback.

Used by Phase 4 criterion ⑤ when `is_agent_target = true`. The offline
seed lives at skills/knowledge/openclaw-ghsa-seed.json and contains the
~50KB Agent-Zero-DB distillation (Critical-13 + incomplete-fix
exemplars + per-component samples + aggregates). Online fallback queries
the GitHub Security Advisory database via the public REST API; it
requires no auth for queries under the unauth rate limit, but a
$GITHUB_TOKEN is honored when set.

Output JSON:
    seed_hits:       advisories from the offline seed matching the query
    online_hits:     advisories from GHSA online (best-effort)
    pattern_matches: incomplete-fix pattern flags from the seed
    aggregates:      seed-level statistics passed through for triage
"""
import argparse, json, os, sys, urllib.request, urllib.error
from pathlib import Path

SEED_PATH = Path(__file__).resolve().parent.parent / "skills" / "knowledge" / "openclaw-ghsa-seed.json"


def load_seed() -> dict:
    if not SEED_PATH.exists():
        return {"aggregates": {}, "advisories": [], "incomplete_fix_patterns": {}}
    try:
        return json.loads(SEED_PATH.read_text())
    except (OSError, json.JSONDecodeError) as e:
        return {"error": f"seed load failed: {e}", "advisories": []}


def seed_search(seed: dict, query: str) -> list[dict]:
    q = query.lower()
    out = []
    for a in seed.get("advisories", []):
        haystack = " ".join([
            a.get("id", ""),
            a.get("sum", ""),
            " ".join(a.get("cmp", [])),
            " ".join(a.get("cwes", [])),
            a.get("llm", "") or "",
        ]).lower()
        if q in haystack:
            out.append(a)
    return out


def pattern_lookup(seed: dict, query: str) -> list[dict]:
    q = query.lower()
    matches = []
    patterns = seed.get("incomplete_fix_patterns", {})
    advisories_by_id = {a["id"]: a for a in seed.get("advisories", [])}
    for pattern_name, ghsa_ids in patterns.items():
        for gid in ghsa_ids:
            adv = advisories_by_id.get(gid)
            if adv is None:
                continue
            haystack = adv.get("sum", "").lower() + " " + " ".join(adv.get("cmp", [])).lower()
            if q in haystack:
                matches.append({
                    "pattern": pattern_name,
                    "ghsa_id": gid,
                    "summary": adv.get("sum"),
                })
    return matches


def online_query(package: str, timeout: int = 8) -> list[dict]:
    """Best-effort GHSA query. Returns [] on any failure."""
    # GHSA REST search endpoint
    url = f"https://api.github.com/advisories?affects={package}&per_page=10"
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            if not isinstance(data, list):
                return []
            return [
                {
                    "ghsa_id": d.get("ghsa_id"),
                    "summary": (d.get("summary") or "")[:160],
                    "severity": d.get("severity"),
                    "cve_id": d.get("cve_id"),
                    "published": d.get("published_at"),
                    "url": d.get("html_url"),
                }
                for d in data[:10]
            ]
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("query",
                        help="package name, component tag, or CWE id")
    parser.add_argument("--no-online", action="store_true",
                        help="skip online GHSA query")
    args = parser.parse_args()

    seed = load_seed()
    if "error" in seed:
        print(json.dumps(seed, indent=2))
        sys.exit(1)

    result = {
        "query": args.query,
        "seed_path": str(SEED_PATH),
        "seed_hits": seed_search(seed, args.query),
        "pattern_matches": pattern_lookup(seed, args.query),
        "aggregates": seed.get("aggregates", {}),
    }
    if not args.no_online:
        result["online_hits"] = online_query(args.query)
    else:
        result["online_hits"] = []

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
