#!/usr/bin/env python3
"""Query OSV.dev for known CVEs affecting a package. Outputs JSON."""
import argparse, json, sys, urllib.request, urllib.error


def query_osv(package: str, ecosystem: str) -> dict:
    url = "https://api.osv.dev/v1/query"
    payload = json.dumps({"package": {"name": package, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            vulns = data.get("vulns", [])
            return {
                "package": package,
                "ecosystem": ecosystem,
                "vuln_count": len(vulns),
                "vulns": [
                    {
                        "id": v.get("id"),
                        "summary": v.get("summary", "")[:120],
                        "published": v.get("published", ""),
                        "cwe": [
                            d.get("cweIds", [])
                            for d in v.get("database_specific", {}).get("cwe_ids", [])
                        ] if "database_specific" in v else [],
                    }
                    for v in vulns[:10]
                ],
            }
    except urllib.error.URLError as e:
        return {"error": str(e), "package": package, "ecosystem": ecosystem}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package")
    parser.add_argument("ecosystem",
                        help="e.g. npm, PyPI, Go, Maven, RubyGems, crates.io")
    args = parser.parse_args()
    print(json.dumps(query_osv(args.package, args.ecosystem), indent=2))

if __name__ == "__main__":
    main()
