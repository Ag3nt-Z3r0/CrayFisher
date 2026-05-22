#!/usr/bin/env python3
"""Clone a GitHub repository to a temp directory. Outputs JSON."""
import argparse, json, subprocess, sys, tempfile
from pathlib import Path

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--dest", default=None)
    args = parser.parse_args()

    dest = args.dest or tempfile.mkdtemp(prefix="vuln-agent-")
    result = subprocess.run(
        ["git", "clone", "--depth=1", args.url, dest],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(json.dumps({"error": result.stderr.strip()}))
        sys.exit(1)

    path = Path(dest)
    total_files = sum(1 for f in path.rglob("*") if f.is_file()
                      and ".git" not in f.parts)
    print(json.dumps({"local_path": dest, "url": args.url, "total_files": total_files}))

if __name__ == "__main__":
    main()
