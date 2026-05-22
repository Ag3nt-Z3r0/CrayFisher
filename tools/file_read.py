#!/usr/bin/env python3
"""Read a file snippet at a specific line with surrounding context. Outputs JSON."""
import argparse, json, sys
from pathlib import Path


def read_snippet(file_path: str, line: int, context: int = 10) -> dict:
    path = Path(file_path)
    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError as e:
        return {"error": str(e)}

    start = max(0, line - context - 1)
    end = min(len(lines), line + context)
    snippet_lines = lines[start:end]

    numbered = "\n".join(
        f"{start + i + 1:4}: {'>>>' if start + i + 1 == line else '   '} {l}"
        for i, l in enumerate(snippet_lines)
    )

    return {
        "file": file_path,
        "target_line": line,
        "line_start": start + 1,
        "line_end": end,
        "content": numbered,
        "total_lines": len(lines),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="File path")
    parser.add_argument("line", type=int, help="Target line number")
    parser.add_argument("--context", type=int, default=10,
                        help="Lines of context around target (default: 10)")
    args = parser.parse_args()

    result = read_snippet(args.file, args.line, args.context)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
