#!/usr/bin/env python3
"""Find HTTP routes, MCP tool handlers, and CLI entry points. Outputs JSON."""
import argparse, json, re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "dist", "build", "__pycache__"}

PATTERNS: list[tuple[str, str, re.Pattern]] = [
    # HTTP — Express/Fastify
    ("http_route", "express",
     re.compile(r'(?:app|router)\.(get|post|put|patch|delete|use)\s*\(\s*["\']([^"\']+)["\']')),
    # HTTP — Flask
    ("http_route", "flask",
     re.compile(r'@\w+\.route\s*\(\s*["\']([^"\']+)["\'](?:.*?methods\s*=\s*(\[[^\]]+\]))?')),
    # HTTP — FastAPI
    ("http_route", "fastapi",
     re.compile(r'@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']')),
    # MCP tool registration
    ("tool_handler", "mcp",
     re.compile(r'server\.tool\s*\(\s*["\']([^"\']+)["\']')),
    ("tool_handler", "mcp",
     re.compile(r'\.setRequestHandler\s*\(\s*CallToolRequestSchema')),
    # LangChain @tool
    ("tool_handler", "langchain",
     re.compile(r'@(?:langchain\.)?tool\b')),
    # OpenAI function_tool
    ("tool_handler", "openai-agents",
     re.compile(r'@function_tool\b')),
    # Agent lifecycle hooks
    ("agent_hook", "langchain",
     re.compile(r'def\s+(on_(?:llm_start|llm_end|tool_start|tool_end|agent_action|agent_finish))\s*\(')),
    # CLI — argparse / click
    ("cli_command", "argparse",
     re.compile(r'add_argument\s*\(\s*["\'](-{1,2}[\w-]+)["\']')),
    ("cli_command", "click",
     re.compile(r'@click\.(?:argument|option)\s*\(\s*["\']([^"\']+)["\']')),
]


def find_entries(root: Path) -> list[dict]:
    results = []
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(p in f.parts for p in SKIP_DIRS):
            continue
        if f.suffix not in {".py", ".ts", ".js", ".tsx", ".jsx"}:
            continue
        try:
            lines = f.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, 1):
            for ep_type, source, pat in PATTERNS:
                m = pat.search(line)
                if m:
                    results.append({
                        "type": ep_type,
                        "source": source,
                        "match": m.group(0)[:80],
                        "file": str(f.relative_to(root)),
                        "line": lineno,
                    })
                    break
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Local repository path")
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    entries = find_entries(Path(args.path))[:args.limit]
    print(json.dumps({"count": len(entries), "entries": entries}, indent=2))

if __name__ == "__main__":
    main()
