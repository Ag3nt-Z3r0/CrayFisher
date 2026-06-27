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
    # MCP tool registration (name may sit on the next line — full-text scan handles it)
    ("tool_handler", "mcp",
     re.compile(r'(?:server|mcpServer|McpServer)\.tool\s*\(\s*["\']([^"\']+)["\']')),
    ("tool_handler", "mcp",
     re.compile(r'\.setRequestHandler\s*\(\s*(\w+RequestSchema)')),
    ("tool_handler", "mcp",
     re.compile(r'\.registerTool\s*\(\s*["\']([^"\']+)["\']')),
    # Gateway RPC / WS control-plane handlers
    ("rpc_handler", "gateway",
     re.compile(r'\b(?:registerMethod|setMethodHandler|onMethod|handleMethod|addMethod)\s*\(\s*["\']([^"\']+)["\']')),
    ("ws_handler", "websocket",
     re.compile(r'\.(?:on|addEventListener)\s*\(\s*["\'](connection|message|connect)["\']')),
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
    # ── Rust ───────────────────────────────────────────────────────────
    # MCP (rmcp) tool handler — the `#[tool]` macro marks an exposed tool fn
    ("tool_handler", "rmcp",
     re.compile(r'#\[tool(?:\(|\s*\])')),
    # clap CLI — derive(Parser) struct + #[arg]/#[command] attrs
    ("cli_command", "clap",
     re.compile(r'#\[(?:arg|command)\b')),
    ("cli_command", "clap-derive",
     re.compile(r'#\[derive\([^)]*\bParser\b')),
    # axum route: .route("/path", get(handler))
    ("http_route", "axum",
     re.compile(r'\.route\s*\(\s*"([^"]+)"\s*,\s*(?:get|post|put|patch|delete|any)\s*\(')),
    # actix-web attribute routes: #[get("/path")]
    ("http_route", "actix",
     re.compile(r'#\[(?:get|post|put|patch|delete)\s*\(\s*"([^"]+)"')),
]


def find_entries(root: Path) -> list[dict]:
    results = []
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(p in f.parts for p in SKIP_DIRS):
            continue
        if f.suffix not in {".py", ".ts", ".js", ".tsx", ".jsx", ".mjs", ".rs"}:
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        rel = str(f.relative_to(root))
        # Full-text (multi-line) scan: a registration like `server.tool(\n  "name"`
        # spans lines, so per-line matching misses it. \s* in the patterns spans
        # newlines, so finditer over the whole file catches both styles.
        seen: set[tuple] = set()
        for ep_type, source, pat in PATTERNS:
            for m in pat.finditer(text):
                lineno = text.count("\n", 0, m.start()) + 1
                key = (ep_type, rel, lineno)
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "type": ep_type,
                    "source": source,
                    "match": " ".join(m.group(0).split())[:80],
                    "file": rel,
                    "line": lineno,
                })
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
