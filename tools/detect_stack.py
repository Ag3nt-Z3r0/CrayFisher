#!/usr/bin/env python3
"""Detect language, framework, and dependency files in a cloned repo. Outputs JSON."""
import argparse, json, re
from collections import Counter
from pathlib import Path

LANG_EXT: dict[str, str] = {
    ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript",
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
}

FRAMEWORK_SIGS: list[tuple[str, list[str]]] = [
    ("express",         ["express()", "require('express')", 'from "express"']),
    ("fastapi",         ["from fastapi", "FastAPI()"]),
    ("flask",           ["from flask", "Flask(__name__)"]),
    ("nextjs",          ['"next":', "from 'next/", 'from "next/']),
    ("django",          ["django.urls", "from django"]),
    ("mcp",             ["@modelcontextprotocol", "McpServer", "CallToolRequestSchema",
                         "StdioServerTransport", "ListToolsRequestSchema"]),
    ("langchain",       ["from langchain", "@langchain/", "langchain_core"]),
    ("llamaindex",      ["from llama_index", "llama-index"]),
    ("crewai",          ["from crewai", "CrewAI"]),
    ("autogen",         ["from autogen", "AssistantAgent"]),
    ("openai-agents",   ["Runner.run(", "from agents import", "openai.Agents"]),
]

DEP_FILES = {
    "package.json", "requirements.txt", "pyproject.toml",
    "go.mod", "Gemfile", "pom.xml", "Cargo.toml",
    "pnpm-lock.yaml", "yarn.lock",
}

SKIP_DIRS = {".git", "node_modules", ".venv", "dist", "build", "__pycache__"}


def scan(root: Path):
    lang_counts: Counter = Counter()
    frameworks: set[str] = set()
    dep_files: list[str] = []
    total_lines = 0

    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(p in f.parts for p in SKIP_DIRS):
            continue
        if f.name in DEP_FILES:
            dep_files.append(str(f.relative_to(root)))

        ext = f.suffix.lower()
        lang = LANG_EXT.get(ext)
        if lang:
            try:
                text = f.read_text(errors="ignore")
                lines = text.count("\n")
                lang_counts[lang] += lines
                total_lines += lines
                for fw, sigs in FRAMEWORK_SIGS:
                    if any(s in text for s in sigs):
                        frameworks.add(fw)
            except OSError:
                pass

    primary = lang_counts.most_common(1)[0][0] if lang_counts else "unknown"
    return {
        "primary_language": primary,
        "languages": dict(lang_counts.most_common()),
        "frameworks": sorted(frameworks),
        "total_lines": total_lines,
        "dependency_files": dep_files,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Local repository path")
    args = parser.parse_args()
    print(json.dumps(scan(Path(args.path)), indent=2))

if __name__ == "__main__":
    main()
