#!/usr/bin/env python3
"""Derive an agent-architecture component map from a repo.

Output mirrors the 18-component threat-boundary schema used in
Agent-Zero-DB/learning/week1/architecture/openclaw-architecture.md, projected
onto the components that exist in a generic agent framework target. Used by
Phase 1 Recon when detect_stack.py reports is_agent_target = true.

Output keys:
    components[]            — generic component-type tags found in the repo
    llm_call_sites[]        — where LLM API is invoked
    tool_registry[]         — where tools are registered to an agent
    memory_stores[]         — where conversation/memory is persisted
    sub_agent_spawners[]    — where new agent/subagent instances are created
    sandbox_sites[]         — sandbox/container spawn sites
    approval_gates[]        — approval / human-in-the-loop checks
    trust_label_sites[]     — string labels likely used as trust markers
"""
import argparse, json, re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "dist", "build", "__pycache__", "vendor", "target"}
SCAN_EXTS = {".py", ".ts", ".js", ".tsx", ".jsx", ".mjs"}

# Each rule: (category, label, regex). One file site per match line.
RULES: list[tuple[str, str, re.Pattern]] = [
    # ── LLM call sites ─────────────────────────────────────────────
    ("llm_call_sites", "openai",
     re.compile(r"\b(openai\.chat|openai\.completions|client\.chat\.completions|client\.messages|openai\.Client)\b")),
    ("llm_call_sites", "anthropic",
     re.compile(r"\b(anthropic\.|Anthropic\()|client\.messages\.create\b")),
    ("llm_call_sites", "langchain",
     re.compile(r"\b(ChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI|HuggingFaceHub|invoke|ainvoke)\s*\(")),
    ("llm_call_sites", "litellm",
     re.compile(r"\blitellm\.completion\b|\blitellm\.acompletion\b")),
    ("llm_call_sites", "ollama",
     re.compile(r"\bollama\.(chat|generate|Client)\b")),

    # ── Tool registry ─────────────────────────────────────────────
    ("tool_registry", "mcp-set-handler",
     re.compile(r"\.setRequestHandler\s*\(\s*CallToolRequestSchema")),
    ("tool_registry", "mcp-server-tool",
     re.compile(r"\b(McpServer|server)\.tool\s*\(")),
    ("tool_registry", "langchain-tool-decorator",
     re.compile(r"@(?:langchain\.)?tool\b|@tool\b")),
    ("tool_registry", "openai-function-tool",
     re.compile(r"@function_tool\b")),
    ("tool_registry", "autogen-register-function",
     re.compile(r"\bregister_function\s*\(")),
    ("tool_registry", "crewai-tools",
     re.compile(r"\bCrew\s*\([^)]*\btools\s*=")),

    # ── Memory stores ──────────────────────────────────────────────
    ("memory_stores", "langchain-memory",
     re.compile(r"\b(ConversationBufferMemory|ConversationSummaryMemory|VectorStoreRetrieverMemory|RedisChatMessageHistory)\b")),
    ("memory_stores", "save-context",
     re.compile(r"\bsave_context\s*\(")),
    ("memory_stores", "history-write",
     re.compile(r"\b(chat_memory|history|conversation_history)\.add_(user|ai|system)_message\b")),
    ("memory_stores", "vector-store",
     re.compile(r"\b(chromadb|pinecone|weaviate|qdrant|FAISS)\b", re.I)),

    # ── Sub-agent spawners ─────────────────────────────────────────
    ("sub_agent_spawners", "langchain-agent-executor",
     re.compile(r"\bAgentExecutor\s*\(|\bAgentExecutor\.from_agent_and_tools\b")),
    ("sub_agent_spawners", "crewai-crew",
     re.compile(r"\bCrew\s*\(")),
    ("sub_agent_spawners", "autogen-agent",
     re.compile(r"\b(AssistantAgent|UserProxyAgent|ConversableAgent|RetrieveAssistantAgent)\s*\(")),
    ("sub_agent_spawners", "openai-runner",
     re.compile(r"\bRunner\.run\s*\(")),
    ("sub_agent_spawners", "claude-agent-sdk",
     re.compile(r"\b(claude_agent_sdk|ClaudeSDKClient|create_agent)\b")),

    # ── Sandbox / container spawn ──────────────────────────────────
    ("sandbox_sites", "docker-spawn",
     re.compile(r"\bdocker\.(from_env|sock|run|create_container)\b|\b/var/run/docker\.sock\b")),
    ("sandbox_sites", "subprocess-shell",
     re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True")),
    ("sandbox_sites", "child_process-exec",
     re.compile(r"\bchild_process\.(?:exec|spawn|execSync|spawnSync)\b")),
    ("sandbox_sites", "vm-isolatedvm",
     re.compile(r"\bisolated-vm\b|\bnew\s+vm\.Script\b|\bvm\.runInContext\b")),
    ("sandbox_sites", "sandbox-config",
     re.compile(r"\bsandbox\s*[:=]\s*['\"](auto|none|off)['\"]")),

    # ── Approval gates ─────────────────────────────────────────────
    ("approval_gates", "explicit-approval",
     re.compile(r"\b(askBeforeRun|require_approval|requestApproval|strictInlineEval|execApprovals|approval_required)\b")),
    ("approval_gates", "human-input-mode",
     re.compile(r"\bhuman_input_mode\s*=\s*['\"](ALWAYS|TERMINATE|NEVER)['\"]")),
    ("approval_gates", "permission-mode",
     re.compile(r"\bpermission_mode\s*[:=]\s*['\"](auto|prompt|deny|allow)['\"]")),

    # ── Trust label string sites (Agent-Zero-DB G1) ────────────────
    ("trust_label_sites", "system-prefix",
     re.compile(r"['\"`]System:\s*\$|['\"`]System:\s*\{")),
    ("trust_label_sites", "media-prefix",
     re.compile(r"['\"`]MEDIA:\s*\$|['\"`]MEDIA:\s*\{")),
    ("trust_label_sites", "trusted-string",
     re.compile(r"['\"`]trusted['\"`]\s*:|trustLevel\s*[:=]")),
]

# Component-type roll-up (broad categories returned in components[]).
COMPONENT_FROM_CATEGORY = {
    "llm_call_sites":      "AgentRuntime",
    "tool_registry":       "ToolRegistry",
    "memory_stores":       "MemoryStore",
    "sub_agent_spawners":  "SubAgentSpawner",
    "sandbox_sites":       "Sandbox",
    "approval_gates":      "ApprovalLayer",
    "trust_label_sites":   "TrustLabelSurface",
}


def scan(root: Path) -> dict:
    out: dict[str, list[dict]] = {k: [] for k in COMPONENT_FROM_CATEGORY}
    component_hits: dict[str, int] = {v: 0 for v in COMPONENT_FROM_CATEGORY.values()}

    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(p in f.parts for p in SKIP_DIRS):
            continue
        if f.suffix not in SCAN_EXTS:
            continue
        try:
            lines = f.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        rel = str(f.relative_to(root))
        for lineno, line in enumerate(lines, 1):
            for category, label, pat in RULES:
                m = pat.search(line)
                if m:
                    out[category].append({
                        "file": rel,
                        "line": lineno,
                        "label": label,
                        "snippet": line.strip()[:160],
                    })
                    component_hits[COMPONENT_FROM_CATEGORY[category]] += 1
                    break

    components = [
        {"name": name, "count": count}
        for name, count in component_hits.items() if count > 0
    ]
    components.sort(key=lambda x: -x["count"])
    return {
        "components": components,
        **out,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Local repository path")
    parser.add_argument("--limit", type=int, default=200,
                        help="Cap each category at N hits to keep output small")
    args = parser.parse_args()
    result = scan(Path(args.path))
    for k in list(result):
        if k != "components" and isinstance(result[k], list):
            result[k] = result[k][:args.limit]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
