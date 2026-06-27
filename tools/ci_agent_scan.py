#!/usr/bin/env python3
"""Scan .github/workflows for AI-agent actions and attacker-controllable
GitHub event data reaching them. Data-collection only — emits JSON, no judgment.

Consumed by skills/03-taint/agentic-ci-injection.md (the LLM does the analysis).
"""
import argparse, json, re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "dist", "build", "__pycache__"}

# Known AI-agent CI actions (substring match on the `uses:` value).
KNOWN_AI_ACTIONS = [
    "anthropics/claude-code-action",
    "google-github-actions/run-gemini-cli",
    "google-gemini/gemini-cli-action",
    "openai/codex-action",
    "actions/ai-inference",
]
# Heuristic fallback — `uses:` value that *looks* like an agent action.
AI_HEURISTIC = re.compile(r"claude|gemini|codex|copilot|ai-inference|\bagent\b", re.I)

USES_RE = re.compile(r'^\s*-?\s*uses:\s*["\']?([^"\'\s]+)["\']?')
# Untrusted expression contexts (attacker-influenceable).
EXPR_RE = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")
UNTRUSTED_CTX = re.compile(r"github\.event|github\.head_ref|\binputs\.")
ENV_BLOCK_RE = re.compile(r'^(\s*)env:\s*$')
ENV_VAR_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$')
UNTRUSTED_EXPR = re.compile(r'\$\{\{[^}]*(?:github\.event|github\.head_ref|inputs\.)')
PERM_LINE_RE = re.compile(r'^\s*permissions:\s*(.*)$')
TRIGGERS = [
    "pull_request_target", "issue_comment", "issues", "pull_request",
    "workflow_dispatch", "workflow_run", "push", "schedule", "discussion",
    "discussion_comment", "fork", "watch",
]
TRIGGER_KEY_RE = {t: re.compile(rf'^\s*{re.escape(t)}\s*:') for t in TRIGGERS}
TRIGGER_LIST_RE = re.compile(r'^\s*on:\s*\[([^\]]+)\]')
# Inputs of interest captured from an AI action's `with:` block.
INPUT_KEYS = (
    "prompt", "args", "input", "instructions", "allowed_tools", "allowedtools",
    "allowed_users", "allowed_non_write_users", "sandbox", "safety", "model",
    "claude_args", "settings",
)
INPUT_RE = re.compile(
    r'^\s*(' + "|".join(re.escape(k) for k in INPUT_KEYS) + r')\s*:\s*(.*)$', re.I)
# Fail-open / over-permissive config tokens.
RISKY_TOKENS = [
    "danger-full-access", "--dangerously-skip-permissions", "--yolo",
    "Bash(*)", "Bash(:*)", "write-all", "permission-mode: bypass",
]


def _lineno(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def scan_workflow(text: str) -> dict:
    lines = text.splitlines()

    triggers = []
    for i, ln in enumerate(lines, 1):
        m = TRIGGER_LIST_RE.match(ln)
        if m:
            for t in m.group(1).split(","):
                t = t.strip().strip("'\"")
                if t in TRIGGERS:
                    triggers.append({"name": t, "line": i})
        for t, rx in TRIGGER_KEY_RE.items():
            if rx.match(ln):
                triggers.append({"name": t, "line": i})

    ai_actions = []
    for i, ln in enumerate(lines, 1):
        m = USES_RE.match(ln)
        if not m:
            continue
        uses = m.group(1)
        known = any(a in uses for a in KNOWN_AI_ACTIONS)
        if not (known or AI_HEURISTIC.search(uses)):
            continue
        inputs = {}
        # Capture key inputs from the following indented block (until dedent to
        # the `- uses:` level or a new list item).
        base_indent = len(ln) - len(ln.lstrip())
        for j in range(i, min(i + 40, len(lines))):
            nxt = lines[j]
            if not nxt.strip():
                continue
            ind = len(nxt) - len(nxt.lstrip())
            if j > i and ind <= base_indent and nxt.lstrip().startswith("-"):
                break
            im = INPUT_RE.match(nxt)
            if im:
                inputs.setdefault(im.group(1).lower(), {
                    "value": im.group(2).strip()[:200], "line": j + 1})
        ai_actions.append({
            "uses": uses, "line": i, "known": known, "inputs": inputs})

    event_expressions = []
    for i, ln in enumerate(lines, 1):
        for em in EXPR_RE.finditer(ln):
            inner = em.group(1).strip()
            if UNTRUSTED_CTX.search(inner):
                event_expressions.append(
                    {"expr": inner, "line": i, "text": ln.strip()[:160]})

    # Vector A: an env: block var whose value is an untrusted expression.
    # Block-aware so checkout/with inputs (ref:, prompt:) are not mislabeled.
    env_event_vars = []
    env_indent = None
    for i, ln in enumerate(lines, 1):
        bm = ENV_BLOCK_RE.match(ln)
        if bm:
            env_indent = len(bm.group(1))
            continue
        if env_indent is None:
            continue
        if ln.strip():
            ind = len(ln) - len(ln.lstrip())
            if ind <= env_indent:           # dedented out of the env: block
                env_indent = None
                bm = ENV_BLOCK_RE.match(ln)  # the dedent line may open a new env:
                if bm:
                    env_indent = len(bm.group(1))
                continue
            vm = ENV_VAR_RE.match(ln)
            if vm and UNTRUSTED_EXPR.search(ln):
                env_event_vars.append(
                    {"name": vm.group(1), "line": i, "text": ln.strip()[:160]})

    permissions = [
        {"line": i, "text": ln.strip()[:160]}
        for i, ln in enumerate(lines, 1) if PERM_LINE_RE.match(ln)
    ]

    risky_config = []
    for i, ln in enumerate(lines, 1):
        low = ln.lower()
        for tok in RISKY_TOKENS:
            if tok.lower() in low:
                risky_config.append({"token": tok, "line": i, "text": ln.strip()[:160]})
        # allowed_users / allowed*: "*"
        if re.search(r'allowed_\w*users?\s*:\s*["\']?\*', ln, re.I):
            risky_config.append({"token": "wildcard-allowed-users", "line": i, "text": ln.strip()[:160]})

    return {
        "triggers": triggers,
        "ai_actions": ai_actions,
        "event_expressions": event_expressions,
        "env_event_vars": env_event_vars,
        "permissions": permissions,
        "risky_config": risky_config,
    }


def scan(root: Path) -> list[dict]:
    out = []
    for f in root.rglob("*"):
        if not f.is_file() or f.suffix not in {".yml", ".yaml"}:
            continue
        if any(p in f.parts for p in SKIP_DIRS):
            continue
        parts = f.parts
        if not (".github" in parts and "workflows" in parts):
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        data = scan_workflow(text)
        # Only emit workflows that actually wire an AI action.
        if not data["ai_actions"]:
            continue
        data["file"] = str(f.relative_to(root))
        out.append(data)
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Local repository path")
    args = parser.parse_args()
    workflows = scan(Path(args.path))
    print(json.dumps({"workflow_count": len(workflows), "workflows": workflows}, indent=2))


if __name__ == "__main__":
    main()
