#!/usr/bin/env python3
"""Build a per-file trust DAG.

Each *node* is an assignment site (file:line + variable name).
Each *edge* approximates a trust-layer transition:

    layer 1 SYSTEM     — operator-controlled, hardcoded
    layer 2 DEVELOPER  — server-side configured strings
    layer 3 USER       — user-supplied (request, stdin, CLI args)
    layer 4 TOOL       — tool-result, external API, file content

A node is tagged with the layer where its right-hand side originates. An
edge from layer N to a higher trust layer M (M < N numerically) is a
*promotion* — these are the high-signal lines for Phase 3 review.

The implementation is regex-based (per the project convention of grep-only
tooling). It will under- and over-approximate; treat the output as a triage
shortlist, not a verdict.

Output schema:
    nodes:   [{file, line, var, layer, snippet}]
    edges:   [{from_node, to_node, from_layer, to_layer, kind}]
    summary: {nodes_per_layer, promotions: count}
"""
import argparse, json, re
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "dist", "build", "__pycache__", "vendor", "target"}
SCAN_EXTS = {".py", ".ts", ".js", ".tsx", ".jsx", ".mjs", ".rs"}

# Higher trust = lower number. Promotion = bigger -> smaller.
LAYER_RANK = {"SYSTEM": 1, "DEVELOPER": 2, "USER": 3, "TOOL": 4, "UNKNOWN": 9}

# (layer, regex) — applied in order. First-match wins for an RHS.
LAYER_SOURCES: list[tuple[str, re.Pattern]] = [
    # SYSTEM — literal strings hardcoded in module
    ("SYSTEM", re.compile(r'^=\s*[fr]?["\']{1,3}.*["\']{1,3}\s*$')),

    # USER inputs (request/stdin/cli/env)
    ("USER", re.compile(r"\b(request\.|req\.|ctx\.request|event\.body|input\(\)|sys\.argv|process\.argv|formData|FormData|searchParams)")),
    ("USER", re.compile(r"\b(os\.environ|process\.env)\b")),
    # Rust: env vars, CLI args
    ("USER", re.compile(r"\b(?:std::)?env::(?:var|var_os|args|args_os)\s*\(|\bArgs::parse\s*\(")),

    # TOOL — tool results, external content, file reads, HTTP fetches
    ("TOOL", re.compile(r"\b(tool_result|tool_output|toolResult|tool\.run|run_tool|invoke_tool)\b")),
    ("TOOL", re.compile(r"\b(await\s+)?fetch\s*\(")),
    ("TOOL", re.compile(r"\b(requests|httpx|aiohttp)\.(get|post|put|patch|delete)\b")),
    ("TOOL", re.compile(r"\.(read_text|readFile|readFileSync|read_bytes)\s*\(")),
    ("TOOL", re.compile(r"\b(subprocess\.run|subprocess\.check_output|child_process\.exec|os\.popen)\b")),
    # Rust: reqwest, std::fs reads, Command output
    ("TOOL", re.compile(r"\breqwest::(?:get|Client)\b|\bfs::read(?:_to_string)?\s*\(|\.output\s*\(\s*\)|\.send\s*\(\s*\)\s*\.await")),

    # DEVELOPER — config / settings / config files
    ("DEVELOPER", re.compile(r"\b(config|settings|CONFIG|SETTINGS)\.[a-zA-Z_][\w]*")),
    ("DEVELOPER", re.compile(r"\b(load_yaml|load_json|yaml\.safe_load|json\.load)\b")),
]

# Names whose presence in the LHS suggests this assignment is *destined* for a higher trust layer.
LHS_TO_LAYER: list[tuple[re.Pattern, str]] = [
    # System-prompt destination
    (re.compile(r"\b(system_prompt|SYSTEM_PROMPT|systemPrompt|systemMessage)\b"), "SYSTEM"),
    (re.compile(r"messages\[0\]\s*=|messages\[0\]\.content\s*="), "SYSTEM"),
    (re.compile(r'role\s*=\s*["\']system["\']'), "SYSTEM"),

    # Developer-layer destinations
    (re.compile(r"\b(DEVELOPER_PROMPT|developer_message|tool_description|tool_desc)\b"), "DEVELOPER"),
]

# Simple Python/TS assignment pattern: `name = expr` (single-line).
ASSIGN_PY = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$")
ASSIGN_TS = re.compile(r"^(\s*)(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+?);?\s*$")
# Rust: `let [mut] name[: Type] = expr;`
ASSIGN_RS = re.compile(r"^(\s*)let\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^=]+)?=\s*(.+?);?\s*$")


def classify_rhs(rhs: str) -> str:
    for layer, pat in LAYER_SOURCES:
        if pat.search(rhs):
            return layer
    return "UNKNOWN"


def classify_lhs_destination(line: str) -> str | None:
    for pat, layer in LHS_TO_LAYER:
        if pat.search(line):
            return layer
    return None


IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")

# ── Tool-arg → sink edges ──────────────────────────────────────────────
# The layer model above only sees assignment-based promotions. The most common
# agent RCE — an untrusted tool-handler argument reaching a dangerous sink — has
# no assignment chain, so it was invisible. These patterns add it as an explicit
# `tool-arg-to-sink` edge (from_layer USER → a sink), the capability-graph seed
# Phase 3-C chaining needs.
SINK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("arbitrary-write", re.compile(r"\bfs\.(?:writeFileSync|writeFile|appendFileSync|appendFile)\s*\(|\.write_text\s*\(|\.write_bytes\s*\(|\bopen\s*\([^)]*['\"][wa]|\bfs::write\s*\(|\bFile::create\s*\(")),
    ("path-control",    re.compile(r"\bpath\.(?:resolve|join)\s*\(|\bos\.path\.join\s*\(|\bPath(?:Buf)?::(?:from|new)\s*\(")),
    ("exec-primitive",  re.compile(r"\bchild_process\.(?:exec|spawn|execSync|spawnSync)\b|\bsubprocess\.(?:run|Popen|call|check_output)\s*\(|\bos\.system\s*\(|\beval\s*\(|\bexecFile\s*\(|\bCommand::new\s*\(")),
    ("deser-sink",      re.compile(r"\bpickle\.loads?\s*\(|\byaml\.load\s*\(")),
]
# Tool-handler param lists (USER/TOOL-tier, attacker-influenced). [\s\S] spans
# the gap between the registration call and the handler's argument list.
HANDLER_PARAMS: list[re.Pattern] = [
    re.compile(r"(?:server|mcpServer|McpServer)\.tool\s*\([\s\S]{0,400}?async\s*\(\s*\{([^}]*)\}\s*\)"),
    re.compile(r"(?:server|mcpServer|McpServer)\.tool\s*\([\s\S]{0,400}?async\s*\(\s*([A-Za-z_$][\w$]*)\s*\)"),
    re.compile(r"\.setRequestHandler\s*\([\s\S]{0,200}?async\s*\(\s*([A-Za-z_$][\w$]*)"),
    re.compile(r"@(?:langchain\.)?tool\b[\s\S]{0,80}?def\s+\w+\s*\(([^)]*)\)"),
    re.compile(r"@function_tool\b[\s\S]{0,80}?def\s+\w+\s*\(([^)]*)\)"),
    # Rust rmcp: `#[tool] ... [async] fn name(&self, params: T) ...`
    re.compile(r"#\[tool(?:\([^)]*\))?\s*\][\s\S]{0,160}?fn\s+\w+\s*\(([^)]*)\)"),
]


def _param_idents(group: str) -> list[str]:
    out: list[str] = []
    for part in group.split(","):
        p = re.split(r"[:=]", part.strip())[0].strip().replace("...", "").strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", p) and p not in {"this", "self"}:
            out.append(p)
    return out


def tool_arg_sink_edges(text: str, rel: str) -> tuple[list[dict], list[dict]]:
    """Edges from tool-handler args (USER tier) to dangerous sinks in the same file."""
    params: dict[str, int] = {}
    for pat in HANDLER_PARAMS:
        for m in pat.finditer(text):
            hline = text.count("\n", 0, m.start()) + 1
            for ident in _param_idents(m.group(1)):
                params.setdefault(ident, hline)
    nodes: list[dict] = []
    edges: list[dict] = []
    if not params:
        return nodes, edges
    for primitive, spat in SINK_PATTERNS:
        for m in spat.finditer(text):
            sline = text.count("\n", 0, m.start()) + 1
            ls = text.rfind("\n", 0, m.start()) + 1
            le = text.find("\n", m.start())
            line_text = text[ls: le if le != -1 else len(text)].strip()
            hit = [p for p in params if re.search(r"\b" + re.escape(p) + r"\b", line_text)]
            if not hit:
                continue
            nodes.append({"file": rel, "line": sline, "var": "+".join(hit),
                          "layer": "USER", "snippet": line_text[:160]})
            for p in hit:
                edges.append({
                    "from_node": {"file": rel, "line": params[p], "var": p},
                    "to_node": {"file": rel, "line": sline, "sink": line_text[:160]},
                    "from_layer": "USER", "to_layer": "SINK",
                    "kind": "tool-arg-to-sink", "primitive": primitive,
                })
    return nodes, edges


def scan(root: Path) -> dict:
    nodes: list[dict] = []
    edges: list[dict] = []
    # Per-file var → highest-untrust layer seen so far in that file.
    # Lower trust = larger numeric rank.
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(p in f.parts for p in SKIP_DIRS):
            continue
        if f.suffix not in SCAN_EXTS:
            continue
        try:
            raw_text = f.read_text(errors="ignore")
        except OSError:
            continue
        lines = raw_text.splitlines()
        is_ts = f.suffix in {".ts", ".tsx", ".js", ".jsx", ".mjs"}
        is_rs = f.suffix == ".rs"
        rel = str(f.relative_to(root))
        var_layer: dict[str, tuple[str, int]] = {}  # var → (layer, lineno)
        file_nodes: list[dict] = []
        for lineno, raw in enumerate(lines, 1):
            line = raw.rstrip()
            if is_rs:
                assign = ASSIGN_RS.match(line)
            elif is_ts:
                assign = ASSIGN_TS.match(line)
            else:
                assign = ASSIGN_PY.match(line)
            if not assign:
                continue
            _, var, rhs = assign.groups()
            rhs_layer = classify_rhs(rhs)
            # Propagate layer through identifier reference: if any identifier on the
            # RHS is already mapped to a lower-trust layer, inherit the worst.
            referenced = set(IDENT.findall(rhs)) - {var}
            inherited: str | None = None
            for r in referenced:
                if r in var_layer:
                    candidate = var_layer[r][0]
                    if inherited is None or LAYER_RANK[candidate] > LAYER_RANK[inherited]:
                        inherited = candidate
            # Final layer = whichever is lower-trust (higher rank, ignoring UNKNOWN).
            final_layer = rhs_layer
            if inherited is not None and (final_layer == "UNKNOWN" or LAYER_RANK[inherited] > LAYER_RANK[final_layer]):
                final_layer = inherited
            if final_layer == "UNKNOWN":
                continue
            node = {
                "file": rel,
                "line": lineno,
                "var": var,
                "layer": final_layer,
                "snippet": line.strip()[:160],
            }
            file_nodes.append(node)
            var_layer[var] = (final_layer, lineno)
            dst_layer = classify_lhs_destination(line)
            if dst_layer is not None and LAYER_RANK[dst_layer] < LAYER_RANK[final_layer]:
                edges.append({
                    "from_node": {"file": rel, "line": lineno, "var": var},
                    "to_node":   {"file": rel, "line": lineno, "var": var, "destination": dst_layer},
                    "from_layer": final_layer,
                    "to_layer": dst_layer,
                    "kind": "promotion",
                })
        nodes.extend(file_nodes)

        # Tool-arg → sink edges (the boundary the layer model can't see).
        ta_nodes, ta_edges = tool_arg_sink_edges(raw_text, rel)
        nodes.extend(ta_nodes)
        edges.extend(ta_edges)

    by_layer: dict[str, int] = {}
    for n in nodes:
        by_layer[n["layer"]] = by_layer.get(n["layer"], 0) + 1
    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "nodes_per_layer": by_layer,
            "promotions": sum(1 for e in edges if e.get("kind") == "promotion"),
            "tool_arg_to_sink": sum(1 for e in edges if e.get("kind") == "tool-arg-to-sink"),
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Local repository path")
    parser.add_argument("--limit", type=int, default=500,
                        help="Cap nodes/edges to keep output bounded")
    args = parser.parse_args()
    result = scan(Path(args.path))
    result["nodes"] = result["nodes"][:args.limit]
    result["edges"] = result["edges"][:args.limit]
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
