# Skill 01-A: Repository Profiling

## Purpose

Clone the target and capture the tech stack / dependencies / size needed
for attack-surface analysis.

## Input

- `TARGET_URL`: GitHub URL to analyze.

## Steps

### Step 1 — Clone

```bash
python tools/clone.py <TARGET_URL>
```

Extract `local_path` from the result. Use this path in every later step.

### Step 2 — Stack detection

```bash
python tools/detect_stack.py <local_path>
```

### Step 3 — Read the JSON output

Capture these fields:

| Field | Meaning |
|---|---|
| `primary_language` | Picks the main analysis language |
| `frameworks` | Selects framework-specific vuln patterns |
| `is_agent_target` | Flips the entire pipeline into Agent-first mode |
| `agent_frameworks` | Which agent frameworks were detected |
| `dependency_files` | Top packages → feed into `tools/osv_lookup.py` |
| `total_lines` | Over 100k → narrow file scope |

### Step 3.5 — Agent-target detour *(only when `is_agent_target == true`)*

```bash
python tools/architecture_map.py <local_path>
python tools/agent_trust_graph.py <local_path>
python tools/ghsa_lookup.py <main_package>
```

Capture:

- `architecture_map.components[]` and per-category counts
- `agent_trust_graph.summary.promotions` — promotion edges are
  immediate Phase 3 candidates
- `ghsa_lookup.seed_hits` — prior advisories on this package or the
  Agent-Zero-DB corpus

Emit an `agent_architecture` block in the profile output.

### Step 4 — OSV scan of top packages (up to 5)

Extract the main packages from `dependency_files`. Query each:

```bash
python tools/osv_lookup.py <package_name> <ecosystem>
# ecosystem: npm | PyPI | Go | Maven | RubyGems | crates.io
```

### Step 5 — Recent-history scan *(agent target only)*

```bash
python tools/incomplete_fix_scan.py <local_path>
```

Capture `candidates[]` — these become Phase 3 priority reads.

## Output

```
## Repo Profile: <repo>

- URL: <url>
- Primary Language: <language>
- Frameworks: <list>
- Total Files / Lines: <N> / <N>
- is_agent_target: true|false
- agent_frameworks: <list>
- Top dependency CVEs: <id + summary>
- (agent target only) Architecture components: <component-name × count>
- (agent target only) Trust-graph promotions: <count>
- (agent target only) GHSA seed hits: <ids>
- (agent target only) Incomplete-fix candidates: <count>
- Next steps: [01-B, 02-A, 03-B if agent target else 03-A, ...]
```
