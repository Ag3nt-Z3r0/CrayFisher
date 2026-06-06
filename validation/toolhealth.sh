#!/usr/bin/env bash
# G-TOOLHEALTH probe (validation plan §2).
# semgrep_run.py discards returncode/stderr and returns [] on JSONDecodeError,
# so an empty result THROUGH that tool is ambiguous. This probe invokes the RAW
# semgrep binary directly to disambiguate a genuine zero-finding scan (CLEAN)
# from a crash/OOM/non-JSON artifact (INCONCLUSIVE).
#
# Usage: toolhealth.sh <scoped_path> <out_json> <err_txt>
# Prints: CLEAN | FINDINGS | INCONCLUSIVE   (and exits 0/0/2)
set -u
SCOPED="${1:?scoped path}"; OUT="${2:?out json}"; ERR="${3:?err txt}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SG="$REPO_ROOT/.venv/bin/semgrep"; [ -x "$SG" ] || SG="semgrep"

# Bounds (plan §4): hard 20-min wall-clock cap; semgrep's own --max-memory (MB)
# is the correct memory bound (ulimit -v breaks semgrep, which maps a large
# virtual address space). --quiet keeps stderr empty on a clean run so a
# non-empty stderr genuinely signals a problem.
timeout 1200 "$SG" scan --json --quiet --no-rewrite-rule-ids --max-memory 4000 \
    --config "$REPO_ROOT/rules/semgrep" "$SCOPED" >"$OUT" 2>"$ERR"
rc=$?

if [ "$rc" -ne 0 ] || [ -s "$ERR" ]; then
  echo "INCONCLUSIVE"; exit 2
fi
# Valid JSON?
if ! "$REPO_ROOT/.venv/bin/python" -c "import json,sys;d=json.load(open(sys.argv[1]));sys.exit(0 if 'results' in d else 3)" "$OUT" 2>/dev/null; then
  echo "INCONCLUSIVE"; exit 2
fi
# results == [] ?  -> CLEAN ; else FINDINGS
n=$("$REPO_ROOT/.venv/bin/python" -c "import json,sys;print(len(json.load(open(sys.argv[1]))['results']))" "$OUT")
if [ "$n" -eq 0 ]; then echo "CLEAN"; else echo "FINDINGS"; fi
exit 0
