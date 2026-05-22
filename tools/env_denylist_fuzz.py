#!/usr/bin/env python3
"""Env-var denylist bypass fuzzer.

Port of the Agent-Zero-DB `env-denylist-fuzzer` concept. Given a target
repo, extract the denylist string set used to filter environment
variables, then emit a list of variant tokens that the denylist might
miss. The variant emission is deterministic and uses three operators:

  1. Case permutations (lower, upper, title)
  2. Surrounding-whitespace and underscore variants
  3. Unicode look-alikes for ASCII letters (Cyrillic А, Greek Ε, etc.)

Cross-references the **seed list** in
`skills/knowledge/openclaw-ghsa-seed.json :
env_denylist_known_bypass_seeds` to surface env vars that have been
empirically missed by similar denylists in the OpenClaw corpus.

Output JSON:
    extracted_denylist:    tokens read from the repo (best-effort grep)
    known_bypass_seeds:    seeds from the offline corpus
    variants:              candidate bypass tokens to evaluate against
                            the running allowlist check
    seed_misses:           seed entries NOT present in extracted_denylist
                            — i.e., the most likely live bypasses
"""
import argparse, json, re
from pathlib import Path

SEED_PATH = Path(__file__).resolve().parent.parent / "skills" / "knowledge" / "openclaw-ghsa-seed.json"

SKIP_DIRS = {".git", "node_modules", ".venv", "dist", "build", "__pycache__", "vendor"}
SCAN_EXTS = {".py", ".ts", ".js", ".tsx", ".jsx", ".mjs", ".json", ".yaml", ".yml", ".toml"}

# Detect denylist-shape declarations: array literals of UPPER_SNAKE_CASE strings.
DENYLIST_LIKE = re.compile(
    r"""(?ix)
    (?:denylist|blocklist|blacklist|blocked_envs|env_block|forbidden_envs|
       restrictedEnv|RESTRICTED_ENV|HOST_ENV_BLOCK)
    \s*[:=]\s*\[(?P<body>[^\]]*)\]
    """,
)
QUOTED_TOKEN = re.compile(r"""['"]([A-Z][A-Z0-9_]{2,})['"]""")

# Cyrillic / Greek look-alikes for common ASCII letters.
HOMOGLYPHS = {
    "A": ["А"],   # U+0410 Cyrillic
    "B": ["В"],   # U+0412
    "E": ["Е", "Ε"],
    "H": ["Н"],
    "I": ["І", "Ι"],
    "K": ["К"],
    "M": ["М"],
    "N": ["Ν"],
    "O": ["О", "Ο"],
    "P": ["Р"],
    "T": ["Т"],
    "X": ["Х"],
}


def extract_denylist(root: Path) -> list[str]:
    found: set[str] = set()
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(p in f.parts for p in SKIP_DIRS):
            continue
        if f.suffix not in SCAN_EXTS:
            continue
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        for m in DENYLIST_LIKE.finditer(text):
            for tok in QUOTED_TOKEN.findall(m.group("body")):
                found.add(tok)
    return sorted(found)


def load_seed() -> list[str]:
    if not SEED_PATH.exists():
        return []
    try:
        data = json.loads(SEED_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    return list(data.get("env_denylist_known_bypass_seeds", []))


def case_variants(tok: str) -> list[str]:
    out = {tok, tok.lower(), tok.upper(), tok.title()}
    if "_" in tok:
        out.add(tok.replace("_", ""))
        out.add(tok.replace("_", "-"))
    return sorted(out)


def whitespace_variants(tok: str) -> list[str]:
    return [
        tok + " ",
        " " + tok,
        tok + "\t",
        tok + "\n",
        tok.replace("_", " "),
    ]


def homoglyph_variants(tok: str, max_per_token: int = 6) -> list[str]:
    out: list[str] = []
    for i, ch in enumerate(tok):
        if ch in HOMOGLYPHS:
            for h in HOMOGLYPHS[ch]:
                out.append(tok[:i] + h + tok[i + 1:])
                if len(out) >= max_per_token:
                    return out
    return out


def fuzz(tokens: list[str]) -> list[dict]:
    variants = []
    for tok in tokens:
        variants.append({
            "base": tok,
            "case": case_variants(tok),
            "whitespace": whitespace_variants(tok),
            "homoglyph": homoglyph_variants(tok),
        })
    return variants


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", help="Local repository path")
    parser.add_argument("--max-tokens", type=int, default=50,
                        help="Cap how many denylist tokens to fuzz")
    args = parser.parse_args()

    extracted = extract_denylist(Path(args.path))
    seeds = load_seed()

    seed_misses = [s for s in seeds if s not in extracted]

    fuzz_input = sorted(set(extracted) | set(seed_misses))[: args.max_tokens]

    print(json.dumps({
        "path": args.path,
        "extracted_denylist": extracted,
        "extracted_count": len(extracted),
        "known_bypass_seeds": seeds,
        "seed_misses": seed_misses,
        "variants": fuzz(fuzz_input),
    }, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
