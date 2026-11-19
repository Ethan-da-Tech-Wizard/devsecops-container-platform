#!/usr/bin/env python3
# ==============================================================================
# Program: twu_yara_vet.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Cryptographic YARA rule vetting and verification engine. Audits rule
#          definitions offline, enforces fail-closed static gating, and compiles
#          tamper-evident SHA-256 manifests with atomic file replacement.
# ==============================================================================

# Defer annotation evaluation so `str | None` style hints work on older Pythons
# (3.8/3.9) that would otherwise fail to evaluate them at definition time.
from __future__ import annotations
# Stdlib only by design: this tool vets security rules, so it must run offline
# and must not itself pull in third-party code.
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Workspace directory resolution
# ROOT is the repository root (scripts/ lives one level below it). Resolving first
# makes the result independent of the caller's working directory and of symlinks.
ROOT = Path(__file__).resolve().parent.parent
# Default location of the vetted rule tree: vendor/ copies, index.yar and MANIFEST.json.
RULES = ROOT / "data" / "yara_rules"

# Security whitelist: Audited native YARA modules permitted in rule definitions.
# Any import outside this set causes immediate rule rejection (e.g. 'import "cuckoo"').
ALLOWED_MODULES = {"pe", "elf", "math", "hash", "dotnet", "macho"}

# Linear regular expressions for static rule inspection (ReDoS-safe)
# IMPORT_RE: captures the module name of each `import "name"` line (line-anchored, multiline).
IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)"', re.M)
# RULE_RE: group 1 = zero or more `private`/`global` modifiers, group 2 = rule identifier.
# Modifiers are captured so static_check can reject `global` rules.
RULE_RE = re.compile(r'^\s*((?:(?:private|global)\s+)*)rule\s+([A-Za-z_]\w*)', re.M)
# INCLUDE_RE: detects any `include "..."` directive at line start.
INCLUDE_RE = re.compile(r'^\s*include\s+"', re.M)


# Step 1: Safely resolve executable binary paths in PATH or ~/.local/bin
def which_local(cmd: str) -> str | None:
    """Locate an executable binary in the system PATH or the local user bin directory.
    
    Checks standard system PATH first, then falls back to ~/.local/bin/ if executable.
    
    Args:
        cmd: Binary name (e.g. 'yara', 'yarac').
        
    Returns:
        Absolute string path to binary if found and executable, otherwise None.
    """
    # 1. Search system PATH directories
    # shutil.which honours PATH and the executable bit, so no manual scanning is needed.
    p = shutil.which(cmd)
    if p:
        return p
    # 2. Check local user environment fallback (~/.local/bin)
    c = Path.home() / ".local" / "bin" / cmd
    return str(c) if c.is_file() and os.access(str(c), os.X_OK) else None


def sha256(path: Path | str) -> str:
    """Computes the cryptographic SHA-256 digest of a target file using 1MB chunked streaming.
    
    Args:
        path: Path to target file.
        
    Returns:
        64-character lowercase hexadecimal SHA-256 hash string.
        
    Attack Vector Prevented:
        Memory exhaustion when hashing large binary files; streaming 1MB buffers preserves low memory footprint.
    """
    # Incremental hasher: fed chunk by chunk so the whole file is never held in RAM.
    h = hashlib.sha256()
    with open(str(path), "rb") as f:
        # Read file in 1 MiB (1,048,576 bytes) chunks to prevent memory spikes
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def strip_comments(text: str) -> str:
    """Strips C-style multi-line (/* ... */) and C++ single-line (// ...) comments from YARA source.
    
    Args:
        text: Raw YARA rule source text.
        
    Returns:
        Sanitized source text with comments excised, preventing commented directives from triggering parser logic.
    """
    # Strip multi-line block comments /* ... */
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    # Strip single-line comments // ...
    return re.sub(r"//[^\n]*", "", text)


def static_check(text: str) -> tuple[list[str], str | None]:
    """Performs static syntax and security boundary checking on raw YARA rule text.
    
    Verifies that:
      - All imported modules exist within ALLOWED_MODULES.
      - No `include` directives are present (rules must be self-contained).
      - No `global` rule modifiers are present (prevents cross-rule poisoning).
      - At least one valid rule declaration is found.
      
    Args:
        text: Raw rule file content.
        
    Returns:
        Tuple of (list_of_rule_names, rejection_reason_or_None).
    """
    # Work on comment-free text so directives hidden in comments neither trigger
    # false rejections nor smuggle anything past the checks.
    bare = strip_comments(text)
    
    # 1. Validate module imports against security whitelist
    for m in IMPORT_RE.findall(bare):
        if m not in ALLOWED_MODULES:
            return [], f"uses disabled module '{m}'"
            
    # 2. Reject include statements to enforce hermetic self-containment
    if INCLUDE_RE.search(bare):
        return [], "uses include (must be self-contained)"
        
    # 3. Extract rule declarations and reject global modifiers
    # Collected rule names; also used later by build() to detect duplicate identifiers across files.
    names = []
    for mods, name in RULE_RE.findall(bare):
        if "global" in mods:
            return [], f"declares global rule {name}"
        names.append(name)
        
    # 4. Ensure file actually defines at least one valid rule
    if not names:
        return [], "no rules found"
        
    return names, None


def compile_check(yarac: str, path: Path | str) -> str | None:
    """Executes yarac compiler in an isolated temporary directory to verify rule syntax and compilation.
    
    Args:
        yarac: Path to yarac compiler binary.
        path: Path to target YARA rule file.
        
    Returns:
        None if compilation succeeds; error message string if compilation fails.
    """
    # yarac needs an output path; a throwaway directory keeps the compiled artefact
    # out of the repo and is removed automatically even if compilation fails.
    with tempfile.TemporaryDirectory() as td:
        try:
            # Execute yarac in isolated scratch directory with a 120-second timeout guard
            r = subprocess.run(
                [yarac, str(path), os.path.join(td, "out.yarc")],
                capture_output=True,
                text=True,
                timeout=120
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            return f"yarac did not run: {e}"
            
        if r.returncode != 0:
            # yarac reports the decisive error on the last output line; fall back to a generic text if it printed nothing.
            msg = ((r.stderr or r.stdout).strip().splitlines() or ["compile error"])[-1]
            # Rules that depend on externally supplied variables cannot compile standalone;
            # label them distinctly so reviewers can tell them from genuine syntax errors.
            if "undefined identifier" in msg or "external" in msg:
                return "needs external variable or undefined identifier: " + msg[-160:]
            return "does not compile: " + msg[-160:]
    return None


def combined_ok(yarac: str, index: Path | str) -> str | None:
    """Validates that the combined index file containing all included rules compiles without conflicts."""
    return compile_check(yarac, index)


def write_index(rules_dir: Path, files: list[str]) -> None:
    """Writes the master index.yar file with sorted, deterministic include statements."""
    # Header marks the file as generated. Output is sorted below so rebuilds are byte-for-byte reproducible.
    lines = ["// generated by scripts/twu_yara_vet.py; do not edit. One include per vetted file.\n"]
    for rel in sorted(files):
        lines.append(f'include "{rel}"\n')
    (rules_dir / "index.yar").write_text("".join(lines), encoding="utf-8")


def write_atomic(path: Path | str, doc: dict) -> None:
    """Writes a JSON document to disk atomically to prevent corruption or incomplete reads.
    
    Writes output to a temporary file on the exact same filesystem, then performs an
    atomic rename (`os.replace`) to overwrite the destination path.
    
    Attack Vector Prevented:
        Race conditions, torn reads, and partially written corrupted manifest files.
    """
    path = Path(path)
    # The temp file must be in the destination directory: os.replace is only atomic within one filesystem.
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        # sort_keys + fixed indent give a stable, diff-friendly manifest.
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    os.replace(tmp, str(path))


def parse_src(spec: str) -> tuple[str, Path, str, str, str]:
    """Parses a source specification string of format ID=DIR@COMMIT|LICENSE|URL."""
    # Split on the first '=' only; the URL part may itself contain '='.
    idpart, rest = spec.split("=", 1)
    # Normalise the first '@' (DIR@COMMIT) to '|' so one split yields DIR, COMMIT, LICENSE, URL;
    # maxsplit=3 keeps any '|' inside the URL intact.
    d, commit, lic, url = rest.replace("@", "|", 1).split("|", 3)
    return idpart, Path(d), commit, lic, url


def build(srcs: list, rules_dir: Path = RULES, yarac: str | None = None,
          include_dirs: dict | None = None, now: float | None = None) -> dict:
    """Builds and vets the complete YARA rule set from pinned external source checkouts.
    
    Iterates over source files, applies static security checks, executes `yarac` compilation checks,
    detects duplicate rule identifiers, records vendor licenses, generates index.yar, and writes
    the cryptographic MANIFEST.json.
    
    Returns:
        Dictionary representing the generated manifest metadata.
    """
    # Fail closed: refuse to build rules that cannot be compiled-checked.
    # (Second occurrence in verify() is soft: verification just skips the compile step.)
    yarac = yarac or which_local("yarac")
    if not yarac:
        raise SystemExit("yarac not found")
    rules_dir = Path(rules_dir)
    # taken maps rule name -> vendored file that first claimed it (duplicate detection).
    taken: dict[str, str] = {}
    # Per-file records written into MANIFEST.json (accepted) or its audit trail (rejected).
    accepted: list[dict] = []
    rejected: list[dict] = []
    sources: list[dict] = []
    # Rebuild from scratch: wipe stale vendored files so removed upstream rules do not linger.
    vendor = rules_dir / "vendor"
    if vendor.exists():
        shutil.rmtree(str(vendor))
        
    for sid, d, commit, lic, url in srcs:
        # Provenance record for this upstream source (pinned commit + license), with running counters.
        entry = {"id": sid, "url": url, "commit": commit, "license": lic, "files": 0, "rejected": 0}
        for sub in (include_dirs or {}).get(sid) or ["."]:
            base = d / sub
            for p in sorted(base.rglob("*")):
                # Only real rule files; upstream 'deprecated' directories are skipped on purpose.
                if p.suffix not in (".yar", ".yara") or not p.is_file() or "deprecated" in p.parts:
                    continue
                rel_src = str(p.relative_to(d))
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                # Gate order: static policy -> duplicate names -> real compile. `why` holds the first rejection reason.
                names, why = static_check(text)
                if not why:
                    dup = [n for n in names if n in taken]
                    if dup:
                        why = f"duplicate rule name {dup[0]} already in {taken[dup[0]]}"
                if not why:
                    why = compile_check(yarac, p)
                if why:
                    rejected.append({"source": sid, "file": rel_src, "reason": why})
                    entry["rejected"] += 1
                    continue
                # Accepted files are copied under vendor/<source-id>/ preserving upstream relative paths.
                dest_rel = f"vendor/{sid}/{rel_src}"
                dest = rules_dir / dest_rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(str(p), str(dest))
                for n in names:
                    taken[n] = dest_rel
                accepted.append({
                    "path": dest_rel,
                    "sha256": sha256(dest),
                    "source": sid,
                    "source_path": rel_src,
                    "rules": len(names)
                })
                entry["files"] += 1
        # Ship the upstream license text alongside its rules and record its hash for attribution/tamper evidence.
        lic_src = d / "LICENSE"
        if lic_src.is_file():
            (rules_dir / "vendor" / sid).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(lic_src), str(rules_dir / "vendor" / sid / "LICENSE"))
            entry["license_file_sha256"] = sha256(rules_dir / "vendor" / sid / "LICENSE")
        sources.append(entry)
        
    # Regenerate the combined index, then prove the whole set compiles together.
    write_index(rules_dir, [a["path"] for a in accepted])
    why = combined_ok(yarac, rules_dir / "index.yar")
    # MANIFEST.json payload. `now` is injectable so tests can build deterministic manifests.
    doc = {
        "version": 1,
        "built": time.strftime("%Y-%m-%d", time.gmtime(now or time.time())),
        "built_epoch": int(now or time.time()),
        "note": "Pinned, vetted YARA rules. Refresh = re-run build from a new pinned commit; see README.md.",
        "sources": sources,
        "files": accepted,
        "rejected": rejected,
        "rule_count": sum(a["rules"] for a in accepted),
        "combined_compile": why or "ok"
    }
    write_atomic(rules_dir / "MANIFEST.json", doc)
    return doc


def verify(rules_dir: Path = RULES, yarac: str | None = None, compile_index: bool = True) -> list[str]:
    """Cryptographically verifies the vetted YARA rules against MANIFEST.json and tests compilation.
    
    Checks that:
      - MANIFEST.json exists and is valid JSON.
      - Every file referenced in the manifest exists on disk.
      - Every file's SHA-256 hash matches the cryptographic hash recorded in the manifest.
      - index.yar references exactly the files registered in the manifest.
      - Combined index.yar compiles cleanly using yarac.
      
    Returns:
        List of identified verification problems (empty list indicates 100% verified status).
    """
    rules_dir = Path(rules_dir)
    # Accumulates every problem found rather than stopping at the first, so one run reports everything.
    probs = []
    try:
        man = json.loads((rules_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [f"MANIFEST.json unreadable: {e}"]
        
    # Verify presence and cryptographic SHA-256 integrity for every file
    for f in man.get("files", []):
        p = rules_dir / f["path"]
        if not p.is_file():
            probs.append(f"missing {f['path']}")
        elif sha256(p) != f["sha256"]:
            probs.append(f"sha256 mismatch {f['path']}")
            
    # Verify index.yar matches manifest files exactly
    idx = rules_dir / "index.yar"
    want = set(f'include "{f["path"]}"' for f in man.get("files", []))
    have = set(l.strip() for l in idx.read_text(encoding="utf-8").splitlines() if l.startswith("include")) if idx.is_file() else set()
    if want != have:
        probs.append("index.yar does not match MANIFEST")
        
    # Verify combined compilation
    yarac = yarac or which_local("yarac")
    if compile_index and yarac and not probs:
        why = compile_check(yarac, idx)
        if why:
            probs.append(f"index.yar {why}")
            
    return probs


def fptest(corpus: list[str], rules_dir: Path = RULES, yara: str | None = None,
           exclusions: tuple = (), timeout: int = 1800) -> dict:
    """Scans a corpus of known-clean files using index.yar to detect false-positive rule triggers.
    
    Links files into an isolated temporary directory so rules compile once; no files are executed.
    """
    yara = yara or which_local("yara")
    # hits maps rule name -> list of clean files it wrongly matched (false positives).
    hits: dict[str, list[str]] = {}
    with tempfile.TemporaryDirectory() as td:
        names = {}
        for i, p in enumerate(corpus):
            # Neutral synthetic names: avoids odd characters/spaces in real paths and keeps yara output parseable;
            # names{} maps them back to the real path afterwards.
            n = f"f{i:07d}"
            try:
                # Symlinks avoid copying a potentially huge corpus; yara -r follows them to scan the real content.
                os.symlink(p, os.path.join(td, n))
            except OSError:
                continue
            names[n] = p
        # Single recursive yara run over all links so the rule set is compiled only once.
        r = subprocess.run(
            [yara, "-r", str(Path(rules_dir) / "index.yar"), td],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        for line in r.stdout.splitlines():
            parts = line.split(" ", 1)
            if len(parts) != 2:
                continue
            # yara prints `<rule> <path>` per match.
            rule, path = parts
            # Rules already documented in EXCLUSIONS.json are known/accepted and ignored here.
            if rule in exclusions:
                continue
            hits.setdefault(rule, []).append(names.get(os.path.basename(path), path))
    return hits


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for twu_yara_vet. Parses commands and runs actions."""
    ap = argparse.ArgumentParser(
        description="Cryptographic YARA Rule Vetting & Verification Engine (twu_yara_vet)"
    )
    # A subcommand is mandatory: build, fptest or verify.
    sub = ap.add_subparsers(dest="cmd", required=True)
    
    # Subcommand: build
    b = sub.add_parser("build", help="Build and vet rules from pinned checkouts")
    b.add_argument("--src", action="append", required=True, help="ID=DIR@COMMIT|LICENSE|URL")
    b.add_argument("--only", action="append", default=[], help="ID=subdir to limit source scope")
    
    # Subcommand: fptest
    f = sub.add_parser("fptest", help="Test false-positives against a corpus of known-clean files")
    f.add_argument("--corpus-file", required=True, help="Path to text file containing filepaths to scan")
    
    # Subcommand: verify
    sub.add_parser("verify", help="Cryptographically verify MANIFEST sha256 checksums and compile index.yar")
    
    a = ap.parse_args(argv)
    
    if a.cmd == "build":
        # Convert repeated --only ID=subdir flags into {id: [subdirs]} for build().
        inc: dict[str, list[str]] = {}
        for o in a.only:
            k, v = o.split("=", 1)
            inc.setdefault(k, []).append(v)
        doc = build([parse_src(s) for s in a.src], include_dirs=inc)
        print(f"accepted {len(doc['files'])} files, {doc['rule_count']} rules; "
              f"rejected {len(doc['rejected'])}; combined compile: {doc['combined_compile']}")
        return 0
        
    if a.cmd == "verify":
        probs = verify()
        print("OK" if not probs else "\n".join(probs))
        return 1 if probs else 0
        
    # Remaining subcommand is fptest: one clean-file path per line, blanks ignored.
    corpus = [l.rstrip("\n") for l in open(a.corpus_file, encoding="utf-8") if l.strip()]
    # Exclusions are optional; a missing or malformed file just means no rules are excluded.
    ex = set()
    try:
        ex = set(e["rule"] for e in json.loads((RULES / "EXCLUSIONS.json").read_text())["excluded"])
    except (OSError, ValueError, KeyError):
        pass
    hits = fptest(corpus, exclusions=tuple(ex))
    print(json.dumps(hits, indent=1))
    # Non-zero exit when any false positive is found so CI can gate on it.
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
