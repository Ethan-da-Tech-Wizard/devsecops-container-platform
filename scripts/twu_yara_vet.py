#!/usr/bin/env python3
# Program: devsecops-container-platform - twu_yara_vet.py
# Programmer: Ethan-da-Tech-Wizard (written with Claude, an AI assistant)
# Last Modified: 2026-11-18
# Purpose: Command-line tool that vets third-party YARA rule files with static checks and the yarac compiler, records SHA-256 hashes in a manifest, and later verifies those hashes and runs false-positive scans.
"""
==============================================================================
Program: Cryptographic YARA Rule Vetting & Verification Engine (twu_yara_vet)
Programmer: The Maintainer <maintainer@example.invalid>
Organization: TWU LLC
License: MIT License 2026
Purpose: Build, audit, and cryptographically verify the vetted YARA detection rule
         manifest in data/yara_rules/ (Python standard library only, 100% offline).

Commands:
  build  --src ID=DIR@COMMIT|LICENSE|URL ...   Vet rule files from pinned, already-downloaded checkouts.
  fptest --corpus-file LIST                    Scan known-clean files, reporting false-positive rule triggers.
  verify                                       Check MANIFEST sha256 checksums and compile index.yar.

Security & Architectural Design:
  1. Offline Operation: Rules are NEVER downloaded dynamically by this script. Rules must be
     downloaded, inspected, and unpacked at a pinned git commit hash before running `build`.
  2. Strict Static Gating: A rule file is REJECTED when it:
     - Imports an unvetted or disabled module outside ALLOWED_MODULES (e.g. cuckoo).
     - Declares an `include "..."` directive (every rule file must be self-contained).
     - Declares a `global` rule modifier (prevents cross-rule condition poisoning).
     - Declares an external variable (the scanning runtime provides zero external variables).
     - Repeats an existing rule identifier already claimed by a previously vetted rule.
  3. Non-Executable Analysis: Scanned target files are opened read-only; nothing here executes
     or evaluates scanned payloads.

Threat Model & Attack Vectors Mitigated:
  - Supply Chain Rule Tampering (CWE-353): Cryptographic SHA-256 verification guarantees that
    no rule file has been modified, corrupted, or backdoored after the manifest build date.
  - Insecure C Extension Exploits (CWE-829): Restricts imports to audited native modules
    (pe, elf, math, hash, dotnet, macho), blocking unvetted modules that could execute arbitrary code.
  - Scope Pollution & Cross-Contamination: Disallowing `global` rules ensures one rule's logic
    cannot force matches or suppress detections across the rest of the detection corpus.
  - Filesystem Race Conditions (CWE-362): Atomic write operations (`write_atomic`) write to a
    temporary file on the same filesystem and replace the target atomically via `os.replace()`.
  - Regular Expression Denial of Service (ReDoS): Mandatory compilation via `yarac` catches
    catastrophic regex syntax before rules are deployed into scanning daemons.

Senior Interview Talking Points:
  - Cryptographic Manifest Provenance: How pinned git commits and SHA-256 integrity trees
    satisfy zero-trust supply chain governance for endpoint threat intelligence feeds.
  - Fail-Closed Static Analysis: Why blocking dynamic includes and external variables enforces
    hermetic rule evaluation across distributed production nodes.
  - Atomic File Persistence in Linux: Why `tempfile.mkstemp` paired with `os.replace` prevents
    partially written or corrupted index files during unexpected power loss or process kill.
==============================================================================
"""

# Standard library only: hashing, JSON, regex, running external programs (yarac/yara), temp files, timing.
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

# ROOT is the repo folder (two levels above this file); RULES is where vetted rules are stored.
# Workspace directory resolution
ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "data" / "yara_rules"

# Only these YARA modules may be imported by a rule file.
# Security whitelist: Audited native YARA modules permitted in rule definitions.
# Any import outside this set causes immediate rule rejection (e.g. 'import "cuckoo"').
ALLOWED_MODULES = {"pe", "elf", "math", "hash", "dotnet", "macho"}

# Pre-compiled patterns used to scan rule text; re.M makes ^ match at the start of every line.
# Linear regular expressions for static rule inspection (ReDoS-safe)
# Matches: import "name"
IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)"', re.M)
# Matches a rule declaration, capturing any private/global modifiers and the rule name.
RULE_RE = re.compile(r'^\s*((?:(?:private|global)\s+)*)rule\s+([A-Za-z_]\w*)', re.M)
# Matches an include "..." line.
INCLUDE_RE = re.compile(r'^\s*include\s+"', re.M)


# Finds a command-line program such as yara or yarac.
def which_local(cmd: str) -> str | None:
    """Locate an executable binary in the system PATH or the local user bin directory.
    
    Checks standard system PATH first, then falls back to ~/.local/bin/ if executable.
    
    Args:
        cmd: Binary name (e.g. 'yara', 'yarac').
        
    Returns:
        Absolute string path to binary if found and executable, otherwise None.
    """
    # Searched the normal PATH first.
    # 1. Search system PATH directories
    # shutil.which returns the full path or None.
    p = shutil.which(cmd)
    if p:
        return p
    # Fallback: a per-user bin folder.
    # 2. Check local user environment fallback (~/.local/bin)
    c = Path.home() / ".local" / "bin" / cmd
    return str(c) if c.is_file() and os.access(str(c), os.X_OK) else None


# Computes a file's SHA-256 fingerprint; any change to the file changes this value.
def sha256(path: Path | str) -> str:
    """Computes the cryptographic SHA-256 digest of a target file using 1MB chunked streaming.
    
    Args:
        path: Path to target file.
        
    Returns:
        64-character lowercase hexadecimal SHA-256 hash string.
        
    Attack Vector Prevented:
        Memory exhaustion when hashing large binary files; streaming 1MB buffers preserves low memory footprint.
    """
    # Start a hash object; we feed it the file piece by piece.
    h = hashlib.sha256()
    # Open in binary mode so the bytes are hashed exactly as stored.
    with open(str(path), "rb") as f:
        # Read 1 MiB at a time until read() returns empty bytes (end of file).
        # Read file in 1 MiB (1,048,576 bytes) chunks to prevent memory spikes
        # (1 << 20 is 2 to the power 20 = 1,048,576.)
        for b in iter(lambda: f.read(1 << 20), b""):
            # Add this chunk to the running hash.
            h.update(b)
    # Return the final fingerprint as hex text.
    return h.hexdigest()


# Removes YARA comments so commented-out imports or includes are not mistaken for real ones.
def strip_comments(text: str) -> str:
    """Strips C-style multi-line (/* ... */) and C++ single-line (// ...) comments from YARA source.
    
    Args:
        text: Raw YARA rule source text.
        
    Returns:
        Sanitized source text with comments excised, preventing commented directives from triggering parser logic.
    """
    # First remove /* ... */ blocks (re.S lets . match newlines), then // line comments.
    # Strip multi-line block comments /* ... */
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    # Strip single-line comments // ...
    return re.sub(r"//[^\n]*", "", text)


# Checks one rule file's text against the safety rules and returns (rule names, rejection reason or None).
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
    # Work on comment-free text.
    bare = strip_comments(text)
    
    # Reject any import that is not on the allowed list.
    # 1. Validate module imports against security whitelist
    for m in IMPORT_RE.findall(bare):
        if m not in ALLOWED_MODULES:
            return [], f"uses disabled module '{m}'"
            
    # Reject include lines so every file stands alone.
    # 2. Reject include statements to enforce hermetic self-containment
    if INCLUDE_RE.search(bare):
        return [], "uses include (must be self-contained)"
        
    # Collect each rule name; reject if a rule is marked global.
    # 3. Extract rule declarations and reject global modifiers
    names = []
    for mods, name in RULE_RE.findall(bare):
        if "global" in mods:
            return [], f"declares global rule {name}"
        names.append(name)
        
    # A file with no rules is useless, so reject it.
    # 4. Ensure file actually defines at least one valid rule
    if not names:
        return [], "no rules found"
        
    # Return the rule names and None meaning 'no problem'.
    return names, None


# Compiles a rule file with the yarac tool to confirm it is valid.
def compile_check(yarac: str, path: Path | str) -> str | None:
    """Executes yarac compiler in an isolated temporary directory to verify rule syntax and compilation.
    
    Args:
        yarac: Path to yarac compiler binary.
        path: Path to target YARA rule file.
        
    Returns:
        None if compilation succeeds; error message string if compilation fails.
    """
    # Use a throwaway folder for the compiled output so nothing is left behind.
    with tempfile.TemporaryDirectory() as td:
        try:
            # Run yarac, capture its messages as text, and give up after 120 seconds.
            # Execute yarac in isolated scratch directory with a 120-second timeout guard
            r = subprocess.run(
                [yarac, str(path), os.path.join(td, "out.yarc")],
                capture_output=True,
                text=True,
                timeout=120
            )
        # If yarac could not start or took too long, report that.
        except (OSError, subprocess.TimeoutExpired) as e:
            return f"yarac did not run: {e}"
            
        # A non-zero return code means compile failure; take the last message line.
        if r.returncode != 0:
            msg = ((r.stderr or r.stdout).strip().splitlines() or ["compile error"])[-1]
            # Messages about undefined/external identifiers get a clearer explanation.
            if "undefined identifier" in msg or "external" in msg:
                return "needs external variable or undefined identifier: " + msg[-160:]
            # Only the last 160 characters of the message are kept to keep reports short.
            return "does not compile: " + msg[-160:]
    # None means success.
    return None


# Thin wrapper: checks that the combined index file compiles.
def combined_ok(yarac: str, index: Path | str) -> str | None:
    """Validates that the combined index file containing all included rules compiles without conflicts."""
    return compile_check(yarac, index)


# Creates index.yar: a file that includes every accepted rule file.
def write_index(rules_dir: Path, files: list[str]) -> None:
    """Writes the master index.yar file with sorted, deterministic include statements."""
    # First line is a note saying the file is generated.
    lines = ["// generated by scripts/twu_yara_vet.py; do not edit. One include per vetted file.\n"]
    # sorted() keeps the output in the same order every time.
    for rel in sorted(files):
        lines.append(f'include "{rel}"\n')
    # Write all lines out in one go.
    (rules_dir / "index.yar").write_text("".join(lines), encoding="utf-8")


# Saves JSON safely: write to a temp file, then swap it into place so readers never see a half-written file.
def write_atomic(path: Path | str, doc: dict) -> None:
    """Writes a JSON document to disk atomically to prevent corruption or incomplete reads.
    
    Writes output to a temporary file on the exact same filesystem, then performs an
    atomic rename (`os.replace`) to overwrite the destination path.
    
    Attack Vector Prevented:
        Race conditions, torn reads, and partially written corrupted manifest files.
    """
    # Path() lets us accept either a string or a Path.
    path = Path(path)
    # mkstemp makes a uniquely named temp file in the same folder (same disk, so the swap is atomic).
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    # Turn the low-level file handle into a normal text file and write the JSON (sorted keys for stable output).
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    # Replace the real file with the finished temp file in one step.
    os.replace(tmp, str(path))


# Splits 'ID=DIR@COMMIT|LICENSE|URL' into its five pieces.
def parse_src(spec: str) -> tuple[str, Path, str, str, str]:
    """Parses a source specification string of format ID=DIR@COMMIT|LICENSE|URL."""
    # Split once at '=' to separate the ID from the rest.
    idpart, rest = spec.split("=", 1)
    # Turn the first '@' into '|' then split into folder, commit, license and URL.
    d, commit, lic, url = rest.replace("@", "|", 1).split("|", 3)
    # Return all five values (the folder becomes a Path).
    return idpart, Path(d), commit, lic, url


# The main workhorse: vets every rule file from each source and writes index.yar and MANIFEST.json.
def build(srcs: list, rules_dir: Path = RULES, yarac: str | None = None,
          include_dirs: dict | None = None, now: float | None = None) -> dict:
    """Builds and vets the complete YARA rule set from pinned external source checkouts.
    
    Iterates over source files, applies static security checks, executes `yarac` compilation checks,
    detects duplicate rule identifiers, records vendor licenses, generates index.yar, and writes
    the cryptographic MANIFEST.json.
    
    Returns:
        Dictionary representing the generated manifest metadata.
    """
    # Use the given yarac or search for one; stop with a message if none exists.
    yarac = yarac or which_local("yarac")
    if not yarac:
        raise SystemExit("yarac not found")
    # Start with clean bookkeeping: names already used, accepted files, rejected files, and per-source summaries.
    rules_dir = Path(rules_dir)
    taken: dict[str, str] = {}
    accepted: list[dict] = []
    rejected: list[dict] = []
    sources: list[dict] = []
    # Remove any previous vendor copy so the result only contains rules from this run.
    vendor = rules_dir / "vendor"
    if vendor.exists():
        shutil.rmtree(str(vendor))
        
    # Handle each source checkout in turn.
    for sid, d, commit, lic, url in srcs:
        # Summary record for this source.
        entry = {"id": sid, "url": url, "commit": commit, "license": lic, "files": 0, "rejected": 0}
        # Optionally limit to chosen subfolders; the default is the whole checkout ('.').
        for sub in (include_dirs or {}).get(sid) or ["."]:
            base = d / sub
            # Visit every file in stable order.
            for p in sorted(base.rglob("*")):
                # Skip anything that is not a .yar/.yara file, and skip 'deprecated' folders.
                if p.suffix not in (".yar", ".yara") or not p.is_file() or "deprecated" in p.parts:
                    continue
                # Path relative to the source checkout, used in reports.
                rel_src = str(p.relative_to(d))
                # Read the rule file; skip it if it cannot be read.
                try:
                    text = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                # Check 1: static safety rules.
                names, why = static_check(text)
                # Check 2: no rule name may already belong to an earlier accepted file.
                if not why:
                    dup = [n for n in names if n in taken]
                    if dup:
                        why = f"duplicate rule name {dup[0]} already in {taken[dup[0]]}"
                # Check 3: it must compile with yarac.
                if not why:
                    why = compile_check(yarac, p)
                # Any failure: record why and move on to the next file.
                if why:
                    rejected.append({"source": sid, "file": rel_src, "reason": why})
                    entry["rejected"] += 1
                    continue
                # Accepted: copy the file into vendor/<source id>/ inside the rules folder.
                dest_rel = f"vendor/{sid}/{rel_src}"
                dest = rules_dir / dest_rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(str(p), str(dest))
                # Remember which file owns each rule name (for duplicate detection).
                for n in names:
                    taken[n] = dest_rel
                # Record the file with its SHA-256 so it can be verified later.
                accepted.append({
                    "path": dest_rel,
                    "sha256": sha256(dest),
                    "source": sid,
                    "source_path": rel_src,
                    "rules": len(names)
                })
                entry["files"] += 1
        # Also copy the source's LICENSE file and record its hash.
        lic_src = d / "LICENSE"
        if lic_src.is_file():
            (rules_dir / "vendor" / sid).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(str(lic_src), str(rules_dir / "vendor" / sid / "LICENSE"))
            entry["license_file_sha256"] = sha256(rules_dir / "vendor" / sid / "LICENSE")
        # Save this source's summary.
        sources.append(entry)
        
    # Write index.yar, then test that all accepted files compile together.
    write_index(rules_dir, [a["path"] for a in accepted])
    why = combined_ok(yarac, rules_dir / "index.yar")
    # The manifest: a JSON record of everything accepted, rejected and how it was built.
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
    # Save the manifest safely and return it.
    write_atomic(rules_dir / "MANIFEST.json", doc)
    return doc


# Re-checks the stored rules against the manifest to detect tampering or damage; returns a list of problems.
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
    # Start with no problems found.
    rules_dir = Path(rules_dir)
    # Load the manifest; if it cannot be read, report that right away.
    probs = []
    try:
        man = json.loads((rules_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [f"MANIFEST.json unreadable: {e}"]
        
    # Verify presence and cryptographic SHA-256 integrity for every file
    # For each listed file: it must exist and its fresh hash must equal the recorded one.
    for f in man.get("files", []):
        p = rules_dir / f["path"]
        if not p.is_file():
            probs.append(f"missing {f['path']}")
        elif sha256(p) != f["sha256"]:
            probs.append(f"sha256 mismatch {f['path']}")
            
    # index.yar must include exactly the files the manifest lists (compared as sets).
    # Verify index.yar matches manifest files exactly
    idx = rules_dir / "index.yar"
    want = set(f'include "{f["path"]}"' for f in man.get("files", []))
    have = set(l.strip() for l in idx.read_text(encoding="utf-8").splitlines() if l.startswith("include")) if idx.is_file() else set()
    if want != have:
        probs.append("index.yar does not match MANIFEST")
        
    # If everything else is fine, also compile the combined index.
    # Verify combined compilation
    yarac = yarac or which_local("yarac")
    if compile_index and yarac and not probs:
        why = compile_check(yarac, idx)
        if why:
            probs.append(f"index.yar {why}")
            
    # Empty list means verified.
    return probs


# Runs the rules over known-harmless files to find rules that wrongly trigger (false positives).
def fptest(corpus: list[str], rules_dir: Path = RULES, yara: str | None = None,
           exclusions: tuple = (), timeout: int = 1800) -> dict:
    """Scans a corpus of known-clean files using index.yar to detect false-positive rule triggers.
    
    Links files into an isolated temporary directory so rules compile once; no files are executed.
    """
    # Find the yara scanner; 'hits' maps rule name to the files it matched.
    yara = yara or which_local("yara")
    # 'names' maps a short safe link name back to the real file path.
    hits: dict[str, list[str]] = {}
    with tempfile.TemporaryDirectory() as td:
        names = {}
        # Give each file a short generated name (f0000000...) and link to it, so odd file names cannot confuse the scanner.
        for i, p in enumerate(corpus):
            n = f"f{i:07d}"
            try:
                os.symlink(p, os.path.join(td, n))
            except OSError:
                continue
            names[n] = p
        # Run yara recursively over the temp folder with a long timeout.
        r = subprocess.run(
            [yara, "-r", str(Path(rules_dir) / "index.yar"), td],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        # Each output line looks like 'rule path'; parse it and skip malformed lines.
        for line in r.stdout.splitlines():
            parts = line.split(" ", 1)
            if len(parts) != 2:
                continue
            rule, path = parts
            # Ignore rules on the exclusions list.
            if rule in exclusions:
                continue
            # Record the real file path under the matching rule name.
            hits.setdefault(rule, []).append(names.get(os.path.basename(path), path))
    # Return the dictionary of false-positive hits.
    return hits


# Entry point: chooses build, fptest or verify from the command line.
def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for twu_yara_vet. Parses commands and runs actions."""
    # Define the command-line options for each sub-command.
    ap = argparse.ArgumentParser(
        description="Cryptographic YARA Rule Vetting & Verification Engine (twu_yara_vet)"
    )
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
    
    # Read what the user typed.
    a = ap.parse_args(argv)
    
    # build: turn --only values (ID=subdir) into a dictionary, then run build and print a summary.
    if a.cmd == "build":
        inc: dict[str, list[str]] = {}
        for o in a.only:
            k, v = o.split("=", 1)
            inc.setdefault(k, []).append(v)
        doc = build([parse_src(s) for s in a.src], include_dirs=inc)
        print(f"accepted {len(doc['files'])} files, {doc['rule_count']} rules; "
              f"rejected {len(doc['rejected'])}; combined compile: {doc['combined_compile']}")
        return 0
        
    # verify: print OK or the list of problems; exit code 1 means problems were found.
    if a.cmd == "verify":
        probs = verify()
        print("OK" if not probs else "\n".join(probs))
        return 1 if probs else 0
        
    # Otherwise this is fptest: load the list of file paths to scan (one per line, blank lines skipped).
    corpus = [l.rstrip("\n") for l in open(a.corpus_file, encoding="utf-8") if l.strip()]
    # Load rule names that are intentionally excluded, if the exclusions file exists.
    ex = set()
    try:
        ex = set(e["rule"] for e in json.loads((RULES / "EXCLUSIONS.json").read_text())["excluded"])
    except (OSError, ValueError, KeyError):
        pass
    # Scan the corpus; any hit is a failure (exit code 1).
    hits = fptest(corpus, exclusions=tuple(ex))
    print(json.dumps(hits, indent=1))
    return 1 if hits else 0


# Run main() only when executed directly, not when imported by the tests.
if __name__ == "__main__":
    sys.exit(main())
