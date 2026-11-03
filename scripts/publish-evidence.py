#!/usr/bin/env python3
"""Copy a selected local evidence bundle into a new versioned directory.

Run checks first; this does not infer success from file presence. The manifest
records what was captured, and the accompanying narrative states check scope.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("name", help="new snapshot directory name, e.g. 2026-11-02-local")
args = parser.parse_args()
if Path(args.name).name != args.name or args.name in {".", ".."}:
    raise SystemExit("name must be a single path component")
dst = ROOT / "evidence/runs" / args.name
dst.mkdir(parents=True, exist_ok=False)
files = ["metadata.json", "benchmark-metadata.json", "baseline.txt", "after.txt", "benchmarks.txt", "profile-before.txt", "profile-after.txt", "query-before.cpu", "query-before.heap", "query-after.cpu", "query-after.heap", "mutations.txt", "tlc.txt", "conformance.json", "load-gfast.json", "load-nethttp.json", "load-fastapi.json", "checks.txt", "final-checks.txt", "fuzz.txt"]
manifest = {}
for name in files:
    source = ROOT / "evidence/local" / name
    if source.is_file():
        shutil.copyfile(source, dst / name)
        manifest[name] = hashlib.sha256(source.read_bytes()).hexdigest()
(dst / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(dst)
