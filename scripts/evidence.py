#!/usr/bin/env python3
"""Capture reproducibility metadata and optionally run repeated benchmarks.

Local output is ignored by git. Publish selected artifacts with a release.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--bench", action="store_true")
parser.add_argument("--count", type=int, default=10)
args = parser.parse_args()
out = ROOT / "evidence/local"
out.mkdir(parents=True, exist_ok=True)
def capture(*command):
    return subprocess.check_output(command, cwd=ROOT, text=True).strip()

files = capture("git", "ls-files", "--cached", "--others", "--exclude-standard").splitlines()
hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sorted(set(files)) if (ROOT / name).is_file() and not name.startswith("evidence/")}
meta = {
    "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "commit": capture("git", "rev-parse", "HEAD"),
    "working_tree_status": capture("git", "status", "--short"),
    "source_sha256": hashes,
    "go_version": capture("go", "version"),
    "go_env": json.loads(capture("go", "env", "-json", "GOOS", "GOARCH", "GOEXPERIMENT", "GOTOOLCHAIN", "CGO_ENABLED")),
    "gomaxprocs_env": os.environ.get("GOMAXPROCS", "runtime default"),
    "platform": platform.platform(), "logical_cpus": os.cpu_count(),
    "python": platform.python_version(),
    "benchmark_command": ["go", "test", "-run", "^$", "-bench", ".", "-benchmem", f"-count={args.count}", "."] if args.bench else None,
}
if platform.system() == "Darwin":
    meta["cpu"] = capture("sysctl", "-n", "machdep.cpu.brand_string")
(out / "metadata.json").write_text(json.dumps(meta, indent=2) + "\n")
if args.bench:
    if args.count < 1: raise SystemExit("count must be positive")
    with (out / "benchmarks.txt").open("w") as log:
        subprocess.run(meta["benchmark_command"], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
print(out)
