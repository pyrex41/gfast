#!/usr/bin/env python3
"""Small auditable fault-injection gate, not an exhaustive mutation score.

Copies current source (including uncommitted changes), never edits the checkout.
Compile errors, crashes, and timeouts are errors, not killed mutants.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MUTANTS = [
    ("authorization-bypass", "gfast.go", "for _, dep := range p.requires {", "for _, dep := range p.requires[:0] {", "TestContractAuthorizationMetamorphic"),
    ("memoization-disabled", "dep.go", "if v, ok := st.memo[e.id]; ok {", "if v, ok := st.memo[e.id]; ok && false {", "TestContractDependencyCleanup"),
    ("cleanup-forward", "gfast.go", "for i := len(st.closers) - 1; i >= 0; i-- {", "for i := 0; i < len(st.closers); i++ {", "TestContractDependencyCleanup"),
    ("refresh-reuse", "oauth.go", "delete(s.refreshes, raw)", "// deliberately retain refresh token", "TestContractOAuthConcurrentConsume"),
    ("capacity-bypass", "oauth.go", "if len(s.refreshes) >= s.maxRefresh {", "if false {", "TestContractOAuthCapacityFailureTrace"),
    ("expiry-inclusive", "oauth.go", "for key, item := range s.codes {\n\t\tif !now.Before(item.expires) {", "for key, item := range s.codes {\n\t\tif now.After(item.expires) {", "TestContractOAuthExpiryBoundary"),
    ("scope-escalation", "oauth.go", 'scopes, err := subsetScopes(item.scopes, r.PostForm.Get("scope"))\n\tif err != nil {', 'scopes, err := subsetScopes(item.scopes, r.PostForm.Get("scope"))\n\tif err != nil && false {', "TestContractOAuthRotation"),
    ("body-cap-bypass", "gfast.go", "r.Body = http.MaxBytesReader(unwrapWriter(w), r.Body, limit)", "// deliberately bypass body cap", "TestIssue9ChunkedTCP"),
]

with tempfile.TemporaryDirectory(prefix="gfast-mutations-", dir=os.environ.get("TMPDIR")) as work:
    dst = Path(work) / "repo"
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "evidence", "bin", "*.test", ".venv", "__pycache__"))
    def run(pattern):
        return subprocess.run(["go", "test", "-count=1", "-run", pattern, "."], cwd=dst, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    baseline = run("TestContract|FuzzJSONBinding")
    if baseline.returncode:
        raise SystemExit("baseline failed:\n" + baseline.stdout)
    results = []
    for name, file, old, new, test in MUTANTS:
        path = dst / file
        source = path.read_text()
        if source.count(old) != 1:
            raise SystemExit(f"stale mutation {name}: expected exactly one anchor")
        path.write_text(source.replace(old, new))
        try:
            result = run(test)
        finally:
            path.write_text(source)
        killed = result.returncode != 0 and "--- FAIL:" in result.stdout and "[build failed]" not in result.stdout
        results.append({"name": name, "test": test, "killed": killed, "output": result.stdout})
        print(f"{name}: {'killed' if killed else 'SURVIVED / invalid'}", flush=True)
    print(json.dumps(results, indent=2))
    if not all(r["killed"] for r in results):
        raise SystemExit(1)
