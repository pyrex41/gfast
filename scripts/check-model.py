#!/usr/bin/env python3
"""Pinned TLC plus a negative control; runs entirely in a temporary directory."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="gfast-tlc-", dir=os.environ.get("TMPDIR")) as work:
    work = Path(work)
    jar = work / "tla2tools.jar"
    urllib.request.urlretrieve("https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar", jar)
    # Upstream's release checksum; verify before executing the downloaded jar.
    assert hashlib.sha1(jar.read_bytes()).hexdigest() == "bee4a54f3ee3d4afc347c3240ec2d9e93b075104", "TLC checksum mismatch"
    source = (ROOT / "formal/OAuth.tla").read_text()
    (work / "OAuth.cfg").write_text((ROOT / "formal/OAuth.cfg").read_text())
    for mutant in (False, True):
        text = source
        if mutant:
            old = "/\\ live' = live \\ {t}\n                 /\\ pending'"
            assert text.count(old) == 1
            text = text.replace(old, "/\\ live' = live\n                 /\\ pending'")
        (work / "OAuth.tla").write_text(text)
        result = subprocess.run(["java", "-XX:+UseParallelGC", "-cp", str(jar), "tlc2.TLC", "-workers", "1", "-config", "OAuth.cfg", "OAuth.tla"], cwd=work, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
        print("NEGATIVE CONTROL" if mutant else "BASELINE", flush=True)
        print(result.stdout, flush=True)
        if mutant:
            assert result.returncode != 0 and "Invariant NoResurrection is violated" in result.stdout, "mutated model must produce the expected counterexample"
        else:
            assert result.returncode == 0 and "No error has been found" in result.stdout, "model check failed"
