#!/usr/bin/env python3
"""Local real-server smoke/saturation harness, never a universal ranking.

Runs one server at a time; captures load data, versions and server configuration.
Use a separate load-generator host for publication-quality performance claims.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--duration", default="3s")
parser.add_argument("--rates", default="100,1000,5000")
parser.add_argument("--fastapi", action="store_true", help="run using this interpreter's uvicorn installation")
parser.add_argument("--repeats", type=int, default=3)
args = parser.parse_args()
out = ROOT / "evidence/local"
out.mkdir(parents=True, exist_ok=True)
rates = [int(n) for n in args.rates.split(",")]
if args.repeats < 1 or any(n < 1 for n in rates): raise SystemExit("positive repeats/rates required")
with tempfile.TemporaryDirectory(prefix="gfast-load-", dir=os.environ.get("TMPDIR")) as work:
    work = Path(work)
    for tool in ("benchserver", "load"):
        subprocess.run(["go", "build", "-o", str(work / tool), "./tools/" + tool], cwd=ROOT, check=True)
    for framework in ["nethttp", "gfast"] + (["fastapi"] if args.fastapi else []):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        command = [str(work / "benchserver"), "-framework", framework, "-addr", f"127.0.0.1:{port}"]
        if framework == "fastapi":
            command = [sys.executable, "-m", "uvicorn", "tools.comparison.fastapi_app:app", "--host", "127.0.0.1", "--port", str(port), "--workers", "1", "--no-access-log"]
        env = dict(os.environ, GOMAXPROCS="1")
        log = (out / f"load-{framework}.log").open("w")
        server = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if server.poll() is not None: raise RuntimeError(f"{framework} server exited; see its log")
                try:
                    with urllib.request.urlopen(base + "/json", timeout=1): break
                except OSError: time.sleep(.05)
            else: raise RuntimeError("startup timed out")
            subprocess.run([str(work / "load"), "-url", base + "/json", "-rate", "100", "-duration", "1s"], check=True, stdout=subprocess.DEVNULL)
            workloads = [("json", "/json", "GET", "", 200)]
            if framework != "nethttp":
                workloads += [("validated", "/validated", "POST", '{"name":"widget","count":3}', 200), ("query", "/query?count=3", "GET", "", 200), ("invalid", "/validated", "POST", '{"name":"","count":0}', 422)]
            results = []
            for name, path, method, body, expected in workloads:
                for rate in rates:
                    for repeat in range(args.repeats):
                        load = [str(work / "load"), "-url", base + path, "-rate", str(rate), "-duration", args.duration, "-method", method, "-body", body, "-expect", str(expected)]
                        result = json.loads(subprocess.check_output(load, cwd=ROOT, text=True))
                        assert result["successful"] + result["failed"] + result["dropped"] == result["scheduled"], "load accounting mismatch"
                        result.update(workload=name, repeat=repeat + 1, command=load)
                        results.append(result)
            report = {"framework": framework, "server_command": command, "server_gomaxprocs": "1", "client_gomaxprocs": os.environ.get("GOMAXPROCS", "runtime default"), "same_host": True, "results": results}
            if framework == "fastapi":
                report["python_packages"] = subprocess.check_output([sys.executable, "-m", "pip", "freeze"], text=True).splitlines()
            (out / f"load-{framework}.json").write_text(json.dumps(report, indent=2) + "\n")
            print(f"{framework}: {len(results)} runs saved", flush=True)
        finally:
            server.terminate()
            try: server.wait(timeout=5)
            except subprocess.TimeoutExpired: server.kill(); server.wait()
            log.close()
