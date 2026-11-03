#!/usr/bin/env python3
"""Independent OpenAPI validation and a bounded schema/runtime sample suite.

Starts its own fixture server; no deployed application is contacted.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from jsonschema import Draft202012Validator
from openapi_spec_validator import validate

ROOT = Path(__file__).resolve().parents[1]

with tempfile.TemporaryDirectory(prefix="gfast-conformance-", dir=os.environ.get("TMPDIR")) as work:
    binary = str(Path(work) / "server")
    subprocess.run(["go", "build", "-o", binary, "./tools/benchserver"], cwd=ROOT, check=True)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
    server = subprocess.Popen([binary, "-addr", f"127.0.0.1:{port}"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    base = f"http://127.0.0.1:{port}"
    def request(path, body=None):
        req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)
    try:
        for _ in range(100):
            if server.poll() is not None:
                raise RuntimeError(server.stderr.read().decode())
            try:
                _, spec = request("/openapi.json"); break
            except urllib.error.URLError:
                time.sleep(.05)
        else:
            raise RuntimeError("fixture startup timed out")
        validate(spec)
        input_schema = spec["paths"]["/validated"]["post"]["requestBody"]["content"]["application/json"]["schema"]
        output_schema = spec["paths"]["/validated"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
        def validator(schema):
            return Draft202012Validator({"$schema": "https://json-schema.org/draft/2020-12/schema", "components": spec.get("components", {}), **schema})
        inputs, outputs = validator(input_schema), validator(output_schema)
        cases = [
            {"name": "widget", "count": 1}, {"name": "é" * 80, "count": 100},
            {"name": "x", "count": 0}, {"name": "x", "count": 101},
            {"name": "", "count": 3}, {"name": "x" * 81, "count": 3},
            {"name": "x", "count": "3"}, {"name": "x", "count": 1.5},
            {"count": 3}, {"name": None, "count": 3},
        ]
        for body in cases:
            valid = inputs.is_valid(body)
            status, response = request("/validated", body)
            assert (status == 200) == valid, (body, status, valid, response)
            if valid:
                outputs.validate(response)
                assert response == body
        for raw, expected in [("1", 200), ("100", 200), ("0", 422), ("101", 422), ("abc", 400)]:
            status, response = request("/query?count=" + raw)
            assert status == expected, (raw, status, response)
        print(json.dumps({"openapi": spec["openapi"], "openapi_valid": True, "body_cases": len(cases), "query_cases": 5, "scope": "fixture schema and selected boundaries, not complete JSON Schema or OAuth/WebSocket conformance"}, indent=2))
    finally:
        server.terminate()
        try: server.wait(timeout=5)
        except subprocess.TimeoutExpired: server.kill(); server.wait()
