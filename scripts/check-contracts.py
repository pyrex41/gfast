#!/usr/bin/env python3
"""Check evidence references and catalog consistency; this is not a proof check."""
import json
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
catalog = json.loads((root / "quality/invariants.json").read_text())
symbols = set()
for source in root.glob("*_test.go"):
    symbols.update(re.findall(r"^func ((?:Test|Fuzz|Benchmark)\w+)\(", source.read_text(), re.M))
ids = set()
for entry in catalog["entries"]:
    assert entry["id"] not in ids, entry["id"]
    ids.add(entry["id"])
    assert entry["kind"] in {"robustness", "performance", "developer-experience"}
    assert entry["priority"] in {"P0", "P1", "P2"}
    assert entry["status"] in {"checked", "partial", "planned"}
    for field in ("statement", "scope", "next"):
        assert entry.get(field), (entry["id"], field)
    if entry["status"] == "checked":
        assert entry.get("tests") or entry.get("checks"), entry["id"]
    for symbol in entry.get("tests", []):
        assert symbol in symbols, (entry["id"], "missing symbol", symbol)
    for path in entry.get("checks", []):
        assert (root / path).is_file(), (entry["id"], "missing check", path)
print(f"{len(ids)} invariant/objective entries: IDs, statuses and evidence references valid")
