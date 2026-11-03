# Local development evidence — 2026-11-02

Parent commit: `f762059b24d339b4a5a3b955bb5bb55e9a4c8e8d`, **plus the working-tree changes in this implementation**. This is not a benchmark of the untouched parent commit. `metadata.json` records the final source hashes and dirty-tree status; `benchmark-metadata.json` records the environment/source snapshot captured before the ten-sample benchmark run. Documentation and load-harness updates followed that benchmark capture; the measured framework and benchmark code did not change afterward.

Environment: Go 1.27.0, macOS 26.5.2, Apple M1 Max / arm64. Local machine, not a controlled CI performance runner. `manifest.json` contains SHA-256 hashes of captured artifacts. This README is an interpretation of those artifacts, not itself a measured result.

## Files and scope

* `baseline.txt`: five samples before query parsing optimization, with the new benchmark harness added to the parent implementation.
* `after.txt`: the same five-sample suite after query parsing optimization, before closer-panic hardening.
* `benchmarks.txt`: ten samples for eleven workloads after both framework fixes and expanded benchmark fixtures.
* `profile-*.txt`, `query-*.cpu`, `query-*.heap`: three-second binding profiles before/after query optimization. These profiles are separate from the timed five-sample series.
* `checks.txt`: full race/coverage run (framework 83.7%) followed by catalog, mutation and initial load-suite completion. `final-checks.txt`: later race run after adding the remaining benchmark fixtures, then vet and ten-sample benchmarks. Vet is silent on success.
* `fuzz.txt`: three sequential 20-second campaigns, two workers each. No counterexample found; this is finite exploration.
* `mutations.txt`: eight curated mutations, all detected by runtime test failures rather than compilation failure.
* `conformance.json`: independent OpenAPI validator plus ten body and five query cases. Not full standards certification.
* `tlc.txt`: finite-model run and expected negative-control counterexample. See the [model scope](../../../formal/README.md).
* `load-{gfast,nethttp,fastapi}.json`: final local HTTP smoke suite after adding the bounded arrival queue. Two-second runs, two repetitions, 100/1,000/5,000 offered requests/second; separate server processes run sequentially. Go servers use `GOMAXPROCS=1`; FastAPI uses one uvicorn worker. The client runs on the same host.

The load suite contains **54 runs / 219,600 scheduled arrivals**. No completed request had an unexpected status or transport/read failure. gfast and the minimal net/http baseline had no dropped arrivals. One FastAPI query run at 5,000 offered requests/second dropped 17 arrivals when the bounded queue filled. The raw report retains those drops and scheduled-arrival latency; do not discard them when interpreting percentiles. These short, same-host smoke results are **not** a universal speed ranking or a complete saturation/soak study. The frameworks perform different response-validation work, and the minimal net/http fixture only implements the JSON workload.

## Reproduction

Use [the evidence commands](../../../docs/evidence.md) and [performance methodology](../../../docs/performance.md). Preserve the exact source hashes, Go version, Python package versions (in the FastAPI load report), workload bodies and server topology when comparing.

Hosted Linux/macOS CI, external OAuth/WebSocket suites, dedicated-runner timing budgets, long soaks and observed usability studies were not run as part of this snapshot. Their status remains explicit in the [invariant catalog](../../../quality/invariants.json).
