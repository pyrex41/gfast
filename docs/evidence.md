# Evidence, claims and gaps

This page is a development snapshot, not a third-party certification or universal framework ranking. The [invariant catalog](../quality/invariants.json) is the source of truth for claim scope and remaining work.

Raw local results are retained in the [2026-11-02 evidence bundle](../evidence/runs/2026-11-02-local/README.md), including source/environment metadata, repeated samples, load results, fuzz/mutation logs and TLC output.

## Implemented evidence layers

| Layer | Executable evidence | What it establishes |
|---|---|---|
| Semantic properties | Hegel suites, including shrinkable OAuth command sequences | Generated examples satisfy the asserted properties |
| Failure/concurrency contracts | `contracts_test.go` | Cleanup, request/app isolation, single-consumer races, expiry and rotation behavior in exercised scenarios |
| Parser fuzzing | Three native Go fuzz targets | Coverage-guided malformed-input exploration of JSON, multipart and signed-token parsing |
| Fault injection | `scripts/mutate.py` | Tests detect eight curated, compiling implementation violations |
| Independent schema checks | `scripts/conformance.py` | External validator accepts fixture OpenAPI; ten body and five query cases match selected runtime boundaries |
| Formal state machine | `formal/OAuth.tla` | Finite-state safety properties under documented abstractions; negative control finds a violation |
| Performance | Go benchmarks, pprof, local open-loop HTTP suite | Costs of named workloads on the recorded environment |
| Release repeatability | CI workflow, metadata collector and catalog-reference check | Reproducible commands and source/version provenance; hosted execution must be checked separately |

## Initial local measurements

Environment: Apple M1 Max, macOS/arm64, Go 1.27.0. Five sequential benchmark samples per revision, default `GOMAXPROCS` (benchmark suffix 10). These are descriptive local medians, not statistically controlled cross-machine claims.

| Workload | Before | After query optimization | Allocation change |
|---|---:|---:|---:|
| Six-field query binding | 4,371 ns/op | 2,309 ns/op | 68 → 28 allocs; 3,558 → 1,078 B/op |
| HTTP six-query-field route | 5,653 ns/op | 3,810 ns/op | 89 → 49 allocs; 5,529 → 3,047 B/op |

The optimization parses the URL query once per binding instead of once per field. A **32-allocation ceiling** guards the six-field workload against reintroducing the original behavior. Existing binding properties and the race suite accompany the optimization. These before/after samples precede the separate closer-panic hardening; later benchmark artifacts measure the final implementation.

Other workloads are retained in the raw files, including unchanged-path variation. We do not generalize this query-specific improvement to every endpoint or claim superiority over another framework.

TLC's configured model explored **10,373 distinct states / 34,540 generated states**, with no invariant violation. The negative control found `NoResurrection` violated after issuance and consumption. This is evidence about the finite model, not a proof of the Go implementation. See [model scope and assumptions](../formal/README.md).

The first local fuzz campaign ran each target for 20 seconds with two workers: JSON 142,012 executions; multipart 86,968; access tokens 327,482. No counterexample was found in that bounded run. Counts vary with machine, corpus and runtime; they are not a security metric.

The full local race/coverage run passed, with **83.7% statement coverage in the framework package**. Coverage measures exercised statements, not the quality of assertions. All eight curated mutations were detected. Final microbenchmarks include ten samples each for eleven workloads, including nested dependencies, multipart and signed-session reads.

## Reproduce the gates

```sh
go vet ./...
go test -race -count=1 ./...
python3 scripts/check-contracts.py
python3 scripts/mutate.py
go test -run '^$' -fuzz '^FuzzJSONBinding$' -fuzztime=30s -parallel=2 .
go test -run '^$' -fuzz '^FuzzMultipart$' -fuzztime=30s -parallel=2 .
go test -run '^$' -fuzz '^FuzzAccessToken$' -fuzztime=30s -parallel=2 .
python3 scripts/check-model.py
```

The model check requires Java and network access for the pinned TLC jar. The Hegel suites use the version pinned in `go.mod`. Run independent schema checks in an isolated Python environment:

```sh
python3 -m venv .venv
.venv/bin/pip install -r tools/conformance/requirements.txt
.venv/bin/python scripts/conformance.py
```

See [performance reproduction](performance.md) for benchmarks, load comparisons and profiling. `scripts/evidence.py` captures the commit, dirty-tree status, source hashes and environment into `evidence/local/metadata.json`. A dirty-tree snapshot is explicitly identified; it must not be described as the untouched parent commit.

## Publishing a release

Attach the invariant catalog, passing-check logs, failing-case corpus, mutation results, model output, benchmark raw samples, comparison semantics, and source/environment metadata to a tagged release. Verify hosted Linux/macOS CI rather than treating a configured workflow as evidence it has passed. Link claims to these artifacts and keep known gaps visible.

## Explicit remaining work

* App-scoped provider registration and an enforced configuration/serving boundary.
* Complete required-property schema/runtime alignment.
* More disconnect, shutdown, resource-ownership and long-running leak/soak tests.
* External WebSocket and broader OAuth conformance suites.
* Controlled-runner timing gates, Huma comparison, stream/CSRF workloads, separate-client saturation curves and resource recovery measurements.
* Observed usability trials using the [prepared protocol](usability.md).
* A stronger implementation-to-model correspondence if formal verification is extended.

These gaps are catalogued acceptance work, not hidden assumptions behind a “fully verified” label.
