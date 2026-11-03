# The north star: explicit contracts, measured objectives

The authoritative, machine-readable catalog is [quality/invariants.json](../quality/invariants.json).
Every entry has a stable ID, priority, statement, scope, evidence, status and next action.
`python3 scripts/check-contracts.py` rejects dangling evidence references in CI.

## Rules of interpretation

* **Robustness is a constraint.** A performance improvement that violates a contract is a regression, regardless of throughput.
* **Performance is workload-specific.** CPU, allocations, tail latency, memory growth and recovery are separate objectives. A single requests/second number cannot stand in for them.
* **Checked** means named executable evidence exists. It does not mean exhaustive proof. **Partial** means important paths or semantics remain unresolved. **Planned** means an explicit acceptance target without adequate evidence yet.
* Quantifiers must have a scope: whose resources, which inputs, which configuration, which failures? User callbacks, deployment topology, unbounded application work and cryptographic assumptions are not silently included in framework guarantees.
* Configuration completes before concurrent serving. Runtime reconfiguration is not currently an established contract.
* Numerical performance targets in the catalog are **provisional review thresholds**, except the tested query allocation budget. Calibrate on a controlled runner before making release-blocking latency promises.

## Robustness requirements

| IDs | Requirements | Main remaining work |
|---|---|---|
| R01–R02 | Rejection stops protected work; invalid input stops handler/injected-provider work | Cross-product failure scenarios and more policy mutations |
| R03–R05 | Request-local memoization, exact resource ownership/cleanup, isolation | Disconnect paths, resource aliasing policy, app-local registration |
| R06–R08 | Single-use credentials, exact expiry/client binding, monotonic scopes, no resurrection | Full endpoint concurrency and an explicit decision on atomic refresh replacement |
| R09–R13 | Bounded framework resources, tamper resistance, origin policy, hostile-input safety, race/leak freedom | Soaks, leak checks, parser coverage and external vectors |
| R14–R16 | Schema/runtime agreement, deterministic binding, correct HTTP/error behavior | Required-property schema semantics and independent wire checks |
| R17–R20 | Defined lifecycle, fail-fast registration, conformance, tests sensitive to faults | Shutdown/disconnect tests, broader conformance and mutation coverage |

### Important current boundaries

* Refresh consumption and replacement issuance use separate critical sections. A competing issuer can take the freed slot. Replacement may fail, and the consumed token remains burned. See `TestContractOAuthCapacityFailureTrace` and the [formal model](../formal/README.md).
* Cleanup is tested for handler errors/panics, cancellation, partial acquisition, background panic and panicking closers. Remaining closers are attempted after a closer panic, then the first closer panic is rethrown. Blocking callbacks, `runtime.Goexit` and process termination are excluded; disconnect/write-failure coverage still needs strengthening.
* Dependency registration remains process-global. Concurrent independent-app **overrides** are tested; globally isolated name registration is not implemented.
* OpenAPI's required non-pointer properties and runtime presence validation are not universally equivalent. The independent conformance fixture establishes selected boundaries, not full schema equivalence.
* Credential readers extract credentials. Applications must provide actual credential verification/authorization where appropriate.

## Performance objectives

| ID | Objective | Measurement |
|---|---|---|
| P01 | Parse query once per binding | Six-field benchmark plus allocation ceiling |
| P02 | No unexplained hot-path regressions | Repeated ns/op, B/op, allocs/op; profile changes |
| P03 | Predictable tails at specified offered load | Open-loop p50/p95/p99, errors and drops |
| P04 | Stable resources and recovery | Post-GC heap slope, goroutine count, recovery time |
| P05 | Streaming memory independent of stream length | Slow-reader profiles across response sizes |
| P06 | Predictable cost of rejected traffic | Mixed valid/invalid saturation curves |
| P07 | Comparable, reproducible speed claims | Equivalent constraints, topology, raw repeats, uncertainty |
| P08 | Predictable application build costs | Route/dependency/schema scaling curves |

## Iteration loop

1. Pick one invariant/objective ID and its highest-risk missing case.
2. Define an oracle independent of the implementation and a deliberate violating mutation.
3. Add a minimal regression or generated sequence; retain minimized counterexamples.
4. Fix the implementation. Run relevant tests, the race detector, and affected benchmark workloads.
5. Compare on the same hardware/toolchain. Report uncertainty and workload semantics.
6. Update the entry's evidence, scope and next action. Upgrade status only when evidence supports it.
7. Publish a release evidence snapshot; describe exactly the claims it supports.

Release review should first address **P0 partial entries R04, R12 and R13**. Then close R14 schema semantics and R17 lifecycle gaps. Parallel performance work should establish P02/P03 baselines before chasing comparative throughput.
