# Performance methodology

Start with the [objectives P01–P08](../quality/invariants.json), not a throughput headline.

## Reproduce

```sh
go test ./...
python3 scripts/evidence.py --bench --count 10
go test -run '^$' -bench '^BenchmarkBindQuery$' -benchtime=3s -cpuprofile=evidence/local/query.cpu -memprofile=evidence/local/query.heap
go tool pprof -top evidence/local/query.cpu
go tool pprof -top -alloc_space evidence/local/query.heap
python3 scripts/load-suite.py --rates 100,1000,5000 --duration 10s --repeats 3
```

Optional FastAPI stack comparison:

```sh
python3 -m venv .venv
.venv/bin/pip install -r tools/comparison/requirements.txt
.venv/bin/python scripts/load-suite.py --fastapi --rates 100,1000,5000 --duration 10s --repeats 3
```

Versions, dirty-tree state and per-file source hashes go into `evidence/local/metadata.json`; benchmark and load outputs remain separate. Run metadata capture alongside each measurement series. Python reports include installed package versions; top-level requirements are pinned but transitive dependencies can change, so retain the captured environment or lock it for a comparative publication.

## Interpretation

* `BenchmarkHTTP` measures a fresh HTTP request and request body plus framework handling. Its discard writer avoids ResponseRecorder buffering. `BenchmarkBindQuery` isolates binding of six scalar fields; `BenchmarkJSON` isolates serialization.
* The `net/http` fixture is a **minimal JSON baseline**, not a validated-framework equivalent. gfast additionally performs its framework work.
* FastAPI runs one uvicorn worker; Go server fixtures run with `GOMAXPROCS=1`. JSON and validation success workloads use similar bodies/constraints, but FastAPI has response-model validation, coercion and error-format differences. These are comparisons of named stacks, not a clean estimate of language/framework overhead. Huma and multicore comparisons remain future work.
* Load starts at scheduled arrival, not actual dispatch. The generator bounds concurrency at 64 with a 64-entry arrival queue, counts arrivals dropped when the queue is full, and includes queueing/scheduling delay in latency. p50/p95/p99 cover all completed requests; dropped arrivals have no latency sample and must be read beside those percentiles. It is a small inspectable harness, not a replacement for a calibrated load generator.
* Local same-host runs are smoke evidence. Client CPU, timer resolution, OS scheduling, warmup, thermal state and background work can dominate. For publishable claims, use a separate client host, controlled CPU quotas, repeated paired samples, and record hardware/kernel/toolchain/configuration.
* Shared CI uploads raw benchmarks, but does not fail builds on noisy timing thresholds. The allocation budget is deterministic enough to gate. Establish reference-runner baselines before enabling P02/P03 timing gates.

## Profiles and stress work

`go run ./tools/benchserver -profile 127.0.0.1:6060` exposes a separate local pprof listener. Collect CPU, heap and execution trace during representative load. Add mutex/block profiling only with explicitly enabled runtime sampling and label its overhead.

For each workload, find the saturation knee, then measure at 25/50/75/100/125% of that load. Plot successful throughput, p99, drops/errors, CPU, RSS, post-GC heap and goroutines. Include a return to low load to measure recovery. Add 30-minute soaks and slow clients before claiming stable resource bounds; those are open P04–P06 work, not established by the short local suite.

Before/after comparisons should use identical harnesses and workloads on alternating revisions with at least ten samples and statistical intervals (for example `benchstat`). Report allocation changes separately from timing. Five sequential local samples can locate an optimization, but cannot establish a universal speedup.
