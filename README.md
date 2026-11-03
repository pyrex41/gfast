# gfast

**FastAPI-style APIs in Go: typed handlers, validation, dependency injection and OpenAPI, built on `net/http`.**

Write a function and a struct. gfast binds the request, checks constraints, writes JSON and serves interactive docs. No third-party **runtime Go** dependencies; Hegel powers the property tests. Swagger UI is bundled in the binary.

## Start with one endpoint

Requires Go 1.27 (including generic methods and `encoding/json/v2`).

```sh
go get github.com/pyrex41/gfast
```

```go
package main

import (
    "context"
    "github.com/pyrex41/gfast"
)

type Item struct {
    Name  string `json:"name" required:"true" minLength:"1" maxLength:"80"`
    Count int    `json:"count" ge:"1" le:"100"`
}

func main() {
    app := gfast.New(gfast.Title("Items"))
    app.Post("/items", func(ctx context.Context, in *struct{ Body Item }) (*Item, error) {
        return &in.Body, nil
    })
    app.Run(":8080")
}
```

Send `{"name":"widget","count":3}` to `POST /items`. Explore `/docs` and `/openapi.json`. See [the complete items application](examples/items) for authentication and tests.

## Included

* Typed request/response handling, field constraints and structured errors.
* Named dependency providers, per-request memoization, resource cleanup and test overrides.
* Route groups, middleware and standard `http.Handler` interoperability.
* OpenAPI and bundled Swagger UI.
* Sessions, CSRF, credential helpers and an optional in-memory OAuth server.
* Multipart uploads, streams/SSE, WebSockets and an in-process test client.

The [behavioral reference](docs/reference.md) explains configuration, semantics and limitations. Configure apps before concurrent serving. The OAuth store is process-local; schema validation is a supported subset, not a full JSON Schema implementation.

## Confidence you can inspect

We organize development around [31 explicit invariants and objectives](docs/invariants.md), with executable evidence and named gaps:

| Evidence | Inspect / reproduce |
|---|---|
| Hegel properties, failure-path contracts and race checks | `go test -race ./...` |
| Coverage-guided parser fuzzing | [Fuzz targets](fuzz_test.go) and [CI](.github/workflows/quality.yml) |
| Deliberate fault injection | `python3 scripts/mutate.py` |
| Independent OpenAPI/schema checks | [Conformance fixture](scripts/conformance.py) |
| OAuth state-machine model and negative control | [TLA+/TLC scope](formal/README.md) |
| Benchmarks, profiles and real-server workloads | [Performance methodology](docs/performance.md) |

See the [measured evidence and remaining work](docs/evidence.md). The formal model is deliberately scoped; it is not a proof of the whole Go framework. Performance results name their workload and environment rather than claiming a universal ranking.

## Contribute against a contract

Choose an ID in [the invariant catalog](quality/invariants.json), add a failing scenario or independent oracle, fix it, and attach the relevant evidence. Performance changes must preserve correctness contracts. The [iteration loop](docs/invariants.md#iteration-loop) and [usability protocol](docs/usability.md) define how we improve both implementation and developer experience.
