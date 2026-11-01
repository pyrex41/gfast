let meta = #{
    name: "gfast-hegel",
    description: "Add Hegel property tests for gfast as it exists and for the FastAPI parity surface",
    when_to_use: "Property-test gfast with Hegel, including behavior that the parity workflow is adding.",
    phases: [
        #{ title: "Install", detail: "add the Hegel test module and learn its API" },
        #{ title: "Current", detail: "properties that must pass today" },
        #{ title: "Parity", detail: "properties for the FastAPI surface" },
        #{ title: "Prove", detail: "go test until the current properties pass" },
    ],
};

fn rules() {
    let s = "";
    s += "Repository: /Users/reuben/projects/gfast-api. Module github.com/pyrex41/gfast. Go 1.27. ";
    s += "Read the code with read_file and grep before writing a property. A property you have not traced in the source is not a test. ";
    s += "Hegel is test-only. Import hegel.dev/go/hegel from package gfast_test. Do not import it from non-test files. ";
    s += "After go get, read the module README and Go docs in the module cache so the API you call is the one that was downloaded. ";
    s += "If the module does not build on darwin/arm64, stop and report the error. Do not write a substitute generator library. ";
    s += "Properties must be falsifiable and must shrink. Prefer generators over a single hand-written example. ";
    s += "Do not weaken or delete existing tests. Do not commit or push. ";
    s += "A property whose API is not in the tree yet goes in hegel_pending_test.go behind a line that skips, with the reason naming the missing symbol. It must still compile. ";
    s += "Do not test behavior from this skip list, and do not treat its absence as a bug: ";
    s += "ORJSON or UJSON; Jinja; HTTP digest; OpenID Connect discovery; ";
    s += "ReDoc; a gfast CLI; use_cache=False; a yield dependency that can edit the response; ";
    s += "async handler signatures; BackgroundTasks argument lists; a Pydantic validator DSL; discriminated unions; ";
    s += "separate validation and serialization aliases; default_factory; response_model exclude filters; ";
    s += "two JSON bodies; slash-capturing paths; a second trailing-slash redirect; ";
    s += "framework-side rejection of bearer tokens for missing scopes. ";
    s += "Sessions, the OAuth server, WebSockets, and the Swagger redirect handshake are in scope when their APIs exist. ";
    s
}

fn run_phase(title, detail) {
    phase(title);
    log(title);
    let prompt = rules();
    prompt += detail;
    prompt += " When you finish, summarize the properties and the test command result.";
    let result = agent(prompt, #{ label: title, capability_mode: "all" });
    if result == () || result.success != true {
        log(title + " failed");
        complete(#{ ok: false, phase: title });
    }
}

run_phase("Install",
    "Add hegel.dev/go/hegel with go get at the latest version that builds. "
    + "Run go test ./... once before writing new tests and record the result. "
    + "Write a short comment at the top of the new test file naming the Hegel version from go.mod.");

run_phase("Current",
    "Add Hegel tests for behavior that is already implemented. Each property draws inputs. Cover at least: "
    + "an acyclic dependency graph runs each provider at most once per request however many fields point at it, and a cycle panics at registration; "
    + "Override replaces that provider and the providers it requests, and a second app keeps the original; "
    + "a body or parameter that fails binding does not run dependencies or the handler; "
    + "a gfast dep field never appears as an OpenAPI parameter or in requestBody, and the operation security object matches the schemes of the dependencies it uses; "
    + "a plain error is 500 with the fixed detail and does not contain the error text; a status error keeps its status and message; "
    + "background functions run after the handler and before io.Closer values, including on a nil, nil response; "
    + "two overlapping requests do not share a memoized dependency value; "
    + "minLength and maxLength count runes; unknown JSON members, duplicate names, and invalid UTF-8 are rejected; "
    + "the first of several query values binds to a scalar, and a documented path parameter is required in OpenAPI. "
    + "Run go test ./... and fix the new tests until these properties pass.");

run_phase("Parity",
    "Read the tree again. For each behavior below, write a Hegel property if the API exists, or a compiling skipped test if it does not. "
    + "Required query, header, and cookie tags return 422 and do not run the handler. Fields without the tag still use the zero value. "
    + "Slice query and header fields bind every generated value. "
    + "gt, ge, lt, le, pattern, minItems, maxItems, enum, and format reject bad drawn values and accept good ones. "
    + "extra allow accepts an unknown member; the default rejects it. Validate() error fails the request. "
    + "422 bodies have detail plus an errors array of loc, type, and msg. "
    + "Dynamic status, headers, and cookies set from the handler are the ones the client observes. "
    + "HEAD yields an empty body and the GET headers. "
    + "Optional credentials yield the zero value; a malformed credential is 401. "
    + "APIKeyCookie reads the cookie. An oauth2 scheme appears in components.securitySchemes with the URLs the caller passed. "
    + "Named structs are $ref components. Deprecated, servers, external docs, examples, and IncludeInSchema(false) show in the document. "
    + "A disabled docs option makes /docs and /openapi.json 404. "
    + "Use middleware runs around the handler. CORS credentials, exposed headers, and max age are present only when configured. Gzip decodes. A foreign host is rejected. "
    + "404 and 405 are problem+json. Mount and Static serve a generated file. "
    + "The cookie-jar client sends a cookie set by the previous response. Redirect following stops at the limit. OnStart runs before the first client request. "
    + "With sessions enabled, a generated value stored in the session survives a second request that echoes the cookie, and a flipped signature byte yields an empty session. "
    + "A session cookie plus Sec-Fetch-Site: cross-site is 403 on an unsafe method. The same request with a same-origin Origin is allowed. A request with the cookie and no browser headers is allowed in the default mode. CSRFStrict rejects same-site. CSRFToken rejects a bad token and accepts the issued one. SkipCSRF allows the cross-site case. A bearer request without the session cookie is not rejected as CSRF. "
    + "With the OAuth server enabled, a valid authorization code and PKCE verifier exchange for a bearer token, and a wrong verifier does not. The docs page points oauth2RedirectUrl at /docs/oauth2-redirect. "
    + "A WebSocket client and server exchange one drawn text payload and one binary payload, and a frame larger than the limit is closed. "
    + "Do not invent a passing test for an API that is absent.");

run_phase("Prove",
    "Run gofmt -w on the test files you added and go test ./... . "
    + "Current-behavior properties must pass. Skipped parity tests must say which symbol is missing. "
    + "Fix only the Hegel tests, unless a test found a real bug in existing behavior. For a real bug, fix the library and add the shrinking counterexample to the test as a comment. "
    + "Report pass, skip, and fail counts.");

complete(#{ ok: true });
