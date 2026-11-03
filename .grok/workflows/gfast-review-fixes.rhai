let meta = #{
    name: "gfast-review-fixes",
    description: "Fix the ten open pyrex41/gfast review issues, with Hegel properties, then prove the suite",
    when_to_use: "Implement GitHub issues 1 through 10 on gfast: mount auth, binding, WebSocket origin, sessions, dependencies, OpenAPI, OAuth storage, gzip, body limits, and recursive inputs.",
    phases: [
        #{ title: "Mount", detail: "issue 1: Require and CSRF on Mount and Static" },
        #{ title: "Bind", detail: "issues 2 and 10: field ownership and recursive inputs" },
        #{ title: "Origin", detail: "issue 3: WebSocket Origin" },
        #{ title: "Gzip", detail: "issue 8: explicit gzip q=0" },
        #{ title: "Session", detail: "issue 4: signed session expiry" },
        #{ title: "Deps", detail: "issue 7: repeatable credential constructors" },
        #{ title: "Spec", detail: "issue 5: OpenAPI matches JSON" },
        #{ title: "Tokens", detail: "issue 6: bound OAuth code and refresh storage" },
        #{ title: "Limit", detail: "issue 9: total body size" },
        #{ title: "Prove", detail: "gofmt, vet, test, and race" },
    ],
};

fn rules() {
    let s = "";
    s += "Repository: /Users/reuben/projects/gfast-api. Module github.com/pyrex41/gfast. Go 1.27. Public repo github.com/pyrex41/gfast. ";
    s += "Read the current source with read_file and grep before editing. Match the style of the file you touch. ";
    s += "Runtime dependencies stay the standard library. Hegel (hegel.dev/go/hegel) is test-only. encoding/json/v2 stays the only JSON implementation. ";
    s += "Handlers stay func(ctx context.Context, in *In) (*Out, error). Dependencies stay named gfast.Dep values. Do not replace net/http.ServeMux. ";
    s += "Do not add WebSocket compression, OpenID Connect, a second JSON library, or app-scoped dependency containers. ";
    s += "Existing tests must keep passing. When you intentionally change a response, update the test in the same change. ";
    s += "New shrinking properties go through the existing prop helper in hegel_test.go, which already uses hegel.WithDatabase(\"hegel-db\"). ";
    s += "Put new properties in hegel_review_test.go unless they extend a property that already draws the same input. ";
    s += "Each property draws inputs and shrinks. Keep one deterministic regression for the minimal counterexample named in the issue. ";
    s += "Assert observable results against an independent oracle. Do not copy a production predicate into the test and compare the code to itself. ";
    s += "Run gofmt on files you edit. Do not commit or push. Do not close GitHub issues. ";
    s
}

fn run_phase(title, detail) {
    phase(title);
    log(title);
    let prompt = rules();
    prompt += detail;
    prompt += " When you finish, name the files you changed, the contract you implemented, and the tests you ran.";
    let result = agent(prompt, #{ label: title, capability_mode: "all" });
    if result == () || result.success != true {
        log(title + " failed");
        complete(#{ ok: false, phase: title });
    }
}

run_phase("Mount",
    "Fix GitHub issue 1. Mount and Static currently register on ServeMux and skip inherited Require, scopes, and CSRF. "
    + "Wrap mounted handlers and the static file server so a rejecting inherited dependency prevents the resource handler from running, and an unsafe method that fails CSRF returns 403 with zero mutations. "
    + "Honor SkipCSRF on the group. GET and HEAD static files stay method-limited as they are today. "
    + "Built-in /docs, /openapi.json, and /oauth routes stay outside a group's Require. Do not require a bearer for Swagger or the token endpoint because some other group uses Require. "
    + "Add a shrinking property that varies registration kind, nesting, credential state, method, Sec-Fetch-Site, and SkipCSRF. "
    + "A rejecting inherited dependency must leave the handler uncalled. A cross-site cookie mutation without a passing CSRF check must be 403. A valid request still runs the handler once.");

run_phase("Bind",
    "Fix GitHub issues 2 and 10 together. They share bind.go and dep.go. "
    + "Issue 2: flat JSON currently decodes into the whole input after path, query, header, and cookie values are set, so a body key can replace a transport value. "
    + "Give each field one source. Decode JSON only into JSON-owned fields. A body key that names a path, query, header, cookie, form, file, or dependency field is a 422 and must not change the transport or dependency value. "
    + "extra:\"allow\" still rejects that overwrite. Embedded fields and json aliases follow the same ownership. "
    + "Issue 10: walkInput and walkDepFields follow struct pointers with no active-path set, so a recursive input such as Node { Next *Node } can overflow the stack at registration. "
    + "If a type appears again on the active path, panic at registration with a short message that names the type. A type used twice under an acyclic tree must still register. "
    + "Do not walk a Body field as a transport container. encoding/json may still decode a finite recursive value inside Body. "
    + "Add shrinking properties over fixed fixtures: self-recursion, mutual recursion, recursion only under Body, a shared acyclic subtree, a conflicting body key, and a dependency field named in JSON. "
    + "Registration of a recursive input must finish with the documented panic. It must not hang. The conflicting body key must leave the handler uncalled.");

run_phase("Origin",
    "Fix GitHub issue 3. acceptWebSocket does not check Origin, so a foreign Origin completes the handshake. "
    + "Before hijack, accept a browser Origin only when its host is the request host or a host configured by a new app-level option, for example WebSocketOrigins. Compare hosts case-insensitively and treat an explicit default port as the same host. "
    + "A missing Origin is a non-browser client and is allowed, matching CSRF. null, a malformed Origin, and a foreign host are rejected with 403 and the handler does not run. "
    + "Add a shrinking property over scheme, host, port, and allowed origins. Use a real TCP handshake. A rejected origin never returns 101. An allowed origin completes one echo. "
    + "A valid session cookie must not authorize a foreign Origin.");

run_phase("Gzip",
    "Fix GitHub issue 8. acceptsGzip treats gzip;q=0, *;q=1 as acceptable because it keeps the maximum quality. "
    + "An explicit gzip entry wins over *. gzip;q=0 means do not compress even when the wildcard quality is higher. A lone * may still select gzip. "
    + "Malformed q values and duplicate gzip tokens need one documented behavior. Keep Vary behavior for negotiated responses. "
    + "Add a shrinking property over qualities, order, case, whitespace, and unrelated codings. The oracle is a small table you write in the test, not a copy of the production loop. "
    + "Send the header through the running app. When gzip is selected, the decompressed body equals the handler bytes. Cover a missing header, HEAD, and a 204.");

run_phase("Session",
    "Fix GitHub issue 4. openSession checks HMAC and JSON and stores no expiry, so a copied cookie outlives MaxAge. "
    + "Use a versioned signed envelope that includes an authenticated expiry. Enforce that expiry on read with time.Now. Do not add a sleep to the tests. "
    + "MaxAge greater than zero is both the cookie Max-Age and the server lifetime. MaxAge 0 remains a browser session with no server expiry. "
    + "Logout clears the cookie the browser will send next. It does not revoke a copy the client already kept. Do not add a session version or a server store. "
    + "A cookie from before this envelope, or a cookie with a bad signature, a bad version, or a tampered expiry, loads as an empty session. "
    + "Add a shrinking property that draws lifetime and how far a test clock would move. Implement the clock as a pure comparison of the signed expiry to time.Now in production, and in the property construct envelopes at known timestamps without sleeping. "
    + "Accept a cookie whose expiry is still in the future. Reject one whose expiry is now or earlier. A flipped MAC byte or a flipped expiry byte does not extend the life of the cookie.");

run_phase("Deps",
    "Fix the executed failure in GitHub issue 7 without replacing the process-global registry. Package-level Provide stays the model. Do not introduce per-app containers. "
    + "APIKeyHeader, APIKeyQuery, APIKeyCookie, Bearer, and Basic with the same name and the same options must return the existing dependency instead of panicking with duplicate dependency. "
    + "A second registration of a different provider function under the same name still panics. "
    + "Two apps in one process that use the same APIKeyHeader name must both run. Building the second app must not change the first app's results. "
    + "Request memoization and Override stay keyed by the stable dependency identity. "
    + "Add a shrinking property that builds two apps, repeats the same credential constructor, and checks that a duplicate name does not panic and that each app still sees its own handler result.");

run_phase("Spec",
    "Fix GitHub issue 5. The OpenAPI schema disagrees with encoding/json. "
    + "time.Time is a string with format date-time. []byte and [N]byte are a string with format byte. A slice of a type other than byte stays an array. "
    + "omitempty and omitzero fields are not listed in required. A required:\"true\" JSON body field rejects a missing value at runtime with 422, and the document marks that field required. "
    + "Zero values, null, and absent keys stay distinct. An empty object does not satisfy a required body property. "
    + "On output schemas, a field named Body or RawBody is an ordinary JSON field when it has a json name. The input-wrapper meaning of Body stays only on the handler input. "
    + "Add a shrinking property that registers fixed fixture types, calls the route, and checks the response bytes against the rules above. Also fetch /openapi.json and check the schema types and required lists. "
    + "Do not shell out to an external JSON Schema package. Encode the expected schema facts in the test.");

run_phase("Tokens",
    "Fix GitHub issue 6. Authorization codes and refresh tokens stay in memory until that exact token is presented, including after expiry. "
    + "On issue and on consume, delete expired codes and expired refresh tokens. "
    + "Add OAuthConfig.MaxCodes and OAuthConfig.MaxRefresh. Zero means 1024. A negative value panics at startup. "
    + "After expired entries are removed, a new code or refresh token that would exceed the cap is refused. Do not evict a live token to make room. The HTTP status for that refusal is 503 with an oauth server_error body. "
    + "Single-use consumption, client binding, and redirect binding stay as they are. CodeTTL, AccessTTL, and RefreshTTL stay the lifetimes. Zero still means the default. A negative TTL is already expired and must be deleted by the sweep. "
    + "Add a shrinking property that issues several codes with a negative CodeTTL, then one live code, and checks that only the live code remains usable and that the stored count is bounded. "
    + "Do not sleep. Do not add a background goroutine.");

run_phase("Limit",
    "Fix GitHub issue 9. JSON decode reads an unbounded body, and ParseMultipartForm(32 << 20) is a spill threshold rather than a total cap. CSRF and OAuth form parsing read bodies too. "
    + "Add app-level MaxBodyBytes. Zero means 1 MiB. A negative value panics at startup. A route option of the same name overrides the app value for that route. "
    + "Reject a body larger than the limit with 413 problem+json before the handler runs. The check must not trust Content-Length alone: a short Content-Length with a longer body, and a chunked body, still stop at the limit. "
    + "Apply the same cap before JSON binding, form parsing, multipart parsing, CSRF token extraction, and the OAuth authorize and token forms. "
    + "A bearer check that does not read the body may run before the limit. Parsing the body past the limit is not allowed. One rejected request must not affect the next request. "
    + "Add a shrinking property over sizes just under, at, and just over the limit, using small limits and small buffers. Over-limit requests are 413 and the handler is not called. "
    + "Do not allocate multi-megabyte fixtures.");

run_phase("Prove",
    "This is the last phase. Earlier phases changed the library. Do not add features. "
    + "Run gofmt -w on the Go files that are dirty. Then run go vet ./... . "
    + "Then run go test -count=1 -timeout 300s ./... . "
    + "Then run go test -race -count=1 -timeout 300s ./... . "
    + "If a test fails because a new property found a real bug, fix the bug and keep the property. "
    + "If a test fails because a property contradicts the contract written in an earlier phase, fix the property so it matches that contract. "
    + "Report vet, test, and race results. List any issue from 1 through 10 that is still open in the code.");

complete(#{ ok: true });
