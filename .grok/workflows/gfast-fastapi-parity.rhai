let meta = #{
    name: "gfast-fastapi-parity",
    description: "Build the FastAPI surface gfast is missing, including sessions, CSRF, an OAuth server, and WebSockets",
    when_to_use: "Fill in FastAPI parity on gfast: validation, responses, security, OAuth, sessions, CSRF, WebSockets, OpenAPI, middleware, and the test client.",
    phases: [
        #{ title: "Bind", detail: "parameters, forms, files, validation" },
        #{ title: "Respond", detail: "status, headers, streams, files" },
        #{ title: "Secure", detail: "optional auth and cookie keys" },
        #{ title: "OAuth", detail: "authorization server and Swagger exchange" },
        #{ title: "Socket", detail: "WebSocket routes" },
        #{ title: "Describe", detail: "OpenAPI components and metadata" },
        #{ title: "Wrap", detail: "middleware, CORS, gzip, hosts" },
        #{ title: "Session", detail: "optional signed cookie sessions" },
        #{ title: "CSRF", detail: "origin, fetch metadata, and synchronizer tokens" },
        #{ title: "Route", detail: "HEAD, errors, mount, static" },
        #{ title: "Client", detail: "cookies, redirects, lifespan state" },
        #{ title: "Prove", detail: "gofmt and go test" },
    ],
};

fn rules() {
    let s = "";
    s += "Repository: /Users/reuben/projects/gfast-api. Module github.com/pyrex41/gfast. Go 1.27. ";
    s += "Read the code with read_file and grep before editing. Match the style of the file you touch. ";
    s += "No third-party Go modules. encoding/json/v2 stays the only JSON implementation. ";
    s += "Handlers stay func(ctx context.Context, in *In) (*Out, error). ";
    s += "Dependencies stay named gfast.Dep values. Do not add anonymous Depends or by-type field injection. ";
    s += "Do not replace net/http.ServeMux. ";
    s += "Existing tests must keep passing. When you intentionally change a response, update the test in the same change. ";
    s += "Run gofmt on files you edit. Do not commit or push. ";
    s += "Do not build any of these, even if a FastAPI doc shows them: ";
    s += "ORJSON or UJSON; Jinja or any template engine; HTTP digest; OpenID Connect discovery; ";
    s += "ReDoc; a gfast CLI or file reloader; use_cache=False; a yield dependency that can edit the response; ";
    s += "async handler signatures; BackgroundTasks argument lists (closures already capture arguments); ";
    s += "Pydantic field_validator or model_validator DSLs; discriminated-union schema generation; ";
    s += "validation_alias and serialization_alias as separate from the json tag; default_factory; ";
    s += "response_model_exclude, exclude_unset, and exclude_none as a runtime filter (json omitempty and a separate struct are enough); ";
    s += "two JSON bodies from one request; path parameters that contain slashes; a second trailing-slash redirect on top of ServeMux; ";
    s += "automatic rejection of bearer tokens for missing scopes (the provider already receives Bearer.Scopes and decides). ";
    s += "Sessions, the OAuth authorization server, WebSockets, and the Swagger OAuth redirect are in scope. They are separate phases. Do not invent a third-party module for them. ";
    s
}

fn run_phase(title, detail) {
    phase(title);
    log(title);
    let prompt = rules();
    prompt += detail;
    prompt += " When you finish, summarize files changed and tests you ran.";
    let result = agent(prompt, #{ label: title, capability_mode: "all" });
    if result == () || result.success != true {
        log(title + " failed");
        complete(#{ ok: false, phase: title });
    }
}

run_phase("Bind",
    "Implement opt-in request binding and validation. "
    + "Required query, header, and cookie fields use required:\"true\" and return 422 when absent. Omitted fields without that tag stay the zero value. "
    + "default:\"...\" tags fill a missing scalar. "
    + "A slice query or header field binds every value, not only the first. "
    + "form:\"name\" fields and file:\"name\" fields read multipart or urlencoded form bodies with the standard library. "
    + "A JSON body stays one body: the field named Body, or, when there is no Body field, the json-tagged fields that are not params or dependencies. "
    + "The doc tag becomes the OpenAPI description for that parameter or property. "
    + "OpenAPI parameter schemas use the Go kind (integer, number, boolean, string, array), not string for every parameter. "
    + "Enforce struct tags gt, ge, lt, le, pattern, minItems, maxItems, and enum. format tags date-time, uuid, email, and uri validate the string. "
    + "Unknown JSON members stay rejected unless the struct says extra:\"allow\". "
    + "A Validate() error method on a request struct runs after binding. "
    + "422 responses stay application/problem+json and keep a detail string. Add an errors array of objects with loc, type, and msg. "
    + "Update parity tests and gfast tests for any new 422 shape without dropping the detail string they already check.");

run_phase("Respond",
    "Implement success responses that FastAPI handlers expect, in Go. "
    + "A handler may set a dynamic status, headers, and cookies through a value stored on the request context, applied when the response is written. Registration-time gfast.Status still works. nil, nil stays 204. "
    + "An option declares extra OpenAPI responses. "
    + "If the output struct has Validate() error, run it before writing JSON. A failure is 500 with the fixed unexpected-error detail, not 422. "
    + "Returning an io.Reader as the body streams with http.Flusher when the client supports it. Add a small SSE helper on top of that. "
    + "Add a file response helper that uses http.ServeContent. "
    + "Add a redirect helper. "
    + "A string or []byte body with an explicit content type can be text/html. Do not add a template engine. "
    + "Register HEAD routes. App.Request on HEAD returns an empty body and the headers the GET handler would have produced.");

run_phase("Secure",
    "Extend credential readers. "
    + "Add an optional mode for Bearer, Basic, and API keys: a missing credential is the zero value and the handler runs; a present but malformed credential is still 401. "
    + "Add APIKeyCookie. "
    + "Keep scope values on Bearer and in the OpenAPI operation. Do not reject tokens inside the framework. "
    + "Leave the authorization server and the Swagger redirect to the OAuth phase.");

run_phase("OAuth",
    "Build an optional OAuth 2.1 authorization server in this process, standard library only. "
    + "The app opts in by registering clients and a function that checks a user's password or session. No server is mounted unless that option is set. "
    + "Implement the authorization endpoint, the token endpoint, authorization code with PKCE S256, refresh tokens, and the client-credentials grant. "
    + "Implement the password grant only when the app supplies a password checker, so Swagger UI's password flow can obtain a token. "
    + "Access tokens are bearer tokens that gfast.Bearer can verify through a validator the server installs. "
    + "Vendor swagger-ui oauth2-redirect.html and serve it at /docs/oauth2-redirect. "
    + "Configure the bundled Swagger UI so oauth2RedirectUrl is that path, and the default security scheme points at this server's authorization and token URLs when the server is enabled. "
    + "The redirect page must complete Swagger UI's popup handshake, and the token endpoint must exchange the authorization code, so Authorize in /docs finishes with a bearer token. "
    + "Store authorization codes and refresh tokens in memory. Document that a process restart drops them. "
    + "Do not implement OpenID Connect discovery, dynamic client registration, or the device-code grant. "
    + "Cover the code exchange and an invalid PKCE verifier with tests that use App.Request or httptest.");

run_phase("Socket",
    "Add WebSocket routes without a third-party module. "
    + "Implement the RFC 6455 pieces we need: upgrade, client masking, text and binary frames, ping and pong, close codes, and a maximum message size. Reject extensions and compression. "
    + "The registration shape is app.WebSocket(path, handler). The handler reads and writes on a connection value tied to the request context. "
    + "Dependencies and path parameters for that route work the same way as HTTP routes. "
    + "httptest.ResponseRecorder cannot hijack. Test the upgrade with httptest.NewServer and a small client written with the same code. "
    + "A failed upgrade is a normal HTTP error, not a half-open socket.");

run_phase("Describe",
    "Extend the OpenAPI 3.1 document. "
    + "Named structs go in components.schemas and are referenced with $ref from operations. "
    + "Support example tags, a Deprecated option, ExternalDocs, Servers, tag descriptions, IncludeInSchema(false), and an OperationID override. "
    + "Add a hook that can edit the document after routes are registered and before /openapi.json is served. "
    + "Accept caller-supplied webhook and callback fragments and place them on the document. Do not invoke them. "
    + "Write parameter and property descriptions from the doc tag. "
    + "An option can disable /docs and /openapi.json.");

run_phase("Wrap",
    "Add middleware as func(http.Handler) http.Handler, registered with Use, outside the router and inside CORS when CORS is set. "
    + "Extend CORS with credentials, exposed headers, max age, and origin patterns. An empty origin list may echo any origin only when credentials are off. Allow-Credentials requires an explicit origin list and must not reflect an arbitrary Origin. "
    + "Add gzip using compress/gzip. Do not compress a response that is already encoded. Do not compress event streams. "
    + "Add a trusted-host check and an HTTPS redirect option. "
    + "Leave signed cookie sessions to the Session phase.");

run_phase("Session",
    "Add optional signed-cookie sessions, off unless gfast.Sessions is passed to New. "
    + "The cookie holds an HMAC-signed JSON map. Use crypto/hmac and encoding/json. No server-side session store and no third-party module. "
    + "Defaults are HttpOnly, SameSite=Lax, and a path of /. Options cover Secure, MaxAge, SameSite=Strict, and SameSite=None. SameSite=None requires Secure. "
    + "Handlers get and set session values through the request context. "
    + "A missing or bad signature is an empty session, not a 500. "
    + "Leave CSRF enforcement to the CSRF phase. "
    + "Test that a value set on one response is readable on the next request that sends the cookie, and that a tampered cookie is ignored.");

run_phase("CSRF",
    "Add CSRF protection that is on by default when sessions are enabled, with explicit ways to tighten or skip it. Standard library only. "
    + "Apply checks only to POST, PUT, PATCH, and DELETE requests that present the session cookie. Bearer-only requests, safe methods, and routes marked gfast.SkipCSRF are unchanged. "
    + "Default mode uses Fetch Metadata and Origin. Reject Sec-Fetch-Site: cross-site. If that header is absent, reject an Origin or Referer whose host is not this request's host and not a host passed to gfast.CSRFOrigins. A browser request with no Origin, no Referer, and Sec-Fetch-Site: cross-site is a 403 problem+json. A non-browser client that sends neither Origin nor Sec-Fetch-Site still passes this default, so curl with the cookie keeps working. "
    + "gfast.CSRFStrict also rejects Sec-Fetch-Site: same-site, which is the subdomain case. "
    + "gfast.CSRFToken adds a synchronizer token stored in the session and mirrored in a non-HttpOnly cookie so same-origin JavaScript can read it. Unsafe cookie requests must echo it in the X-CSRF-Token header or a csrf_token form field. Compare in constant time. A missing or wrong token is 403. Expose the current token to handlers. "
    + "gfast.NoCSRF turns the checks off for the app. SkipCSRF turns them off for one route. "
    + "Token mode can be combined with the default and with CSRFStrict. "
    + "Tests: a cross-site fetch metadata header is 403; a same-origin Origin is allowed; curl with the cookie and no browser headers is allowed in the default mode; CSRFStrict rejects same-site; CSRFToken rejects a missing token and accepts the token from the session; SkipCSRF allows the cross-site request; a bearer request with no session cookie is not checked.");

run_phase("Route",
    "Unmatched paths and wrong methods return application/problem+json with 404 and 405, including an Allow header on 405. "
    + "Add Mount(prefix, http.Handler) and Static(prefix, directory) using the standard library file server. "
    + "Do not add slash-capturing path parameters. Do not add a trailing-slash redirect beyond ServeMux.");

run_phase("Client",
    "Extend the test client. "
    + "A client value keeps a cookie jar across requests and can follow redirects up to a small limit. "
    + "It can run OnStart before requests and OnStop when closed. "
    + "App.Request stays a single shot with no jar. "
    + "Add an exported way to read the current *http.Request from context, and a mutable app state map that OnStart hooks can fill and handlers can read.");

run_phase("Prove",
    "Run gofmt -w on the Go files in the module and go test ./... . "
    + "Fix failures that this parity work caused. Do not delete a test to make it pass. "
    + "Do not add a third-party module. "
    + "Report the test result and any FastAPI behavior you could not implement inside the rules.");

complete(#{ ok: true });
