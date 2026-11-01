let meta = #{
    name: "gfast-hegel-followup",
    description: "Turn the skipped Hegel properties into real tests once the parity build has landed",
    when_to_use: "After gfast-fastapi-parity finishes, replace hegel_pending_test.go skips with shrinking properties for the new APIs.",
    phases: [
        #{ title: "Survey", detail: "map each skip to the API that landed" },
        #{ title: "Properties", detail: "replace skips with shrinking tests" },
        #{ title: "Prove", detail: "gofmt and go test" },
    ],
};

fn rules() {
    let s = "";
    s += "Repository: /Users/reuben/projects/gfast-api. Module github.com/pyrex41/gfast. Go 1.27. ";
    s += "Hegel is already a test-only dependency. Import hegel.dev/go/hegel only from package gfast_test. Do not add another test framework. ";
    s += "Read the current source before asserting a signature. The parity build may have named a function differently from hegel_pending_test.go. ";
    s += "Do not weaken or delete a property that already passes in hegel_test.go, hegel_props_test.go, hegel_api_test.go, or hegel_io_test.go. ";
    s += "Do not commit or push. Do not start this work by rewriting the library. A mismatch between a property and the code is a failing test or a skip that names the missing symbol, unless the behavior is a clear bug in code this follow-up is allowed to touch. ";
    s += "Properties must draw inputs and shrink. A single hand-written example is not enough when the input is a string, a number, a header, or a cookie. ";
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

run_phase("Survey",
    "Read hegel_pending_test.go and the public gfast API. "
    + "For each skipped test, record the real function or option that now exists, or record that it is still absent. "
    + "Also look for WebSocket, Sessions, CSRF, CSRFStrict, CSRFToken, SkipCSRF, NoCSRF, Use, Gzip, TrustedHost, Mount, Static, and a cookie-jar test client. "
    + "Do not edit files in this phase. Return a list of skip name, symbol found or missing, and the property to write.");

run_phase("Properties",
    "Replace every skipped test in hegel_pending_test.go whose API now exists with a real Hegel property. Remove the skip. Keep a compiling skip only when the symbol is still absent, and keep the reason. "
    + "Cover these behaviors when the API exists: "
    + "Named structs appear under components.schemas and operations use $ref. "
    + "Deprecated, Servers, ExternalDocs, and examples show in the document. IncludeInSchema(false) omits the route. Disabling docs makes /docs and /openapi.json 404. "
    + "Use middleware observes the request and the response. CORS AllowCredentials, ExposeHeaders, and MaxAge appear only when configured, and Allow-Credentials does not reflect an arbitrary Origin. "
    + "Gzip encodes a generated body and the decoded bytes match. A foreign Host is rejected by TrustedHost. "
    + "An unmatched path is 404 problem+json. The wrong method is 405 problem+json and includes Allow. "
    + "Mount and Static serve a generated file. "
    + "The cookie-jar client resends a cookie set by the previous response. Redirect following stops at the configured limit. "
    + "A generated session value survives the next request that echoes the signed cookie. A flipped signature byte yields an empty session. SameSite=None without Secure is rejected. "
    + "With sessions enabled, Sec-Fetch-Site: cross-site on an unsafe method is 403. A same-origin Origin is allowed. A request with the cookie and no browser headers is allowed in the default mode. "
    + "CSRFStrict rejects same-site. CSRFToken rejects a missing or wrong token and accepts the token that was issued. SkipCSRF and NoCSRF allow the cross-site case. A bearer request with no session cookie is not rejected as CSRF. "
    + "A WebSocket client and server exchange one drawn text payload and one binary payload. A frame larger than the limit is closed. A failed upgrade is an HTTP error. "
    + "Write the new tests in hegel_followup_test.go if hegel_pending_test.go would become a pile of unrelated helpers. Delete a pending test once its replacement exists so the suite does not skip and pass the same property.");

run_phase("Prove",
    "Run gofmt -w on the Hegel test files and go test -count=1 -timeout 300s ./... . "
    + "Existing properties must still pass. New properties for APIs that exist must pass. "
    + "If a new property finds a real bug, fix the library and leave the shrinking counterexample in a comment. "
    + "Report pass, skip, and fail counts, and list any pending skip that remains.");

complete(#{ ok: true });
