# gfast

A small Go API framework on the standard library. You write a function and a struct. gfast binds the request, checks struct-tag constraints, writes the JSON, and publishes OpenAPI at `/openapi.json` and Swagger UI at `/docs`. It has no third-party Go dependencies. Swagger UI 5.34.1 is included in the binary, under the Apache 2.0 license.

Go 1.27 can put type parameters on a method, so a route hangs off the app. The part that matches FastAPI's `Depends` is a named provider: auth, a database session, or anything else you would otherwise stuff into middleware and pull back out of `context`.

```go
var CurrentUser = gfast.Dep("CurrentUser", func(ctx context.Context, cred gfast.Bearer) (User, error) {
    user, err := users.FromToken(ctx, cred.Token)
    if err != nil {
        return User{}, gfast.Unauthorized("invalid token")
    }
    return user, nil
})

type GetItemInput struct {
    ID   string `path:"id" doc:"Item id"`
    User User   `gfast:"dep=CurrentUser"`
}

func main() {
    app := gfast.New(gfast.Title("Items"), gfast.Version("0.1.0"))
    app.Get("/items/{id}", GetItem, gfast.Summary("Get one item"))
    app.Run(":8080")
}

func GetItem(ctx context.Context, in *GetItemInput) (*Item, error) {
    return store.Find(ctx, in.ID, in.User.ID)
}
```

`CurrentUser` takes `gfast.Bearer`, so the operation is documented with `bearerAuth`. A missing token is 401. The same dependency runs once per request when several fields use it.

Require it for a whole group when the handler does not read the value:

```go
api := app.Group("/v1", gfast.Require(CurrentUser))
api.Get("/items", ListItems)
```

Tests replace a provider by identity. The replacement function is the one that runs, so a double that only takes `context` does not ask for a token:

```go
app.Override(CurrentUser, func(ctx context.Context) (User, error) {
    return User{ID: "u_test"}, nil
})
res := app.Request(http.MethodGet, "/items/1", nil)
```

A working example is `examples/items`.

## What you get

- Path, query, header, cookie, form, file, and JSON body binding. Query, header, and cookie fields are optional unless tagged `required:"true"`. `default` fills a missing scalar. A slice query or header field takes every value. `doc` is the OpenAPI description. `encoding/json/v2` rejects unknown fields unless the struct says `extra:"allow"`, and it rejects duplicate names and invalid UTF-8. Constraint tags and a `Validate() error` method return 422 problem details with an `errors` array.
- Dependencies filled from `gfast:"dep=Name"` fields before the handler runs. Extra provider parameters are dependencies matched by type.
- `Bearer`, `Basic`, `APIKeyHeader`, `APIKeyQuery`, and `APIKeyCookie`. `Optional` on those readers leaves a missing credential as the zero value and still returns 401 when the value was sent but does not parse. Taking `Bearer` or `Basic` as a provider parameter attaches the required scheme. `BearerAuth` and `BasicAuth` are those dependencies when a group needs `Require`. The optional names are `bearerAuthOptional`, `basicAuthOptional`, and the API key name with `_optional` appended. Route scopes stay on `Bearer` and on the `bearerAuth` operation. The framework does not reject a token for missing scopes. With `OAuthServer`, the server's validator checks the access token first and fills `Subject`, `ClientID`, and `TokenScopes`.
- `Require` on an app or a group.
- `Override` for tests, and `Request` so tests do not open a port. `Request` is one shot: it does not keep cookies, follow redirects, or run `OnStart`.
- `Client` keeps a cookie jar across requests and follows at most 10 same-host redirects (`301`, `302`, `303`, `307`, `308`). A redirect to another host is returned as-is. `301`, `302`, and `303` from a non-GET continue as GET without the body. `Start` runs `OnStart` before requests. `Close` runs `OnStop` when start succeeded. `FollowRedirects` can be set false.
- `Background` after the response is written, then `io.Closer` on dependency values, in reverse order.
- `OnStart` and `OnStop`. `Run` stops on SIGINT and SIGTERM. Both hooks receive the app state map on their context. `State` and `StateFrom` are that map. Handlers read it with `StateFrom`. `RequestFrom` returns the current `*http.Request`. The map is not safe for concurrent writes.
- `CORS(origins...)`. An origin of `*` allows every origin, and any other origin that contains `*` is a pattern. `AllowOriginPattern` adds a regular expression matched against the whole origin. `AllowCredentials`, `ExposeHeaders`, and `MaxAge` extend the same check. With no origins, every origin is echoed unless credentials are on. Credentials require a listed origin or a pattern and never echo an arbitrary origin.
- `Use` adds middleware of type `func(http.Handler) http.Handler`. It runs outside the router and inside CORS. The first middleware registered is the outermost. `Gzip` wraps it, so middleware sees the uncompressed response.
- `Gzip` compresses responses when the client accepts gzip. A response that already has a content encoding is left alone, and event streams are not compressed.
- A path that matches nothing is 404 `application/problem+json`. The same path with the wrong method is 405 problem+json and includes an `Allow` header. `Mount` serves an `http.Handler` under a prefix. `Static` serves a directory with the standard file server for GET and HEAD. The prefix is stripped. ServeMux redirects a request for the prefix without a trailing slash; gfast does not add another redirect.
- `TrustedHost` rejects a request whose host is not listed. `*` allows any host, and `*.example.com` allows that suffix. A listed `www` host redirects the apex host there. `HTTPSRedirect` sends plain HTTP to HTTPS.
- `Sessions` stores a JSON object in an HMAC-signed cookie. It is off unless that option is passed to `New`. CSRF checks are on for unsafe requests that send that cookie. See below.
- OpenAPI 3.1 at `/openapi.json` and Swagger UI at `/docs`, served by the app. `Docs(false)` leaves both unregistered. A named struct is one `components.schemas` entry, and operations point at it with `$ref`. Anonymous structs stay inline. `doc` is the parameter or property description. `example` is the schema example. `Deprecated`, `OperationID`, `ExternalDocs`, `Servers`, `TagDescription`, and `IncludeInSchema` fill the document. `Webhooks` and `Callbacks` copy caller-supplied fragments onto it and do not call them. `OpenAPIHook` can edit the document after routes are registered and before it is served.
- Optional OAuth 2.1 authorization server. See below.

Handlers are `func(ctx context.Context, in *In) (*Out, error)`. Return `nil, nil` for 204. Set the success status with `gfast.Status`. Put a JSON body in a field named `Body`. `gfast.Get(app, ...)` still works when the router is an interface.

## Sessions

`Sessions` is off unless it is passed to `New`. The cookie is named `session`. Its value is an HMAC-signed JSON object. Nothing is stored on the server. Handlers read and write the map from `SessionFrom`. The cookie is sent only when the map changed. Clearing every key deletes it.

The cookie defaults to `HttpOnly`, `SameSite=Lax`, and `Path=/`. `Secure` sets the Secure attribute. `MaxAge` is the lifetime in seconds. Zero omits `Max-Age`, so the browser drops it when the session ends. `SameSite` accepts Lax, Strict, and None. None requires `Secure`. A missing cookie or a bad signature is an empty map, not a 500.

CSRF checks run only when sessions are on. They apply to `POST`, `PUT`, `PATCH`, and `DELETE` that send the `session` cookie. Safe methods are not checked. A request with no session cookie is not checked, including a bearer request. `NoCSRF` turns the checks off for the app. `SkipCSRF` turns them off for one route, and a group passes that on.

The default check uses Fetch Metadata and the origin. `Sec-Fetch-Site: cross-site` is 403 problem+json. When that header is absent, the `Origin` host, or the `Referer` host if there is no `Origin`, must be this request's host or a host passed to `CSRFOrigins`. A client that sends neither `Origin` nor `Sec-Fetch-Site`, such as curl with the cookie, is allowed. `CSRFStrict` also rejects `Sec-Fetch-Site: same-site`.

`CSRFToken` stores a synchronizer token in the session and copies it to a `csrf_token` cookie that is not `HttpOnly`, so same-origin JavaScript can read it. An unsafe cookie request must send that value in the `X-CSRF-Token` header or a `csrf_token` form field. The comparison is constant time. A missing or wrong token is 403. `CSRFTokenFrom` returns the current token. Token mode can be combined with the default checks and with `CSRFStrict`.

```go
app := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "change-me"}))

func Login(ctx context.Context, in *LoginInput) (*struct{}, error) {
    gfast.SessionFrom(ctx)["user"] = in.Name
    return &struct{}{}, nil
}
```

## OAuth 2.1

`OAuthServer` mounts an authorization server in this process. Nothing is mounted unless that option is set. Register clients, and a function that checks a password, a session, or both.

- `GET` and `POST /oauth/authorize` issue an authorization code. PKCE S256 is required. `POST /oauth/token` exchanges the code, rotates a refresh token, and serves the client-credentials grant. Client credentials requires a client secret. The password grant is offered only when `Password` is set, so Swagger UI's password flow can obtain a token.
- Access tokens are bearer tokens signed by this process. `Bearer` verifies them through the validator the server installs.
- Authorization codes and refresh tokens are stored in memory. A process restart drops them. The signing key is in memory as well, so access tokens from before the restart no longer verify. Codes last one minute, access tokens one hour, and refresh tokens 24 hours. A refresh token works once. `CodeTTL`, `AccessTTL`, and `RefreshTTL` override those lifetimes. Zero keeps the default. A negative duration is already expired.
- Swagger UI uses `oauth2RedirectUrl` `window.location.origin + "/docs/oauth2-redirect"`. That page is the vendored Swagger UI 5.34.1 handshake (`oauth2-redirect.html` and `oauth2-redirect.js`). When the server is enabled, `bearerAuth` is an OAuth 2.0 scheme whose authorization and token URLs are `/oauth/authorize` and `/oauth/token`, and PKCE is turned on. The docs redirect on the request host is accepted in addition to each client's registered redirect URIs, so Authorize in `/docs` can finish with a bearer token. A registered path such as `/docs/oauth2-redirect` matches that path on the request host.
- OpenID Connect discovery, dynamic client registration, and the device-code grant are not implemented.

```go
app := gfast.New(gfast.OAuthServer(gfast.OAuthConfig{
    Clients: []gfast.OAuthClient{{
        ID:           "docs",
        RedirectURIs: []string{"/docs/oauth2-redirect"},
    }},
    Scopes: map[string]string{"items:read": "Read items"},
    Password: func(ctx context.Context, username, password string) (string, error) {
        if username == "ada" && password == "secret" {
            return "user-ada", nil
        }
        return "", gfast.Unauthorized("invalid username or password")
    },
}))
```

## What this is not

gfast does not ship a database or a full JSON Schema validator. The items example checks a fixed dev token. The authorization server above is optional and in-memory.
