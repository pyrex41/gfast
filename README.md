# gfast

A small Go API framework on the standard library. You write a function and a struct. gfast binds the request, checks `minLength` and `maxLength`, writes the JSON, and publishes OpenAPI at `/openapi.json` and Swagger UI at `/docs`. It has no third-party Go dependencies. Swagger UI 5.34.1 is included in the binary, under the Apache 2.0 license.

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

- Path, query, header, cookie, and JSON body binding. `encoding/json/v2` rejects unknown fields, duplicate names, and invalid UTF-8. `minLength` and `maxLength` return 422 problem details.
- Dependencies filled from `gfast:"dep=Name"` fields before the handler runs. Extra provider parameters are dependencies matched by type.
- `Bearer`, `Basic`, `APIKeyHeader`, and `APIKeyQuery`. Taking `Bearer` or `Basic` as a provider parameter attaches that security scheme. `BearerAuth` and `BasicAuth` are the same dependencies when a group needs `Require`.
- `Require` on an app or a group.
- `Override` for tests, and `Request` so tests do not open a port.
- `Background` after the response is written, then `io.Closer` on dependency values, in reverse order.
- `OnStart` and `OnStop`. `Run` stops on SIGINT and SIGTERM.
- `CORS(origins...)`.
- OpenAPI 3.1 at `/openapi.json` and Swagger UI at `/docs`, served by the app.

Handlers are `func(ctx context.Context, in *In) (*Out, error)`. Return `nil, nil` for 204. Set the success status with `gfast.Status`. Put a JSON body in a field named `Body`. `gfast.Get(app, ...)` still works when the router is an interface.

## What this is not

gfast does not ship a database, an OAuth server, or a full JSON Schema validator. The items example checks a fixed dev token.
