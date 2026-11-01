package gfast_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pyrex41/gfast"
)

type principal struct {
	ID string `json:"id"`
}

type item struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

var calls atomic.Int32

var currentUser = gfast.Dep("CurrentUser", func(ctx context.Context, cred gfast.Bearer) (principal, error) {
	calls.Add(1)
	if cred.Token != "secret" {
		return principal{}, gfast.Unauthorized("invalid token")
	}
	return principal{ID: "u1"}, nil
})

type session struct {
	closed atomic.Int32
}

func (s *session) Close() error {
	s.closed.Add(1)
	return nil
}

var sessions = gfast.Dep("Session", func(ctx context.Context) (*session, error) {
	return &session{}, nil
})

var userFromSession = gfast.Dep("UserFromSession", func(ctx context.Context, s *session) (sessionUser, error) {
	return sessionUser{ID: "sess"}, nil
})

var headerKey = gfast.APIKeyHeader("X-API-Key")
var queryKey = gfast.APIKeyQuery("api_key")

type cycleA struct{ N int }
type cycleB struct{ N int }

var cycleDepA = gfast.Dep("cycleA", func(ctx context.Context, v cycleB) (cycleA, error) {
	return cycleA{N: v.N}, nil
})
var cycleDepB = gfast.Dep("cycleB", func(ctx context.Context, v cycleA) (cycleB, error) {
	return cycleB{N: v.N}, nil
})

type sessionUser struct {
	ID string
}

func TestRouteValidationDocsAndStatus(t *testing.T) {
	app := gfast.New(gfast.Title("Items"), gfast.Version("0.1.0"))
	gfast.Get(app, "/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	}, gfast.Summary("Ping"))
	gfast.Post(app, "/items", func(ctx context.Context, in *struct {
		Body struct {
			Title string `json:"title" minLength:"2"`
		}
	}) (*item, error) {
		return &item{ID: "1", Title: in.Body.Title}, nil
	}, gfast.Status(http.StatusCreated))
	gfast.Delete(app, "/items/{id}", func(ctx context.Context, in *struct {
		ID string `path:"id"`
	}) (*struct{}, error) {
		return nil, nil
	})

	res := app.Request(http.MethodGet, "/ping", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("ping status %d body %s", res.Status, res.Body)
	}

	bad := app.Request(http.MethodPost, "/items", []byte(`{"title":"a"}`))
	if bad.Status != http.StatusUnprocessableEntity {
		t.Fatalf("validation status %d body %s", bad.Status, bad.Body)
	}

	created := app.Request(http.MethodPost, "/items", []byte(`{"title":"ab"}`))
	if created.Status != http.StatusCreated {
		t.Fatalf("create status %d body %s", created.Status, created.Body)
	}
	var got item
	if err := created.JSON(&got); err != nil {
		t.Fatal(err)
	}
	if got.Title != "ab" {
		t.Fatalf("title %q", got.Title)
	}

	gone := app.Request(http.MethodDelete, "/items/1", nil)
	if gone.Status != http.StatusNoContent {
		t.Fatalf("delete status %d body %s", gone.Status, gone.Body)
	}
	if len(strings.TrimSpace(string(gone.Body))) != 0 {
		t.Fatalf("delete body %s", gone.Body)
	}

	docs := app.Request(http.MethodGet, "/docs", nil)
	if docs.Status != http.StatusOK || !strings.Contains(string(docs.Body), "SwaggerUIBundle") || !strings.Contains(string(docs.Body), `url: "/openapi.json"`) {
		t.Fatalf("docs status %d body %s", docs.Status, docs.Body)
	}
	slash := app.Request(http.MethodGet, "/docs/", nil)
	if slash.Status != http.StatusOK || !strings.Contains(string(slash.Body), "/docs/swagger-ui-bundle.js") {
		t.Fatalf("docs slash status %d", slash.Status)
	}
	css := app.Request(http.MethodGet, "/docs/swagger-ui.css", nil)
	if css.Status != http.StatusOK || !strings.Contains(css.Header.Get("Content-Type"), "text/css") || !strings.Contains(string(css.Body), ".swagger-ui") {
		t.Fatalf("css status %d type %s", css.Status, css.Header.Get("Content-Type"))
	}
	js := app.Request(http.MethodGet, "/docs/swagger-ui-bundle.js", nil)
	if js.Status != http.StatusOK || !strings.Contains(js.Header.Get("Content-Type"), "javascript") || !strings.Contains(string(js.Body), "SwaggerUIBundle") {
		t.Fatalf("bundle status %d type %s", js.Status, js.Header.Get("Content-Type"))
	}
	preset := app.Request(http.MethodGet, "/docs/swagger-ui-standalone-preset.js", nil)
	if preset.Status != http.StatusOK || !strings.Contains(string(preset.Body), "SwaggerUIStandalonePreset") {
		t.Fatalf("preset status %d", preset.Status)
	}
	missing := app.Request(http.MethodGet, "/docs/missing.js", nil)
	if missing.Status != http.StatusNotFound {
		t.Fatalf("missing asset status %d", missing.Status)
	}
	spec := app.Request(http.MethodGet, "/openapi.json", nil)
	if spec.Status != http.StatusOK || !strings.Contains(string(spec.Body), `"Items"`) {
		t.Fatalf("openapi status %d body %s", spec.Status, spec.Body)
	}
}

func TestAuthOpenAPIOverrideAndGroup(t *testing.T) {
	app := gfast.New()
	type getIn struct {
		ID   string    `path:"id"`
		User principal `gfast:"dep=CurrentUser"`
		Also principal `gfast:"dep=CurrentUser"`
	}
	gfast.Get(app, "/items/{id}", func(ctx context.Context, in *getIn) (*item, error) {
		if in.User.ID != in.Also.ID {
			t.Fatalf("deps differ")
		}
		return &item{ID: in.ID, Title: in.User.ID}, nil
	}, gfast.Summary("Get item"), gfast.Scopes("items:read"))

	gfast.Get(app, "/me", func(ctx context.Context, in *struct{}) (*principal, error) {
		return &principal{ID: "hidden"}, nil
	})
	authed := app.Group("/v1", gfast.Require(currentUser))
	gfast.Get(authed, "/me", func(ctx context.Context, in *struct{}) (*principal, error) {
		return &principal{ID: "u1"}, nil
	})

	calls.Store(0)
	missing := app.Request(http.MethodGet, "/items/9", nil)
	if missing.Status != http.StatusUnauthorized {
		t.Fatalf("missing status %d body %s", missing.Status, missing.Body)
	}
	if missing.Header.Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("challenge %q", missing.Header.Get("WWW-Authenticate"))
	}
	if calls.Load() != 0 {
		t.Fatalf("provider ran without a token: %d", calls.Load())
	}

	bad := app.Request(http.MethodGet, "/items/9", nil, http.Header{"Authorization": []string{"Bearer no"}})
	if bad.Status != http.StatusUnauthorized || !strings.Contains(string(bad.Body), "invalid token") {
		t.Fatalf("bad token %d %s", bad.Status, bad.Body)
	}

	calls.Store(0)
	ok := app.Request(http.MethodGet, "/items/9", nil, http.Header{"Authorization": []string{"Bearer secret"}})
	if ok.Status != http.StatusOK {
		t.Fatalf("ok status %d body %s", ok.Status, ok.Body)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls %d", calls.Load())
	}
	var got item
	if err := ok.JSON(&got); err != nil {
		t.Fatal(err)
	}
	if got.Title != "u1" {
		t.Fatalf("title %q", got.Title)
	}

	open := app.Request(http.MethodGet, "/me", nil)
	if open.Status != http.StatusOK {
		t.Fatalf("public %d", open.Status)
	}
	gated := app.Request(http.MethodGet, "/v1/me", nil)
	if gated.Status != http.StatusUnauthorized {
		t.Fatalf("group %d %s", gated.Status, gated.Body)
	}

	spec := app.Request(http.MethodGet, "/openapi.json", nil)
	var doc map[string]any
	if err := json.Unmarshal(spec.Body, &doc); err != nil {
		t.Fatal(err, string(spec.Body))
	}
	paths := doc["paths"].(map[string]any)
	op := paths["/items/{id}"].(map[string]any)["get"].(map[string]any)
	raw, _ := json.Marshal(op["security"])
	if string(raw) != `[{"bearerAuth":["items:read"]}]` {
		t.Fatalf("security %s", raw)
	}
	params, _ := op["parameters"].([]any)
	for _, p := range params {
		name := p.(map[string]any)["name"]
		if name == "User" || name == "Also" {
			t.Fatalf("dep field documented as parameter: %v", name)
		}
	}
	if _, ok := op["requestBody"]; ok {
		t.Fatalf("dep field became a body: %s", spec.Body)
	}
	schemes := doc["components"].(map[string]any)["securitySchemes"].(map[string]any)
	bearer := schemes["bearerAuth"].(map[string]any)
	if bearer["scheme"] != "bearer" {
		t.Fatalf("scheme %#v", bearer)
	}
	public := paths["/me"].(map[string]any)["get"].(map[string]any)
	if _, ok := public["security"]; ok {
		t.Fatalf("public route has security: %v", public["security"])
	}

	other := gfast.New()
	gfast.Get(other, "/items/{id}", func(ctx context.Context, in *getIn) (*item, error) {
		return &item{ID: in.ID, Title: in.User.ID}, nil
	})
	other.Override(currentUser, func(ctx context.Context) (principal, error) {
		return principal{ID: "u_test"}, nil
	})
	over := other.Request(http.MethodGet, "/items/4", nil)
	if over.Status != http.StatusOK {
		t.Fatalf("override %d %s", over.Status, over.Body)
	}
	if err := over.JSON(&got); err != nil {
		t.Fatal(err)
	}
	if got.Title != "u_test" {
		t.Fatalf("override user %q", got.Title)
	}
}

func TestSessionCloserRunsOnce(t *testing.T) {
	app := gfast.New()
	var held *session
	gfast.Get(app, "/s", func(ctx context.Context, in *struct {
		A sessionUser `gfast:"dep=UserFromSession"`
		B sessionUser `gfast:"dep=UserFromSession"`
		S *session    `gfast:"dep=Session"`
	}) (*struct{ OK bool }, error) {
		if in.A.ID != "sess" || in.B.ID != in.A.ID || in.S == nil {
			t.Fatalf("%+v", in)
		}
		held = in.S
		return &struct{ OK bool }{true}, nil
	})
	res := app.Request(http.MethodGet, "/s", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("%d %s", res.Status, res.Body)
	}
	if held == nil || held.closed.Load() != 1 {
		t.Fatalf("closed %v", held)
	}
}

func TestAPIKeyAndBasic(t *testing.T) {
	_ = headerKey
	_ = queryKey
	app := gfast.New()
	gfast.Get(app, "/k", func(ctx context.Context, in *struct {
		Key gfast.APIKey `gfast:"dep=apiKey_header_X_API_Key"`
	}) (*struct{ Key string }, error) {
		return &struct{ Key string }{Key: in.Key.Value}, nil
	})
	gfast.Get(app, "/q", func(ctx context.Context, in *struct {
		Key gfast.APIKey `gfast:"dep=apiKey_query_api_key"`
	}) (*struct{ Key string }, error) {
		return &struct{ Key string }{Key: in.Key.Value}, nil
	})
	gfast.Get(app, "/b", func(ctx context.Context, in *struct {
		Cred gfast.Basic `gfast:"dep=basicAuth"`
	}) (*struct{ User string }, error) {
		return &struct{ User string }{User: in.Cred.Username}, nil
	})

	missing := app.Request(http.MethodGet, "/k", nil)
	if missing.Status != http.StatusUnauthorized {
		t.Fatalf("key %d", missing.Status)
	}
	ok := app.Request(http.MethodGet, "/k", nil, http.Header{"X-API-Key": []string{"k1"}})
	if ok.Status != http.StatusOK || !strings.Contains(string(ok.Body), "k1") {
		t.Fatalf("key ok %d %s", ok.Status, ok.Body)
	}
	q := app.Request(http.MethodGet, "/q?api_key=k2", nil)
	if q.Status != http.StatusOK || !strings.Contains(string(q.Body), "k2") {
		t.Fatalf("query key %d %s", q.Status, q.Body)
	}

	noBasic := app.Request(http.MethodGet, "/b", nil)
	if noBasic.Status != http.StatusUnauthorized {
		t.Fatalf("basic %d", noBasic.Status)
	}
	req := app.Request(http.MethodGet, "/b", nil, http.Header{"Authorization": []string{"Basic dTpw"}}) // u:p
	if req.Status != http.StatusOK || !strings.Contains(string(req.Body), `"u"`) {
		t.Fatalf("basic ok %d %s", req.Status, req.Body)
	}
}

func TestBackgroundPlainErrorAndCORS(t *testing.T) {
	done := make(chan struct{})
	app := gfast.New(gfast.CORS("https://example.com"))
	gfast.Post(app, "/work", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		gfast.Background(ctx, func() { close(done) })
		return nil, nil
	})
	gfast.Get(app, "/boom", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		return nil, errors.New("boom")
	})
	res := app.Request(http.MethodPost, "/work", []byte(`{}`))
	if res.Status != http.StatusNoContent {
		t.Fatalf("work %d %s", res.Status, res.Body)
	}
	<-done

	boom := app.Request(http.MethodGet, "/boom", nil)
	if boom.Status != http.StatusInternalServerError {
		t.Fatalf("boom %d %s", boom.Status, boom.Body)
	}

	pre := app.Request(http.MethodOptions, "/work", nil, http.Header{"Origin": []string{"https://example.com"}})
	if allow := pre.Header.Get("Access-Control-Allow-Origin"); allow != "https://example.com" {
		t.Fatalf("cors %q status %d", allow, pre.Status)
	}
}

func TestHooks(t *testing.T) {
	var started, stopped atomic.Int32
	app := gfast.New(
		gfast.OnStart(func(ctx context.Context) error {
			started.Add(1)
			return nil
		}),
		gfast.OnStop(func(ctx context.Context) error {
			stopped.Add(1)
			return nil
		}),
	)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- app.Serve(ln) }()
	ln.Close()
	if err := <-errCh; err != nil && !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "use of closed") {
		t.Fatal(err)
	}
	if started.Load() != 1 || stopped.Load() != 1 {
		t.Fatalf("started %d stopped %d", started.Load(), stopped.Load())
	}

	bad := gfast.New(gfast.OnStart(func(ctx context.Context) error {
		return errors.New("nope")
	}))
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	if err := bad.Serve(ln2); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("start error %v", err)
	}
}

func TestMisconfiguredDependenciesPanic(t *testing.T) {
	_ = cycleDepA
	_ = cycleDepB
	app := gfast.New()
	mustPanic(t, "cycle", func() {
		gfast.Get(app, "/c", func(ctx context.Context, in *struct {
			A cycleA `gfast:"dep=cycleA"`
		}) (*struct{}, error) {
			return &struct{}{}, nil
		})
	})

	mustPanic(t, "unknown", func() {
		gfast.Get(gfast.New(), "/u", func(ctx context.Context, in *struct {
			X int `gfast:"dep=missing-dep"`
		}) (*struct{}, error) {
			return &struct{}{}, nil
		})
	})
}

func mustPanic(t *testing.T, part string, fn func()) {
	t.Helper()
	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatal("expected panic")
		}
		if !strings.Contains(strings.ToLower(toString(rec)), part) {
			t.Fatalf("panic %v", rec)
		}
	}()
	fn()
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return ""
}

func TestNotFoundHelper(t *testing.T) {
	app := gfast.New()
	gfast.Get(app, "/nope", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		return nil, gfast.NotFound("gone")
	})
	res := app.Request(http.MethodGet, "/nope", nil)
	if res.Status != http.StatusNotFound || !strings.Contains(string(res.Body), "gone") {
		t.Fatalf("%d %s", res.Status, res.Body)
	}
}
