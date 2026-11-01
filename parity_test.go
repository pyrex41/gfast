package gfast_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/pyrex41/gfast"
)

// Coverage follows the FastAPI tests for parameters, bodies, dependencies,
// security, OpenAPI, CORS, and background work, limited to what gfast implements.

type orderMarker struct{}

func (orderMarker) Close() error {
	orderLog = append(orderLog, "close")
	return nil
}

var orderLog []string

var orderDep = gfast.Dep("orderMarker", func(ctx context.Context) (*orderMarker, error) {
	return &orderMarker{}, nil
})

func TestParameters(t *testing.T) {
	app := gfast.New(gfast.Title("Params"), gfast.Version("1.0.0"))
	type nested struct {
		Q string `query:"q"`
	}
	type in struct {
		ID     int    `path:"id"`
		N      int    `query:"n"`
		Flag   *bool  `query:"flag"`
		ReqID  string `header:"X-Request-Id"`
		Cookie string `cookie:"session"`
		Filter nested
	}
	var seen in
	app.Get("/items/{id}", func(ctx context.Context, in *in) (*in, error) {
		seen = *in
		return in, nil
	}, gfast.Summary("Read item"), gfast.Description("One item"), gfast.Tags("items"))

	ok := app.Request(http.MethodGet, "/items/12?n=3&n=9&q=hat", nil, http.Header{
		"X-Request-Id": []string{"req-1"},
		"Cookie":       []string{"session=abc"},
	})
	if ok.Status != http.StatusOK {
		t.Fatalf("status %d body %s", ok.Status, ok.Body)
	}
	if seen.ID != 12 || seen.N != 3 || seen.Filter.Q != "hat" || seen.ReqID != "req-1" || seen.Cookie != "abc" {
		t.Fatalf("bound %+v", seen)
	}
	if seen.Flag != nil {
		t.Fatalf("omitted query pointer %#v", seen.Flag)
	}
	if ct := ok.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %s", ct)
	}

	flag := app.Request(http.MethodGet, "/items/1?flag=true", nil)
	if flag.Status != http.StatusOK || seen.Flag == nil || !*seen.Flag {
		t.Fatalf("flag status %d value %v body %s", flag.Status, seen.Flag, flag.Body)
	}

	badInt := app.Request(http.MethodGet, "/items/no", nil)
	if badInt.Status != http.StatusBadRequest {
		t.Fatalf("bad path %d %s", badInt.Status, badInt.Body)
	}
	badQuery := app.Request(http.MethodGet, "/items/1?n=no", nil)
	if badQuery.Status != http.StatusBadRequest {
		t.Fatalf("bad query %d %s", badQuery.Status, badQuery.Body)
	}

	spec := openAPI(t, app)
	op := spec.paths["/items/{id}"]["get"]
	if op["summary"] != "Read item" || op["description"] != "One item" {
		t.Fatalf("docs %#v", op)
	}
	tags, _ := op["tags"].([]any)
	if len(tags) != 1 || tags[0] != "items" {
		t.Fatalf("tags %#v", op["tags"])
	}
	if op["operationId"] != "get-items-id" {
		t.Fatalf("operationId %v", op["operationId"])
	}
	locs := map[string]string{}
	types := map[string]string{}
	for _, raw := range op["parameters"].([]any) {
		p := raw.(map[string]any)
		locs[p["name"].(string)] = p["in"].(string)
		schema := p["schema"].(map[string]any)
		types[p["name"].(string)] = schema["type"].(string)
		if p["name"] == "id" && p["required"] != true {
			t.Fatalf("path required %#v", p)
		}
		if p["name"] == "n" && p["required"] == true {
			t.Fatalf("optional query marked required: %#v", p)
		}
	}
	if types["id"] != "integer" || types["n"] != "integer" || types["flag"] != "boolean" || types["q"] != "string" || types["X-Request-Id"] != "string" || types["session"] != "string" {
		t.Fatalf("param types %#v", types)
	}
	for name, loc := range map[string]string{"id": "path", "n": "query", "flag": "query", "q": "query", "X-Request-Id": "header", "session": "cookie"} {
		if locs[name] != loc {
			t.Fatalf("%s in %q, parameters %#v", name, locs[name], op["parameters"])
		}
	}
}

func TestJSONBodyValidation(t *testing.T) {
	app := gfast.New()
	type body struct {
		Title string `json:"title" minLength:"2" maxLength:"4"`
	}
	var calls int
	app.Post("/items", func(ctx context.Context, in *struct {
		Body body
		User principal `gfast:"dep=CurrentUser"`
	}) (*body, error) {
		calls++
		return &in.Body, nil
	}, gfast.Status(http.StatusCreated))

	callsBefore := calls
	provider := callsLoad()
	short := app.Request(http.MethodPost, "/items", []byte(`{"title":"a"}`), bearer("secret"))
	assertProblem(t, short, http.StatusUnprocessableEntity, "title must be at least 2")
	if calls != callsBefore || callsLoad() != provider {
		t.Fatalf("handler or provider ran on invalid body: handler %d provider %d", calls, callsLoad())
	}

	long := app.Request(http.MethodPost, "/items", []byte(`{"title":"abcde"}`), bearer("secret"))
	assertProblem(t, long, http.StatusUnprocessableEntity, "title must be at most 4")

	// Two runes, eight bytes. The limit counts runes.
	emoji := app.Request(http.MethodPost, "/items", []byte(`{"title":"👍👍"}`), bearer("secret"))
	if emoji.Status != http.StatusCreated {
		t.Fatalf("emoji %d %s", emoji.Status, emoji.Body)
	}

	unknown := app.Request(http.MethodPost, "/items", []byte(`{"title":"ab","extra":1}`), bearer("secret"))
	if unknown.Status != http.StatusBadRequest {
		t.Fatalf("unknown %d %s", unknown.Status, unknown.Body)
	}
	dup := app.Request(http.MethodPost, "/items", []byte(`{"title":"ab","title":"cd"}`), bearer("secret"))
	if dup.Status != http.StatusBadRequest {
		t.Fatalf("duplicate %d %s", dup.Status, dup.Body)
	}
	wrong := app.Request(http.MethodPost, "/items", []byte(`{"title":1}`), bearer("secret"))
	if wrong.Status != http.StatusBadRequest {
		t.Fatalf("type %d %s", wrong.Status, wrong.Body)
	}
	badUTF := app.Request(http.MethodPost, "/items", []byte("{\"title\":\"\xff\"}"), bearer("secret"))
	if badUTF.Status != http.StatusBadRequest {
		t.Fatalf("utf8 %d %s", badUTF.Status, badUTF.Body)
	}
	empty := app.Request(http.MethodPost, "/items", nil, bearer("secret"))
	assertProblem(t, empty, http.StatusUnprocessableEntity, "title must be at least 2")

	spec := openAPI(t, app)
	op := spec.paths["/items"]["post"]
	reqBody := op["requestBody"].(map[string]any)
	if reqBody["required"] != true {
		t.Fatalf("requestBody %#v", reqBody)
	}
	content := reqBody["content"].(map[string]any)["application/json"].(map[string]any)
	schema := spec.deref(content["schema"].(map[string]any))
	title := schema["properties"].(map[string]any)["title"].(map[string]any)
	if title["minLength"] != float64(2) || title["maxLength"] != float64(4) || title["type"] != "string" {
		t.Fatalf("title schema %#v", title)
	}
	resp := op["responses"].(map[string]any)["201"].(map[string]any)
	outSchema := spec.deref(resp["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any))
	if outSchema["properties"].(map[string]any)["title"].(map[string]any)["type"] != "string" {
		t.Fatalf("response schema %#v", outSchema)
	}
}

func TestPutPatchGroupAndRouting(t *testing.T) {
	app := gfast.New()
	app.Put("/items/{id}", func(ctx context.Context, in *struct {
		ID   string `path:"id"`
		Body struct {
			Title string `json:"title"`
		}
	}) (*struct {
		ID    string `json:"id"`
		Title string `json:"title"`
	}, error) {
		return &struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		}{ID: in.ID, Title: in.Body.Title}, nil
	})
	app.Patch("/items/{id}", func(ctx context.Context, in *struct {
		ID string `path:"id"`
	}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})
	api := app.Group("/v1", gfast.Tags("v1"))
	gfast.Get(api, "/health", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})

	put := app.Request(http.MethodPut, "/items/7", []byte(`{"title":"pen"}`))
	if put.Status != http.StatusOK || !strings.Contains(string(put.Body), `"pen"`) || !strings.Contains(string(put.Body), `"7"`) {
		t.Fatalf("put %d %s", put.Status, put.Body)
	}
	patch := app.Request(http.MethodPatch, "/items/7", nil)
	if patch.Status != http.StatusOK || !strings.Contains(string(patch.Body), `"OK":true`) {
		t.Fatalf("patch %d %s", patch.Status, patch.Body)
	}
	health := app.Request(http.MethodGet, "/v1/health", nil)
	if health.Status != http.StatusOK {
		t.Fatalf("health %d %s", health.Status, health.Body)
	}

	missing := app.Request(http.MethodGet, "/missing", nil)
	assertProblem(t, missing, http.StatusNotFound, "Not Found")
	if missing.Header.Get("Allow") != "" {
		t.Fatalf("missing allow %q", missing.Header.Get("Allow"))
	}
	wrong := app.Request(http.MethodPost, "/v1/health", nil)
	assertProblem(t, wrong, http.StatusMethodNotAllowed, "Method Not Allowed")
	if wrong.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("method allow %q", wrong.Header.Get("Allow"))
	}

	spec := openAPI(t, app)
	if _, ok := spec.paths["/v1/health"]["get"]; !ok {
		t.Fatalf("paths %#v", spec.paths)
	}
	tags := spec.paths["/v1/health"]["get"]["tags"].([]any)
	if len(tags) != 1 || tags[0] != "v1" {
		t.Fatalf("group tags %#v", tags)
	}
}

func TestStatusErrorsHidePlainMessages(t *testing.T) {
	app := gfast.New()
	app.Get("/bad", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		return nil, gfast.BadRequest("nope")
	})
	app.Get("/deny", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		return nil, gfast.Forbidden("no")
	})
	app.Get("/boom", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		return nil, errString("secret-bug")
	})

	assertProblem(t, app.Request(http.MethodGet, "/bad", nil), http.StatusBadRequest, "nope")
	assertProblem(t, app.Request(http.MethodGet, "/deny", nil), http.StatusForbidden, "no")
	boom := app.Request(http.MethodGet, "/boom", nil)
	assertProblem(t, boom, http.StatusInternalServerError, "unexpected error occurred")
	if strings.Contains(string(boom.Body), "secret-bug") {
		t.Fatalf("plain error leaked: %s", boom.Body)
	}
}

func TestBackgroundRunsBeforeCloser(t *testing.T) {
	orderLog = nil
	app := gfast.New()
	gfast.Post(app, "/work", func(ctx context.Context, in *struct {
		M *orderMarker `gfast:"dep=orderMarker"`
	}) (*struct{}, error) {
		gfast.Background(ctx, nil)
		gfast.Background(ctx, func() { orderLog = append(orderLog, "task") })
		if in.M == nil {
			t.Fatal("missing marker")
		}
		return nil, nil
	})
	res := app.Request(http.MethodPost, "/work", nil)
	if res.Status != http.StatusNoContent {
		t.Fatalf("%d %s", res.Status, res.Body)
	}
	if strings.Join(orderLog, ",") != "task,close" {
		t.Fatalf("order %v", orderLog)
	}

	mustPanic(t, "no request", func() {
		gfast.Background(context.Background(), func() {})
	})
}

func TestCORSAllowsListedOrigins(t *testing.T) {
	app := gfast.New(gfast.CORS("https://example.com"))
	app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})

	ok := app.Request(http.MethodOptions, "/ping", nil, http.Header{"Origin": []string{"https://example.com"}})
	if ok.Status != http.StatusNoContent {
		t.Fatalf("preflight %d", ok.Status)
	}
	if ok.Header.Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Fatalf("allow %q", ok.Header.Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(ok.Header.Get("Access-Control-Allow-Methods"), "PATCH") {
		t.Fatalf("methods %q", ok.Header.Get("Access-Control-Allow-Methods"))
	}
	if ok.Header.Get("Vary") != "Origin" {
		t.Fatalf("vary %q", ok.Header.Get("Vary"))
	}

	denied := app.Request(http.MethodGet, "/ping", nil, http.Header{"Origin": []string{"https://evil.example"}})
	if denied.Status != http.StatusOK {
		t.Fatalf("denied status %d", denied.Status)
	}
	if denied.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("evil origin echoed %q", denied.Header.Get("Access-Control-Allow-Origin"))
	}

	any := gfast.New(gfast.CORS())
	any.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})
	echo := any.Request(http.MethodGet, "/ping", nil, http.Header{"Origin": []string{"https://other.example"}})
	if echo.Header.Get("Access-Control-Allow-Origin") != "https://other.example" {
		t.Fatalf("any origin %q", echo.Header.Get("Access-Control-Allow-Origin"))
	}
}

func TestRegistrationPanics(t *testing.T) {
	app := gfast.New()
	app.Get("/x", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		return &struct{}{}, nil
	})
	mustPanic(t, "conflict", func() {
		app.Get("/x", func(ctx context.Context, in *struct{}) (*struct{}, error) {
			return &struct{}{}, nil
		})
	})
	mustPanic(t, "nil handler", func() {
		var handler func(context.Context, *struct{}) (*struct{}, error)
		gfast.Get(app, "/nil", handler)
	})
	mustPanic(t, "nil", func() {
		app.Override(nil, func(ctx context.Context) (principal, error) {
			return principal{}, nil
		})
	})
}

type errString string

func (e errString) Error() string { return string(e) }

func bearer(token string) http.Header {
	return http.Header{"Authorization": []string{"Bearer " + token}}
}

func callsLoad() int32 { return calls.Load() }

type openDoc struct {
	paths map[string]map[string]map[string]any
	raw   map[string]any
}

func (d openDoc) deref(schema map[string]any) map[string]any {
	if schema == nil {
		return nil
	}
	ref, _ := schema["$ref"].(string)
	name, ok := strings.CutPrefix(ref, "#/components/schemas/")
	if !ok || name == "" || strings.Contains(name, "/") {
		return schema
	}
	comps, _ := d.raw["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	next, _ := schemas[name].(map[string]any)
	if next == nil {
		return schema
	}
	return next
}

func openAPI(t *testing.T, app *gfast.App) openDoc {
	t.Helper()
	res := app.Request(http.MethodGet, "/openapi.json", nil)
	if res.Status != http.StatusOK {
		t.Fatalf("openapi %d %s", res.Status, res.Body)
	}
	var doc struct {
		OpenAPI string                               `json:"openapi"`
		Paths   map[string]map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(res.Body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.1.0" {
		t.Fatalf("openapi version %s", doc.OpenAPI)
	}
	var raw map[string]any
	if err := json.Unmarshal(res.Body, &raw); err != nil {
		t.Fatal(err)
	}
	return openDoc{paths: doc.Paths, raw: raw}
}

func assertProblem(t *testing.T, res *gfast.Result, status int, detail string) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("status %d body %s", res.Status, res.Body)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %s", ct)
	}
	var body struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
		Errors []struct {
			Loc  []string `json:"loc"`
			Type string   `json:"type"`
			Msg  string   `json:"msg"`
		} `json:"errors"`
	}
	if err := res.JSON(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != status || body.Title != http.StatusText(status) || !strings.Contains(body.Detail, detail) {
		t.Fatalf("problem %#v", body)
	}
	if status != http.StatusUnprocessableEntity {
		return
	}
	if len(body.Errors) == 0 {
		t.Fatalf("missing errors %#v", body)
	}
	found := false
	for _, issue := range body.Errors {
		if len(issue.Loc) == 0 || issue.Type == "" || issue.Msg == "" {
			t.Fatalf("error entry %#v", issue)
		}
		if strings.Contains(body.Detail, issue.Msg) {
			found = true
		}
	}
	if !found {
		t.Fatalf("detail %q does not include errors %#v", body.Detail, body.Errors)
	}
}

type reservedQuery struct {
	N int `query:"n" ge:"1" le:"9"`
}

func (in *reservedQuery) Validate() error {
	if in.N == 4 {
		return errors.New("4 is reserved")
	}
	return nil
}

type statusQuery struct {
	N int `query:"n"`
}

func (in *statusQuery) Validate() error {
	if in.N < 0 {
		return gfast.BadRequest("no negatives")
	}
	return nil
}

func TestOptInBinding(t *testing.T) {
	app := gfast.New()
	type requiredIn struct {
		Q       string `query:"q" required:"true" doc:"Search"`
		Trace   string `header:"X-Trace" required:"true"`
		Session string `cookie:"session" required:"true"`
	}
	app.Get("/required", func(ctx context.Context, in *requiredIn) (*requiredIn, error) {
		return in, nil
	})
	missing := app.Request(http.MethodGet, "/required", nil)
	assertProblem(t, missing, http.StatusUnprocessableEntity, "q is required")
	assertProblem(t, missing, http.StatusUnprocessableEntity, "X-Trace is required")
	assertProblem(t, missing, http.StatusUnprocessableEntity, "session is required")
	var missingBody struct {
		Errors []struct {
			Loc  []string `json:"loc"`
			Type string   `json:"type"`
			Msg  string   `json:"msg"`
		} `json:"errors"`
	}
	if err := missing.JSON(&missingBody); err != nil {
		t.Fatal(err)
	}
	if len(missingBody.Errors) != 3 || missingBody.Errors[0].Type != "missing" || missingBody.Errors[0].Loc[0] != "query" {
		t.Fatalf("missing errors %#v", missingBody.Errors)
	}
	okReq := app.Request(http.MethodGet, "/required?q=hat", nil, http.Header{
		"X-Trace": []string{"t1"},
		"Cookie":  []string{"session=abc"},
	})
	if okReq.Status != http.StatusOK {
		t.Fatalf("required ok %d %s", okReq.Status, okReq.Body)
	}

	type defaults struct {
		Limit int  `query:"limit" default:"10" doc:"Page size"`
		Flag  bool `query:"flag" default:"true"`
	}
	var seenDefault defaults
	app.Get("/defaults", func(ctx context.Context, in *defaults) (*defaults, error) {
		seenDefault = *in
		return in, nil
	})
	defRes := app.Request(http.MethodGet, "/defaults", nil)
	if defRes.Status != http.StatusOK || seenDefault.Limit != 10 || !seenDefault.Flag {
		t.Fatalf("defaults %d %+v %s", defRes.Status, seenDefault, defRes.Body)
	}
	over := app.Request(http.MethodGet, "/defaults?limit=2&flag=false", nil)
	if over.Status != http.StatusOK || seenDefault.Limit != 2 || seenDefault.Flag {
		t.Fatalf("override default %+v %s", seenDefault, over.Body)
	}

	type lists struct {
		N []int    `query:"n" minItems:"2" maxItems:"3"`
		H []string `header:"X-Tag"`
	}
	var seenList lists
	app.Get("/lists", func(ctx context.Context, in *lists) (*lists, error) {
		seenList = *in
		return in, nil
	})
	omitted := app.Request(http.MethodGet, "/lists", nil)
	if omitted.Status != http.StatusUnprocessableEntity {
		t.Fatalf("omitted slice %d %s", omitted.Status, omitted.Body)
	}
	if seenList.N != nil || seenList.H != nil {
		t.Fatalf("omitted slice allocated %#v", seenList)
	}
	listed := app.Request(http.MethodGet, "/lists?n=3&n=9", nil, http.Header{"X-Tag": []string{"a", "b"}})
	if listed.Status != http.StatusOK || len(seenList.N) != 2 || seenList.N[0] != 3 || seenList.N[1] != 9 || len(seenList.H) != 2 || seenList.H[0] != "a" || seenList.H[1] != "b" {
		t.Fatalf("lists %d %+v %s", listed.Status, seenList, listed.Body)
	}
	tooMany := app.Request(http.MethodGet, "/lists?n=1&n=2&n=3&n=4", nil)
	assertProblem(t, tooMany, http.StatusUnprocessableEntity, "n must have at most 3 items")

	type bounds struct {
		N float64 `query:"n" gt:"0" le:"2" doc:"count"`
	}
	app.Get("/bounds", func(ctx context.Context, in *bounds) (*bounds, error) {
		return in, nil
	})
	assertProblem(t, app.Request(http.MethodGet, "/bounds?n=0", nil), http.StatusUnprocessableEntity, "n must be greater than 0")
	assertProblem(t, app.Request(http.MethodGet, "/bounds?n=2.5", nil), http.StatusUnprocessableEntity, "n must be less than or equal to 2")
	if res := app.Request(http.MethodGet, "/bounds?n=2", nil); res.Status != http.StatusOK {
		t.Fatalf("bounds %d %s", res.Status, res.Body)
	}

	type coded struct {
		Code string `query:"code" pattern:"^[a-z]+$" enum:"hat,bat"`
	}
	app.Get("/coded", func(ctx context.Context, in *coded) (*coded, error) {
		return in, nil
	})
	assertProblem(t, app.Request(http.MethodGet, "/coded?code=A1", nil), http.StatusUnprocessableEntity, "must match pattern")
	assertProblem(t, app.Request(http.MethodGet, "/coded?code=cat", nil), http.StatusUnprocessableEntity, "must be one of hat, bat")
	if res := app.Request(http.MethodGet, "/coded?code=hat", nil); res.Status != http.StatusOK {
		t.Fatalf("coded %d %s", res.Status, res.Body)
	}

	type formats struct {
		When  string `json:"when" format:"date-time"`
		ID    string `json:"id" format:"uuid"`
		Email string `json:"email" format:"email"`
		Site  string `json:"site" format:"uri"`
	}
	app.Post("/formats", func(ctx context.Context, in *formats) (*formats, error) {
		return in, nil
	})
	validFmt := []byte(`{"when":"2020-01-02T03:04:05Z","id":"123e4567-e89b-12d3-a456-426614174000","email":"a@b.co","site":"https://example.com/a"}`)
	if res := app.Request(http.MethodPost, "/formats", validFmt); res.Status != http.StatusOK {
		t.Fatalf("formats %d %s", res.Status, res.Body)
	}
	assertProblem(t, app.Request(http.MethodPost, "/formats", []byte(`{"when":"yesterday","id":"123e4567-e89b-12d3-a456-426614174000","email":"a@b.co","site":"https://example.com/a"}`)), http.StatusUnprocessableEntity, "when must be a valid date-time")
	assertProblem(t, app.Request(http.MethodPost, "/formats", []byte(`{"when":"2020-01-02T03:04:05Z","id":"not-a-uuid","email":"a@b.co","site":"https://example.com/a"}`)), http.StatusUnprocessableEntity, "id must be a valid uuid")
	assertProblem(t, app.Request(http.MethodPost, "/formats", []byte(`{"when":"2020-01-02T03:04:05Z","id":"123e4567-e89b-12d3-a456-426614174000","email":"not-an-email","site":"https://example.com/a"}`)), http.StatusUnprocessableEntity, "email must be a valid email")
	assertProblem(t, app.Request(http.MethodPost, "/formats", []byte(`{"when":"2020-01-02T03:04:05Z","id":"123e4567-e89b-12d3-a456-426614174000","email":"a@b.co","site":"/relative"}`)), http.StatusUnprocessableEntity, "site must be a valid uri")

	type flatIn struct {
		Title string `json:"title" minLength:"2" doc:"Item title"`
		Note  string `json:"note" default:"hi"`
	}
	var seenFlat flatIn
	app.Post("/flat", func(ctx context.Context, in *flatIn) (*flatIn, error) {
		seenFlat = *in
		return in, nil
	})
	flatOK := app.Request(http.MethodPost, "/flat", []byte(`{"title":"ab"}`))
	if flatOK.Status != http.StatusOK || seenFlat.Title != "ab" || seenFlat.Note != "hi" {
		t.Fatalf("flat %d %+v %s", flatOK.Status, seenFlat, flatOK.Body)
	}
	if res := app.Request(http.MethodPost, "/flat", []byte(`{"title":"ab","zz":1}`)); res.Status != http.StatusBadRequest {
		t.Fatalf("flat unknown %d %s", res.Status, res.Body)
	}

	type loose struct {
		Title string   `json:"title"`
		_     struct{} `extra:"allow"`
	}
	app.Post("/loose", func(ctx context.Context, in *loose) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: in.Title == "ab"}, nil
	})
	looseOK := app.Request(http.MethodPost, "/loose", []byte(`{"title":"ab","zz":1}`))
	if looseOK.Status != http.StatusOK || !strings.Contains(string(looseOK.Body), `"OK":true`) {
		t.Fatalf("loose %d %s", looseOK.Status, looseOK.Body)
	}
	app.Post("/boxed", func(ctx context.Context, in *struct {
		Body struct {
			Title string `json:"title"`
		} `extra:"allow"`
	}) (*struct{ Title string }, error) {
		return &struct{ Title string }{Title: in.Body.Title}, nil
	})
	boxed := app.Request(http.MethodPost, "/boxed", []byte(`{"title":"ab","zz":1}`))
	if boxed.Status != http.StatusOK || !strings.Contains(string(boxed.Body), `"ab"`) {
		t.Fatalf("boxed %d %s", boxed.Status, boxed.Body)
	}

	var seenValid reservedQuery
	app.Get("/reserved", func(ctx context.Context, in *reservedQuery) (*reservedQuery, error) {
		seenValid = *in
		return in, nil
	})
	assertProblem(t, app.Request(http.MethodGet, "/reserved?n=4", nil), http.StatusUnprocessableEntity, "4 is reserved")
	if res := app.Request(http.MethodGet, "/reserved?n=3", nil); res.Status != http.StatusOK || seenValid.N != 3 {
		t.Fatalf("reserved %d %+v %s", res.Status, seenValid, res.Body)
	}
	app.Get("/signed", func(ctx context.Context, in *statusQuery) (*statusQuery, error) {
		return in, nil
	})
	assertProblem(t, app.Request(http.MethodGet, "/signed?n=-1", nil), http.StatusBadRequest, "no negatives")

	type formIn struct {
		Name string   `form:"name" required:"true" doc:"Given name"`
		Tag  []string `form:"tag" minItems:"1"`
	}
	var seenForm formIn
	app.Post("/form", func(ctx context.Context, in *formIn) (*formIn, error) {
		seenForm = *in
		return in, nil
	})
	assertProblem(t, app.Request(http.MethodPost, "/form", []byte("tag=a"), http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}}), http.StatusUnprocessableEntity, "name is required")
	formOK := app.Request(http.MethodPost, "/form", []byte("name=ada&tag=a&tag=b"), http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}})
	if formOK.Status != http.StatusOK || seenForm.Name != "ada" || len(seenForm.Tag) != 2 || seenForm.Tag[0] != "a" || seenForm.Tag[1] != "b" {
		t.Fatalf("form %d %+v %s", formOK.Status, seenForm, formOK.Body)
	}

	type uploadIn struct {
		Title  string                `form:"title" required:"true"`
		Upload *multipart.FileHeader `file:"upload" required:"true" doc:"Payload"`
	}
	var seenUpload uploadIn
	app.Post("/upload", func(ctx context.Context, in *uploadIn) (*struct{ Name string }, error) {
		seenUpload = *in
		if in.Upload == nil {
			return nil, gfast.BadRequest("missing upload")
		}
		f, err := in.Upload.Open()
		if err != nil {
			return nil, err
		}
		defer f.Close()
		body, err := io.ReadAll(f)
		if err != nil {
			return nil, err
		}
		return &struct{ Name string }{Name: in.Upload.Filename + ":" + string(body)}, nil
	})
	assertProblem(t, app.Request(http.MethodPost, "/upload", nil), http.StatusUnprocessableEntity, "upload is required")
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.WriteField("title", "note"); err != nil {
		t.Fatal(err)
	}
	part, err := writer.CreateFormFile("upload", "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	uploaded := app.Request(http.MethodPost, "/upload", buf.Bytes(), http.Header{"Content-Type": []string{writer.FormDataContentType()}})
	if uploaded.Status != http.StatusOK || !strings.Contains(string(uploaded.Body), "note.txt:hello") || seenUpload.Title != "note" {
		t.Fatalf("upload %d %+v %s", uploaded.Status, seenUpload.Title, uploaded.Body)
	}

	spec := openAPI(t, app)
	boundsOp := spec.paths["/bounds"]["get"]
	var nParam map[string]any
	for _, raw := range boundsOp["parameters"].([]any) {
		p := raw.(map[string]any)
		if p["name"] == "n" {
			nParam = p
		}
	}
	if nParam["description"] != "count" {
		t.Fatalf("doc %#v", nParam)
	}
	nSchema := nParam["schema"].(map[string]any)
	if nSchema["type"] != "number" || nSchema["exclusiveMinimum"] != float64(0) || nSchema["maximum"] != float64(2) {
		t.Fatalf("bounds schema %#v", nSchema)
	}
	defOp := spec.paths["/defaults"]["get"]["parameters"].([]any)[0].(map[string]any)
	if defOp["schema"].(map[string]any)["default"] != float64(10) || defOp["schema"].(map[string]any)["type"] != "integer" {
		t.Fatalf("default schema %#v", defOp["schema"])
	}
	listParams := spec.paths["/lists"]["get"]["parameters"].([]any)
	var nList map[string]any
	for _, raw := range listParams {
		p := raw.(map[string]any)
		if p["name"] == "n" {
			nList = p["schema"].(map[string]any)
		}
	}
	if nList["type"] != "array" || nList["items"].(map[string]any)["type"] != "integer" || nList["minItems"] != float64(2) {
		t.Fatalf("list schema %#v", nList)
	}
	flatSchema := spec.deref(spec.paths["/flat"]["post"]["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any))
	title := flatSchema["properties"].(map[string]any)["title"].(map[string]any)
	note := flatSchema["properties"].(map[string]any)["note"].(map[string]any)
	if title["description"] != "Item title" || title["type"] != "string" || note["default"] != "hi" {
		t.Fatalf("flat schema %#v", flatSchema)
	}
	formBody := spec.paths["/form"]["post"]["requestBody"].(map[string]any)
	formContent := formBody["content"].(map[string]any)
	if _, ok := formContent["application/x-www-form-urlencoded"]; !ok || formBody["required"] != true {
		t.Fatalf("form body %#v", formBody)
	}
	uploadBody := spec.paths["/upload"]["post"]["requestBody"].(map[string]any)
	uploadSchema := uploadBody["content"].(map[string]any)["multipart/form-data"].(map[string]any)["schema"].(map[string]any)
	uploadProp := uploadSchema["properties"].(map[string]any)["upload"].(map[string]any)
	if uploadProp["type"] != "string" || uploadProp["format"] != "binary" || uploadProp["description"] != "Payload" {
		t.Fatalf("upload schema %#v", uploadProp)
	}
	if _, ok := spec.paths["/upload"]["post"]["parameters"]; ok {
		t.Fatalf("file field became a parameter: %#v", spec.paths["/upload"]["post"]["parameters"])
	}

	mustPanic(t, "pattern", func() {
		app.Get("/bad-pattern", func(ctx context.Context, in *struct {
			Q string `query:"q" pattern:"["`
		}) (*struct{}, error) {
			return &struct{}{}, nil
		})
	})
	mustPanic(t, "default", func() {
		app.Get("/bad-default", func(ctx context.Context, in *struct {
			N int `query:"n" default:"no"`
		}) (*struct{}, error) {
			return &struct{}{}, nil
		})
	})
	mustPanic(t, "form", func() {
		app.Post("/both", func(ctx context.Context, in *struct {
			A string `form:"a"`
			B string `json:"b"`
		}) (*struct{}, error) {
			return &struct{}{}, nil
		})
	})
}
