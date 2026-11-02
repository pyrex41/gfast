package gfast_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"github.com/pyrex41/gfast"
)

type pendCell struct {
	Name string `json:"name" doc:"Cell name"`
}

type pendBody struct {
	Title string     `json:"title" doc:"Item title" example:"coat"`
	N     int        `json:"n" example:"0"`
	On    bool       `json:"on" example:"false"`
	Cells []pendCell `json:"cells"`
	Inner struct {
		N int `json:"n"`
	} `json:"inner"`
}

type pendCycle struct {
	Name string     `json:"name"`
	Next *pendCycle `json:"next"`
}

type pendOnly struct {
	Z int `json:"z"`
}

type pendIn struct {
	Q    string `query:"q" doc:"Search" example:"hat"`
	Body pendBody
}

func TestPropNamedStructRef(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		again := hegel.Draw(ht, hegel.Booleans())
		app := gfast.New()
		app.Post("/items", func(ctx context.Context, in *pendIn) (*pendBody, error) {
			return &in.Body, nil
		})
		app.Get("/anon", func(ctx context.Context, in *struct{}) (*struct {
			N int `json:"n"`
		}, error) {
			return nil, nil
		})
		app.Get("/mix", func(ctx context.Context, in *struct{}) (*struct {
			Item pendBody `json:"item"`
			N    int      `json:"n"`
		}, error) {
			return nil, nil
		})
		app.Get("/cycle", func(ctx context.Context, in *struct{}) (*pendCycle, error) {
			return &pendCycle{Name: "a"}, nil
		})
		if again {
			app.Get("/again", func(ctx context.Context, in *struct{}) (*pendBody, error) {
				return &pendBody{}, nil
			})
		}

		doc := pendSpec(ht, app)
		op := pendOp(ht, doc, "/items", "post")
		bodyRef := pendMediaSchema(ht, op, true)
		outRef := pendMediaSchema(ht, op, false)
		if bodyRef["$ref"] != "#/components/schemas/pendBody" || outRef["$ref"] != bodyRef["$ref"] {
			ht.Fatalf("refs body %#v out %#v", bodyRef, outRef)
		}
		if len(bodyRef) != 1 || len(outRef) != 1 {
			ht.Fatalf("named schema inlined body %#v out %#v", bodyRef, outRef)
		}
		schemas := pendSchemas(ht, doc)
		body := pendObj(ht, schemas["pendBody"], "pendBody")
		props := pendObj(ht, body["properties"], "properties")
		title := pendObj(ht, props["title"], "title")
		if title["description"] != "Item title" || title["example"] != "coat" || title["type"] != "string" {
			ht.Fatalf("title %#v", title)
		}
		if n, ok := pendNum(pendObj(ht, props["n"], "n")["example"]); !ok || n != 0 {
			ht.Fatalf("zero example n %#v", props["n"])
		}
		if pendObj(ht, props["on"], "on")["example"] != false {
			ht.Fatalf("zero example on %#v", props["on"])
		}
		if !reflect.DeepEqual(body["required"], []any{"title", "n", "on", "cells", "inner"}) {
			ht.Fatalf("required %#v", body["required"])
		}
		cells := pendObj(ht, props["cells"], "cells")
		if cells["type"] != "array" || pendObj(ht, cells["items"], "items")["$ref"] != "#/components/schemas/pendCell" {
			ht.Fatalf("cells %#v", cells)
		}
		cell := pendObj(ht, pendObj(ht, schemas["pendCell"], "pendCell")["properties"], "cell props")
		name := pendObj(ht, cell["name"], "cell name")
		if name["type"] != "string" || name["description"] != "Cell name" {
			ht.Fatalf("cell %#v", name)
		}
		inner := pendObj(ht, props["inner"], "inner")
		if inner["$ref"] != nil || inner["type"] != "object" || pendObj(ht, pendObj(ht, inner["properties"], "inner props")["n"], "inner n")["type"] != "integer" {
			ht.Fatalf("inner %#v", inner)
		}
		params, _ := op["parameters"].([]any)
		if len(params) != 1 {
			ht.Fatalf("params %#v", params)
		}
		q := pendObj(ht, params[0], "query")
		if q["name"] != "q" || q["description"] != "Search" || pendObj(ht, q["schema"], "q schema")["example"] != "hat" {
			ht.Fatalf("query %#v", q)
		}
		anon := pendMediaSchema(ht, pendOp(ht, doc, "/anon", "get"), false)
		if anon["$ref"] != nil || anon["type"] != "object" || pendObj(ht, pendObj(ht, anon["properties"], "anon props")["n"], "anon n")["type"] != "integer" {
			ht.Fatalf("anon %#v", anon)
		}
		mix := pendMediaSchema(ht, pendOp(ht, doc, "/mix", "get"), false)
		if mix["$ref"] != nil || mix["type"] != "object" || pendObj(ht, pendObj(ht, mix["properties"], "mix props")["item"], "mix item")["$ref"] != "#/components/schemas/pendBody" {
			ht.Fatalf("mix %#v", mix)
		}
		cycle := pendObj(ht, pendObj(ht, schemas["pendCycle"], "pendCycle")["properties"], "cycle props")
		if pendObj(ht, cycle["next"], "next")["$ref"] != "#/components/schemas/pendCycle" {
			ht.Fatalf("cycle %#v", cycle)
		}
		if again {
			other := pendMediaSchema(ht, pendOp(ht, doc, "/again", "get"), false)
			if other["$ref"] != "#/components/schemas/pendBody" {
				ht.Fatalf("again %#v", other)
			}
			if len(schemas) != 3 {
				ht.Fatalf("schemas %d %#v", len(schemas), schemas)
			}
		}
	})
}

func TestPropDeprecatedServersDocsExamples(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		text := hegel.Text().Alphabet("abc012")
		title := hegel.Draw(ht, text.MinSize(1).MaxSize(8))
		second := "https://api.example/" + hegel.Draw(ht, text.MinSize(1).MaxSize(6))
		desc := hegel.Draw(ht, hegel.Text().Alphabet("abc ").MaxSize(12))
		extURL := "https://docs.example/" + hegel.Draw(ht, text.MinSize(1).MaxSize(6))
		extDesc := hegel.Draw(ht, hegel.Text().Alphabet("abc ").MaxSize(12))
		routeURL := "https://route.example/" + hegel.Draw(ht, text.MinSize(1).MaxSize(6))
		routeDesc := hegel.Draw(ht, hegel.Text().Alphabet("abc ").MaxSize(8))
		groupOn := hegel.Draw(ht, hegel.Booleans())
		choice := hegel.Draw(ht, hegel.Integers(0, 2))

		var routeOpts []gfast.Option
		routeOpts = append(routeOpts, gfast.ExternalDocs(routeURL, routeDesc))
		effective := groupOn
		switch choice {
		case 1:
			routeOpts = append(routeOpts, gfast.Deprecated(true))
			effective = true
		case 2:
			routeOpts = append(routeOpts, gfast.Deprecated(false))
			effective = false
		}
		app := gfast.New(
			gfast.Title(title),
			gfast.Servers(gfast.Server{URL: "https://old.example/a", Description: "Old"}),
			gfast.Servers(gfast.Server{URL: second, Description: desc}),
			gfast.ExternalDocs(extURL, extDesc),
		)
		g := app.Group("/v1", gfast.Deprecated(groupOn))
		g.Post("/items", func(ctx context.Context, in *pendIn) (*pendBody, error) {
			return &in.Body, nil
		}, routeOpts...)

		doc := pendSpec(ht, app)
		info := pendObj(ht, doc["info"], "info")
		if info["title"] != title {
			ht.Fatalf("title %#v", info["title"])
		}
		servers, _ := doc["servers"].([]any)
		if len(servers) != 1 {
			ht.Fatalf("servers %#v", servers)
		}
		server := pendObj(ht, servers[0], "server")
		if server["url"] != second || pendStr(server["description"]) != desc {
			ht.Fatalf("server %#v want %s %q", server, second, desc)
		}
		ext := pendObj(ht, doc["externalDocs"], "externalDocs")
		if ext["url"] != extURL || pendStr(ext["description"]) != extDesc {
			ht.Fatalf("external %#v", ext)
		}
		op := pendOp(ht, doc, "/v1/items", "post")
		if effective && op["deprecated"] != true {
			ht.Fatalf("deprecated %#v want true", op["deprecated"])
		}
		if !effective && op["deprecated"] != nil {
			ht.Fatalf("deprecated %#v want omitted", op["deprecated"])
		}
		opExt := pendObj(ht, op["externalDocs"], "operation docs")
		if opExt["url"] != routeURL || pendStr(opExt["description"]) != routeDesc {
			ht.Fatalf("operation docs %#v", opExt)
		}
		props := pendObj(ht, pendObj(ht, pendSchemas(ht, doc)["pendBody"], "body")["properties"], "props")
		if pendObj(ht, props["title"], "title")["example"] != "coat" {
			ht.Fatalf("example title %#v", props["title"])
		}
		if n, ok := pendNum(pendObj(ht, props["n"], "n")["example"]); !ok || n != 0 || pendObj(ht, props["on"], "on")["example"] != false {
			ht.Fatalf("examples n %#v on %#v", props["n"], props["on"])
		}
		params, _ := op["parameters"].([]any)
		q := pendObj(ht, params[0], "q")
		if pendObj(ht, q["schema"], "schema")["example"] != "hat" {
			ht.Fatalf("query example %#v", q)
		}
	})
}

func TestPropIncludeInSchema(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		groupHide := hegel.Draw(ht, hegel.Booleans())
		choice := hegel.Draw(ht, hegel.Integers(0, 2))
		plainHide := hegel.Draw(ht, hegel.Booleans())

		var groupOpts []gfast.Option
		groupShown := true
		if groupHide {
			groupOpts = append(groupOpts, gfast.IncludeInSchema(false))
			groupShown = false
		}
		childShown := groupShown
		var routeOpts []gfast.Option
		switch choice {
		case 1:
			routeOpts = append(routeOpts, gfast.IncludeInSchema(true))
			childShown = true
		case 2:
			routeOpts = append(routeOpts, gfast.IncludeInSchema(false))
			childShown = false
		}
		app := gfast.New()
		g := app.Group("/v1", groupOpts...)
		g.Get("/child", func(ctx context.Context, in *struct{}) (*pendOnly, error) {
			return &pendOnly{Z: 1}, nil
		}, routeOpts...)
		var plainOpts []gfast.Option
		if plainHide {
			plainOpts = append(plainOpts, gfast.IncludeInSchema(false))
		}
		app.Get("/live", func(ctx context.Context, in *struct{}) (*struct {
			OK bool `json:"ok"`
		}, error) {
			return &struct {
				OK bool `json:"ok"`
			}{OK: true}, nil
		}, plainOpts...)

		if res := app.Request(http.MethodGet, "/v1/child", nil); res.Status != http.StatusOK {
			ht.Fatalf("child %d %s", res.Status, res.Body)
		}
		if res := app.Request(http.MethodGet, "/live", nil); res.Status != http.StatusOK {
			ht.Fatalf("live %d %s", res.Status, res.Body)
		}
		doc := pendSpec(ht, app)
		paths, _ := doc["paths"].(map[string]any)
		if paths == nil {
			paths = map[string]any{}
		}
		if _, ok := paths["/v1/child"]; ok != childShown {
			ht.Fatalf("child in schema %v want %v", ok, childShown)
		}
		if _, ok := paths["/live"]; ok != !plainHide {
			ht.Fatalf("live in schema %v want %v", ok, !plainHide)
		}
		schemas := pendSchemas(ht, doc)
		_, hasOnly := schemas["pendOnly"]
		if hasOnly != childShown {
			ht.Fatalf("pendOnly %v want %v schemas %#v", hasOnly, childShown, schemas)
		}
	})
}

func TestPropDocsDisabled(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		title := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(8))
		mode := hegel.Draw(ht, hegel.Integers(0, 2))
		var opts []gfast.Option
		opts = append(opts, gfast.Title(title))
		on := true
		switch mode {
		case 1:
			opts = append(opts, gfast.Docs(true))
		case 2:
			opts = append(opts, gfast.Docs(false))
			on = false
		}
		app := gfast.New(opts...)
		app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
			return &struct{ OK bool }{OK: true}, nil
		})
		if res := app.Request(http.MethodGet, "/ping", nil); res.Status != http.StatusOK {
			ht.Fatalf("ping %d %s", res.Status, res.Body)
		}
		spec := app.Request(http.MethodGet, "/openapi.json", nil)
		docs := app.Request(http.MethodGet, "/docs", nil)
		slash := app.Request(http.MethodGet, "/docs/", nil)
		css := app.Request(http.MethodGet, "/docs/swagger-ui.css", nil)
		hand := app.Request(http.MethodGet, "/docs/oauth2-redirect", nil)
		script := app.Request(http.MethodGet, "/docs/oauth2-redirect.js", nil)
		if !on {
			for _, res := range []*gfast.Result{spec, docs, slash, css, hand, script} {
				if res.Status != http.StatusNotFound {
					ht.Fatalf("docs off %d %s", res.Status, res.Body)
				}
			}
			return
		}
		if spec.Status != http.StatusOK {
			ht.Fatalf("spec %d %s", spec.Status, spec.Body)
		}
		var doc map[string]any
		if err := json.Unmarshal(spec.Body, &doc); err != nil {
			ht.Fatal(err)
		}
		if pendObj(ht, doc["info"], "info")["title"] != title {
			ht.Fatalf("info %#v", doc["info"])
		}
		for _, res := range []*gfast.Result{docs, slash, hand} {
			if res.Status != http.StatusOK || res.Header.Get("Content-Type") != "text/html; charset=utf-8" {
				ht.Fatalf("html %d %q", res.Status, res.Header.Get("Content-Type"))
			}
		}
		if !strings.Contains(string(docs.Body), "<title>"+title+"</title>") || !strings.Contains(string(docs.Body), `oauth2RedirectUrl: window.location.origin + "/docs/oauth2-redirect"`) {
			ht.Fatalf("docs page missing title or redirect")
		}
		if css.Status != http.StatusOK || css.Header.Get("Content-Type") != "text/css; charset=utf-8" || len(css.Body) == 0 {
			ht.Fatalf("css %d %q %d", css.Status, css.Header.Get("Content-Type"), len(css.Body))
		}
		if script.Status != http.StatusOK || script.Header.Get("Content-Type") != "text/javascript; charset=utf-8" || len(script.Body) == 0 {
			ht.Fatalf("redirect script %d %q", script.Status, script.Header.Get("Content-Type"))
		}
	})
}

func TestPropUseMiddleware(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		n := hegel.Draw(ht, hegel.Integers(0, 3))
		corsOn := hegel.Draw(ht, hegel.Booleans())
		ids := []string{"a", "b", "c"}[:n]
		var opts []gfast.Option
		if corsOn {
			opts = append(opts, gfast.CORS("https://example.com"))
		}
		app := gfast.New(opts...)
		var order []string
		for _, id := range ids {
			id := id
			app.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					order = append(order, id+"-in")
					next.ServeHTTP(w, r)
					order = append(order, id+"-out")
				})
			})
		}
		var hits int
		app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
			hits++
			order = append(order, "handler")
			return &struct{ OK bool }{OK: true}, nil
		})

		header := http.Header{}
		if corsOn {
			header.Set("Origin", "https://example.com")
		}
		order = nil
		hits = 0
		pre := app.Request(http.MethodOptions, "/ping", nil, header)
		if corsOn {
			if pre.Status != http.StatusNoContent || hits != 0 || len(order) != 0 {
				ht.Fatalf("preflight status %d hits %d order %v body %s", pre.Status, hits, order, pre.Body)
			}
			if pre.Header.Get("Access-Control-Allow-Origin") != "https://example.com" {
				ht.Fatalf("preflight origin %q", pre.Header.Get("Access-Control-Allow-Origin"))
			}
		} else {
			want := pendWrapOrder(ids, false)
			if pre.Status != http.StatusMethodNotAllowed || hits != 0 || !reflect.DeepEqual(order, want) {
				ht.Fatalf("options status %d hits %d order %v want %v", pre.Status, hits, order, want)
			}
		}

		order = nil
		hits = 0
		res := app.Request(http.MethodGet, "/ping", nil, header)
		want := pendWrapOrder(ids, true)
		if res.Status != http.StatusOK || hits != 1 || !reflect.DeepEqual(order, want) {
			ht.Fatalf("get status %d hits %d order %v want %v", res.Status, hits, order, want)
		}
		if corsOn && res.Header.Get("Access-Control-Allow-Origin") != "https://example.com" {
			ht.Fatalf("get origin %q", res.Header.Get("Access-Control-Allow-Origin"))
		}
	})
}

func TestPropCORSCredentialsExposeMaxAge(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		kind := hegel.Draw(ht, hegel.Integers(0, 4))
		credentials := hegel.Draw(ht, hegel.Booleans())
		withPattern := hegel.Draw(ht, hegel.Booleans())
		maxMode := hegel.Draw(ht, hegel.Integers(0, 2))
		exposeDup := hegel.Draw(ht, hegel.Booleans())
		originChoice := hegel.Draw(ht, hegel.Integers(0, 5))
		preflight := hegel.Draw(ht, hegel.Booleans())

		var origins []string
		switch kind {
		case 1:
			origins = []string{"https://ok.example"}
		case 2:
			origins = []string{"*"}
		case 3:
			origins = []string{"https://ok.example", "*"}
		case 4:
			origins = []string{"https://*.docs.test"}
		}
		var patterns []string
		if withPattern {
			patterns = []string{`https://re[.]fixed[.]test`}
		}
		rawExpose := []string{"X-Request-Id"}
		if exposeDup {
			rawExpose = []string{"X-Request-Id", " X-Request-Id ", " X-Trace ", ""}
		}
		originsSent := []string{"", "https://ok.example", "https://a.docs.test", "https://re.fixed.test", "https://evil.example", "https://anywhere.example"}
		origin := originsSent[originChoice]

		opts := []gfast.Option{gfast.CORS(origins...)}
		if withPattern {
			opts = append(opts, gfast.AllowOriginPattern(patterns...))
		}
		opts = append(opts, gfast.AllowCredentials(credentials), gfast.ExposeHeaders(rawExpose...))
		maxAge := -1
		switch maxMode {
		case 1:
			maxAge = 0
		case 2:
			maxAge = 600
		}
		if maxAge >= 0 {
			opts = append(opts, gfast.MaxAge(maxAge))
		}
		var hits int
		app := gfast.New(opts...)
		app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
			hits++
			return &struct{ OK bool }{OK: true}, nil
		})

		method := http.MethodGet
		if preflight {
			method = http.MethodOptions
		}
		header := http.Header{}
		if origin != "" {
			header.Set("Origin", origin)
		}
		res := app.Request(method, "/ping", nil, header)
		match := pendCORSAllows(origins, patterns, credentials, origin)
		wantStatus := http.StatusOK
		wantHits := 1
		if preflight {
			wantStatus = http.StatusNoContent
			wantHits = 0
		}
		if res.Status != wantStatus || hits != wantHits {
			ht.Fatalf("status %d hits %d want %d/%d body %s", res.Status, hits, wantStatus, wantHits, res.Body)
		}
		if !match {
			if res.Header.Get("Access-Control-Allow-Origin") != "" || res.Header.Get("Access-Control-Allow-Credentials") != "" || res.Header.Get("Vary") != "" || res.Header.Get("Access-Control-Expose-Headers") != "" || res.Header.Get("Access-Control-Max-Age") != "" {
				ht.Fatalf("cors leaked %v", res.Header)
			}
			return
		}
		if res.Header.Get("Access-Control-Allow-Origin") != origin || res.Header.Get("Vary") != "Origin" {
			ht.Fatalf("origin %q vary %q", res.Header.Get("Access-Control-Allow-Origin"), res.Header.Get("Vary"))
		}
		if res.Header.Get("Access-Control-Allow-Methods") != "GET, POST, PUT, PATCH, DELETE, OPTIONS" {
			ht.Fatalf("methods %q", res.Header.Get("Access-Control-Allow-Methods"))
		}
		if res.Header.Get("Access-Control-Allow-Headers") != "Authorization, Content-Type, Accept" {
			ht.Fatalf("headers %q", res.Header.Get("Access-Control-Allow-Headers"))
		}
		wantCred := ""
		if credentials {
			wantCred = "true"
		}
		if res.Header.Get("Access-Control-Allow-Credentials") != wantCred {
			ht.Fatalf("credentials %q", res.Header.Get("Access-Control-Allow-Credentials"))
		}
		wantExpose := ""
		wantAge := ""
		if preflight {
			if maxAge >= 0 {
				wantAge = strconv.Itoa(maxAge)
			}
		} else {
			wantExpose = pendExpose(rawExpose)
		}
		if res.Header.Get("Access-Control-Expose-Headers") != wantExpose || res.Header.Get("Access-Control-Max-Age") != wantAge {
			ht.Fatalf("expose %q age %q want %q %q", res.Header.Get("Access-Control-Expose-Headers"), res.Header.Get("Access-Control-Max-Age"), wantExpose, wantAge)
		}
	})
}

func TestPropGzip(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		encodings := []string{
			"",
			"gzip",
			"identity",
			"gzip;q=0",
			"deflate, gzip;q=0.8",
			"*;q=0",
			"*;q=0.1",
			"GZip",
			"gzip;q=0, identity;q=1",
		}
		accept := encodings[hegel.Draw(ht, hegel.Integers(0, len(encodings)-1))]
		mode := hegel.Draw(ht, hegel.Integers(0, 4))
		text := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MaxSize(24))

		var seen []byte
		app := gfast.New(gfast.Gzip())
		app.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tw := &tapWriter{ResponseWriter: w}
				next.ServeHTTP(tw, r)
				seen = append([]byte(nil), tw.buf...)
			})
		})
		app.Get("/body", func(ctx context.Context, in *struct{}) (*string, error) {
			gfast.ResponseFrom(ctx).SetContentType("text/plain")
			switch mode {
			case 2:
				gfast.ResponseFrom(ctx).Header().Set("Content-Encoding", "deflate")
			case 1:
				return nil, nil
			}
			s := text
			return &s, nil
		})
		app.Get("/events", func(ctx context.Context, in *struct{}) (*gfast.Events, error) {
			return gfast.SSE(func(ctx context.Context, send func(gfast.Event) error) error {
				return send(gfast.Event{Data: text})
			}), nil
		})

		method := http.MethodGet
		path := "/body"
		if mode == 3 {
			path = "/events"
		}
		if mode == 4 {
			method = http.MethodHead
		}
		res := app.Request(method, path, nil, http.Header{"Accept-Encoding": []string{accept}})
		plain := []byte(text)
		if mode == 3 {
			plain = []byte("data: " + text + "\n\n")
		}
		if mode == 1 {
			plain = nil
		}
		wantGzip := mode == 0 && pendAcceptsGzip(accept)
		switch {
		case mode == 4:
			if res.Status != http.StatusOK || len(res.Body) != 0 || res.Header.Get("Content-Encoding") != "" || res.Header.Get("Content-Type") != "text/plain" {
				ht.Fatalf("head %d enc %q type %q body %q", res.Status, res.Header.Get("Content-Encoding"), res.Header.Get("Content-Type"), res.Body)
			}
		case mode == 1:
			if res.Status != http.StatusNoContent || len(res.Body) != 0 || res.Header.Get("Content-Encoding") != "" || len(seen) != 0 {
				ht.Fatalf("empty %d enc %q body %q seen %q", res.Status, res.Header.Get("Content-Encoding"), res.Body, seen)
			}
		case mode == 2:
			if res.Header.Get("Content-Encoding") != "deflate" || !bytes.Equal(res.Body, plain) || !bytes.Equal(seen, plain) {
				ht.Fatalf("encoded %q body %q seen %q", res.Header.Get("Content-Encoding"), res.Body, seen)
			}
		case mode == 3:
			if res.Header.Get("Content-Encoding") != "" || res.Header.Get("Content-Type") != "text/event-stream" || !bytes.Equal(res.Body, plain) || !bytes.Equal(seen, plain) {
				ht.Fatalf("sse enc %q type %q body %q seen %q", res.Header.Get("Content-Encoding"), res.Header.Get("Content-Type"), res.Body, seen)
			}
		case wantGzip:
			got, err := pendGunzip(res.Body)
			if err != nil {
				ht.Fatal(err)
			}
			if res.Header.Get("Content-Encoding") != "gzip" || !strings.Contains(res.Header.Get("Vary"), "Accept-Encoding") || !bytes.Equal(got, plain) || !bytes.Equal(seen, plain) {
				ht.Fatalf("gzip enc %q vary %q got %q seen %q", res.Header.Get("Content-Encoding"), res.Header.Get("Vary"), got, seen)
			}
		default:
			if res.Header.Get("Content-Encoding") != "" || !bytes.Equal(res.Body, plain) || !bytes.Equal(seen, plain) {
				ht.Fatalf("plain enc %q body %q seen %q", res.Header.Get("Content-Encoding"), res.Body, seen)
			}
		}
	})
}

func TestPropForeignHost(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		label := hegel.Draw(ht, hegel.Text().Alphabet("abcdefghijklmnopqrstuvwxyz").MinSize(1).MaxSize(8))
		mode := hegel.Draw(ht, hegel.Integers(0, 7))
		query := hegel.Draw(ht, hegel.Booleans())
		target := "/ping"
		locPath := "/ping"
		if query {
			target = "/ping?x=1"
			locPath = "/ping?x=1"
		}
		var hosts []string
		host := "example.com"
		want := http.StatusOK
		wantHits := 1
		location := ""
		switch mode {
		case 0:
			hosts = []string{"api.example"}
			want = http.StatusBadRequest
			wantHits = 0
		case 1:
			hosts = []string{"*"}
			host = "evil.test"
		case 2:
			hosts = []string{"www.example.com"}
			want = http.StatusTemporaryRedirect
			wantHits = 0
			location = "http://www.example.com" + locPath
		case 3:
			hosts = []string{"*." + label + ".test"}
			host = "a." + label + ".test"
		case 4:
			hosts = []string{"*." + label + ".test"}
			host = label + ".test"
			want = http.StatusBadRequest
			wantHits = 0
		case 5:
			hosts = []string{"api.example"}
			host = "API.Example"
		case 6:
			hosts = []string{"api.example"}
			host = "api.example:8443"
		default:
			hosts = []string{"www." + label + ".test"}
			host = label + ".test"
			want = http.StatusTemporaryRedirect
			wantHits = 0
			location = "http://www." + label + ".test" + locPath
		}
		var hits int
		app := gfast.New(gfast.TrustedHost(hosts...))
		app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
			hits++
			return &struct{ OK bool }{OK: true}, nil
		})
		res := pendServe(app, http.MethodGet, target, host)
		if res.Status != want || hits != wantHits {
			ht.Fatalf("mode %d status %d hits %d want %d/%d body %s", mode, res.Status, hits, want, wantHits, res.Body)
		}
		if want == http.StatusBadRequest && !strings.Contains(string(res.Body), "Invalid host header") {
			ht.Fatalf("body %s", res.Body)
		}
		if res.Header.Get("Location") != location {
			ht.Fatalf("location %q want %q", res.Header.Get("Location"), location)
		}
	})
}

func TestPropCookieJarClient(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		alpha := hegel.Text().Alphabet("abcXYZ019")
		name := "s" + hegel.Draw(ht, alpha.MinSize(1).MaxSize(6))
		value := hegel.Draw(ht, alpha.MinSize(1).MaxSize(8))
		first := hegel.Draw(ht, alpha.MinSize(1).MaxSize(8))
		second := hegel.Draw(ht, alpha.MinSize(1).MaxSize(8))

		app := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}))
		app.Post("/login", func(ctx context.Context, in *struct {
			Name string `json:"name"`
		}) (*struct{}, error) {
			gfast.SessionFrom(ctx)["user"] = in.Name
			gfast.ResponseFrom(ctx).SetCookie(&http.Cookie{Name: name, Value: value, Path: "/"})
			return &struct{}{}, nil
		})
		app.Get("/me", func(ctx context.Context, in *struct{}) (*struct {
			User string `json:"user"`
			Sid  string `json:"sid"`
		}, error) {
			user, _ := gfast.SessionFrom(ctx)["user"].(string)
			sid := ""
			if c, err := gfast.RequestFrom(ctx).Cookie(name); err == nil {
				sid = c.Value
			}
			return &struct {
				User string `json:"user"`
				Sid  string `json:"sid"`
			}{User: user, Sid: sid}, nil
		})

		client := app.Client()
		login := client.Request(http.MethodPost, "/login", []byte(`{"name":"`+first+`"}`))
		if login.Status != http.StatusOK {
			ht.Fatalf("login %d %s", login.Status, login.Body)
		}
		me := client.Request(http.MethodGet, "/me", nil)
		var got struct {
			User string `json:"user"`
			Sid  string `json:"sid"`
		}
		if err := me.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if me.Status != http.StatusOK || got.User != first || got.Sid != value {
			ht.Fatalf("me %d %+v", me.Status, got)
		}
		bare := app.Request(http.MethodGet, "/me", nil)
		got = struct {
			User string `json:"user"`
			Sid  string `json:"sid"`
		}{}
		if err := bare.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.User != "" || got.Sid != "" || bare.Header.Get("Set-Cookie") != "" {
			ht.Fatalf("single shot %+v cookie %q", got, bare.Header.Get("Set-Cookie"))
		}
		again := client.Request(http.MethodGet, "/me", nil)
		got = struct {
			User string `json:"user"`
			Sid  string `json:"sid"`
		}{}
		if err := again.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.User != first || got.Sid != value {
			ht.Fatalf("jar dropped %+v", got)
		}
		next := client.Request(http.MethodPost, "/login", []byte(`{"name":"`+second+`"}`))
		if next.Status != http.StatusOK {
			ht.Fatalf("second login %d %s", next.Status, next.Body)
		}
		after := client.Request(http.MethodGet, "/me", nil)
		got = struct {
			User string `json:"user"`
			Sid  string `json:"sid"`
		}{}
		if err := after.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.User != second || got.Sid != value {
			ht.Fatalf("updated %+v want %s %s", got, second, value)
		}
	})
}

func TestPropRedirectLimit(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		codes := []int{
			http.StatusMovedPermanently,
			http.StatusFound,
			http.StatusSeeOther,
			http.StatusTemporaryRedirect,
			http.StatusPermanentRedirect,
		}
		code := codes[hegel.Draw(ht, hegel.Integers(0, len(codes)-1))]
		k := hegel.Draw(ht, hegel.Integers(0, 12))
		follow := hegel.Draw(ht, hegel.Booleans())
		foreign := hegel.Draw(ht, hegel.Booleans())
		post := hegel.Draw(ht, hegel.Booleans())
		name := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(6))

		var steps, lands int
		app := gfast.New()
		step := func(ctx context.Context, in *struct {
			N int `path:"n"`
		}) (*gfast.Redirect, error) {
			steps++
			loc := "/land"
			if foreign && in.N == 0 {
				loc = "https://elsewhere.example/no"
			} else if in.N+1 < k {
				loc = "/step/" + strconv.Itoa(in.N+1)
			}
			return gfast.RedirectTo(loc, code), nil
		}
		land := func(ctx context.Context, in *struct {
			Name string `json:"name"`
		}) (*struct {
			Method string `json:"method"`
			Name   string `json:"name"`
		}, error) {
			lands++
			return &struct {
				Method string `json:"method"`
				Name   string `json:"name"`
			}{Method: gfast.RequestFrom(ctx).Method, Name: in.Name}, nil
		}
		app.Get("/step/{n}", step)
		app.Post("/step/{n}", step)
		app.Get("/land", land)
		app.Post("/land", land)

		client := app.Client()
		client.FollowRedirects = follow
		method := http.MethodGet
		var body []byte
		if post {
			method = http.MethodPost
			body = []byte(`{"name":"` + name + `"}`)
		}
		path := "/land"
		if k > 0 {
			path = "/step/0"
		}
		res := client.Request(method, path, body)

		reached := k == 0 || (follow && !foreign && k <= gfast.ClientRedirectLimit)
		wantStatus := http.StatusOK
		wantSteps := 0
		wantLands := 1
		wantLoc := ""
		switch {
		case k == 0:
		case foreign || !follow:
			wantStatus = code
			wantSteps = 1
			wantLands = 0
			wantLoc = "/land"
			if k > 1 && !foreign {
				wantLoc = "/step/1"
			}
			if foreign {
				wantLoc = "https://elsewhere.example/no"
			}
		case k > gfast.ClientRedirectLimit:
			wantStatus = code
			wantSteps = gfast.ClientRedirectLimit + 1
			wantLands = 0
			wantLoc = "/step/" + strconv.Itoa(gfast.ClientRedirectLimit+1)
			if gfast.ClientRedirectLimit+1 == k {
				wantLoc = "/land"
			}
		default:
			wantSteps = k
		}
		if res.Status != wantStatus || steps != wantSteps || lands != wantLands || res.Header.Get("Location") != wantLoc {
			ht.Fatalf("k %d follow %v foreign %v code %d status %d steps %d lands %d loc %q want %d/%d/%d %q body %s", k, follow, foreign, code, res.Status, steps, lands, res.Header.Get("Location"), wantStatus, wantSteps, wantLands, wantLoc, res.Body)
		}
		if !reached {
			return
		}
		var got struct {
			Method string `json:"method"`
			Name   string `json:"name"`
		}
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		wantMethod := method
		wantName := ""
		if post {
			wantName = name
		}
		if post && k > 0 && (code == http.StatusMovedPermanently || code == http.StatusFound || code == http.StatusSeeOther) {
			wantMethod = http.MethodGet
			wantName = ""
		}
		if got.Method != wantMethod || got.Name != wantName {
			ht.Fatalf("land %+v want %s %q", got, wantMethod, wantName)
		}
	})
}

func TestPropSessionRoundTrip(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		secret := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		value := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301XYZ019").MaxSize(12))
		n := hegel.Draw(ht, hegel.Integers(-5, 20))
		same := hegel.Draw(ht, hegel.Integers(0, 2))
		secure := hegel.Draw(ht, hegel.Booleans())
		maxPick := hegel.Draw(ht, hegel.Integers(0, 3))
		maxAge := []int{0, 1, 30, 120}[maxPick]
		sameSite := http.SameSiteLaxMode
		switch same {
		case 1:
			sameSite = http.SameSiteStrictMode
		case 2:
			sameSite = http.SameSiteNoneMode
			secure = true
		}
		cfg := gfast.SessionConfig{Secret: secret, Secure: secure, MaxAge: maxAge, SameSite: sameSite}
		app := gfast.New(gfast.Sessions(cfg))
		app.Post("/set", func(ctx context.Context, in *struct {
			V string `json:"v"`
			N int    `json:"n"`
		}) (*struct{}, error) {
			gfast.SessionFrom(ctx)["user"] = in.V
			gfast.SessionFrom(ctx)["n"] = in.N
			return &struct{}{}, nil
		})
		read := func(ctx context.Context, in *struct{}) (*struct {
			User  string  `json:"user"`
			N     float64 `json:"n"`
			NType string  `json:"ntype"`
		}, error) {
			user, _ := gfast.SessionFrom(ctx)["user"].(string)
			var num float64
			kind := "missing"
			switch v := gfast.SessionFrom(ctx)["n"].(type) {
			case float64:
				num = v
				kind = "float64"
			case nil:
			default:
				kind = "other"
			}
			return &struct {
				User  string  `json:"user"`
				N     float64 `json:"n"`
				NType string  `json:"ntype"`
			}{User: user, N: num, NType: kind}, nil
		}
		app.Get("/get", read)
		app.Post("/clear", func(ctx context.Context, in *struct{}) (*struct{}, error) {
			sess := gfast.SessionFrom(ctx)
			for key := range sess {
				delete(sess, key)
			}
			return nil, nil
		})
		app.Post("/err", func(ctx context.Context, in *struct {
			V string `json:"v"`
			N int    `json:"n"`
		}) (*struct{}, error) {
			gfast.SessionFrom(ctx)["user"] = in.V
			gfast.SessionFrom(ctx)["n"] = in.N
			return nil, gfast.BadRequest("nope")
		})

		payload := []byte(`{"v":"` + value + `","n":` + strconv.Itoa(n) + `}`)
		set := app.Request(http.MethodPost, "/set", payload)
		if set.Status != http.StatusOK {
			ht.Fatalf("set %d %s", set.Status, set.Body)
		}
		cookie := pendCookie(ht, set, "session")
		if !cookie.HttpOnly || cookie.Path != "/" || cookie.Secure != secure || cookie.SameSite != sameSite || cookie.MaxAge != maxAge || cookie.Value == "" {
			ht.Fatalf("cookie %+v cfg secure %v same %v age %d", cookie, secure, sameSite, maxAge)
		}
		header := http.Header{"Cookie": []string{"session=" + cookie.Value}}
		got := pendReadSession(ht, app.Request(http.MethodGet, "/get", nil, header))
		if got.User != value || got.N != float64(n) || got.NType != "float64" {
			ht.Fatalf("round trip %+v want %q %d", got, value, n)
		}
		if app.Request(http.MethodGet, "/get", nil, header).Header.Get("Set-Cookie") != "" {
			ht.Fatalf("unchanged set-cookie")
		}
		bare := pendReadSession(ht, app.Request(http.MethodGet, "/get", nil))
		if bare.User != "" || bare.N != 0 || bare.NType != "missing" || app.Request(http.MethodGet, "/get", nil).Header.Get("Set-Cookie") != "" {
			ht.Fatalf("missing cookie %+v", bare)
		}
		tampered := pendTamper(cookie.Value)
		bad := pendReadSession(ht, app.Request(http.MethodGet, "/get", nil, http.Header{"Cookie": []string{"session=" + tampered}}))
		if bad.User != "" || bad.NType != "missing" {
			ht.Fatalf("tamper %+v", bad)
		}
		if app.Request(http.MethodGet, "/get", nil, http.Header{"Cookie": []string{"session=" + tampered}}).Header.Get("Set-Cookie") != "" {
			ht.Fatalf("tamper set-cookie")
		}
		other := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: secret + "x", Secure: secure, MaxAge: maxAge, SameSite: sameSite}))
		other.Get("/get", read)
		wrong := pendReadSession(ht, other.Request(http.MethodGet, "/get", nil, header))
		if wrong.User != "" || wrong.NType != "missing" {
			ht.Fatalf("other secret %+v", wrong)
		}
		cleared := app.Request(http.MethodPost, "/clear", nil, header)
		if cleared.Status != http.StatusNoContent {
			ht.Fatalf("clear %d %s", cleared.Status, cleared.Body)
		}
		gone := pendCookie(ht, cleared, "session")
		if gone.MaxAge >= 0 || gone.Value != "" {
			ht.Fatalf("clear cookie %+v", gone)
		}
		failed := app.Request(http.MethodPost, "/err", payload)
		hpProblem(ht, failed, http.StatusBadRequest, "nope")
		saved := pendCookie(ht, failed, "session")
		kept := pendReadSession(ht, app.Request(http.MethodGet, "/get", nil, http.Header{"Cookie": []string{"session=" + saved.Value}}))
		if kept.User != value || kept.N != float64(n) || kept.NType != "float64" {
			ht.Fatalf("error saved %+v", kept)
		}
	})
}

func TestPropSessionCSRF(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		methods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
		method := methods[hegel.Draw(ht, hegel.Integers(0, len(methods)-1))]
		cookieMode := hegel.Draw(ht, hegel.Integers(0, 2))
		site := []string{"", "cross-site", "CROSS-SITE", "same-origin", "same-site", "none"}[hegel.Draw(ht, hegel.Integers(0, 5))]
		origins := []string{"", "https://example.com", "https://EXAMPLE.com", "https://example.com:443", "https://evil.test", "https://files.example", "null", "https://example.com/page"}
		origin := origins[hegel.Draw(ht, hegel.Integers(0, len(origins)-1))]
		referers := []string{"", "https://example.com/page?q=1", "https://evil.test/x", "https://files.example/a"}
		referer := referers[hegel.Draw(ht, hegel.Integers(0, len(referers)-1))]
		sessions := hegel.Draw(ht, hegel.Booleans())
		noCSRF := hegel.Draw(ht, hegel.Booleans())
		listed := hegel.Draw(ht, hegel.Booleans())
		skip := hegel.Draw(ht, hegel.Booleans())

		var opts []gfast.Option
		if sessions {
			opts = append(opts, gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}))
		}
		if noCSRF {
			opts = append(opts, gfast.NoCSRF())
		}
		var extra []string
		if listed {
			opts = append(opts, gfast.CSRFOrigins("https://files.example"))
			extra = []string{"files.example"}
		}
		app := gfast.New(opts...)
		var hits int
		handle := func(ctx context.Context, in *struct{}) (*struct {
			OK bool `json:"ok"`
		}, error) {
			hits++
			return &struct {
				OK bool `json:"ok"`
			}{OK: true}, nil
		}
		var routeOpts []gfast.Option
		if skip {
			routeOpts = append(routeOpts, gfast.SkipCSRF())
		}
		app.Get("/do", handle, routeOpts...)
		app.Post("/do", handle, routeOpts...)
		app.Put("/do", handle, routeOpts...)
		app.Patch("/do", handle, routeOpts...)
		app.Delete("/do", handle, routeOpts...)

		header := http.Header{}
		cookie := ""
		switch cookieMode {
		case 1:
			header.Set("Cookie", "session=")
		case 2:
			cookie = "abc"
			header.Set("Cookie", "session="+cookie)
		}
		if site != "" {
			header.Set("Sec-Fetch-Site", site)
		}
		if origin != "" {
			header.Set("Origin", origin)
		}
		if referer != "" {
			header.Set("Referer", referer)
		}
		res := app.Request(method, "/do", nil, header)
		blocked := pendCSRFBlocked(sessions, noCSRF, false, skip, method, cookie, site, origin, referer, extra)
		if blocked {
			if hits != 0 {
				ht.Fatalf("handler ran")
			}
			hpProblem(ht, res, http.StatusForbidden, "csrf check failed")
			return
		}
		want := http.StatusOK
		if method == http.MethodHead {
			if res.Status != http.StatusOK || len(res.Body) != 0 || hits != 1 {
				ht.Fatalf("head %d hits %d body %q", res.Status, hits, res.Body)
			}
			return
		}
		if res.Status != want || hits != 1 {
			ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
		}
	})
}

func TestPropCSRFStrict(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		site := []string{"", "cross-site", "same-site", "SAME-SITE", "same-origin", "none"}[hegel.Draw(ht, hegel.Integers(0, 5))]
		withCookie := hegel.Draw(ht, hegel.Booleans())
		method := http.MethodPost
		if hegel.Draw(ht, hegel.Booleans()) {
			method = http.MethodGet
		}
		app := gfast.New(
			gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}),
			gfast.CSRFStrict(),
		)
		var hits int
		handle := func(ctx context.Context, in *struct{}) (*struct {
			OK bool `json:"ok"`
		}, error) {
			hits++
			return &struct {
				OK bool `json:"ok"`
			}{OK: true}, nil
		}
		app.Get("/do", handle)
		app.Post("/do", handle)
		header := http.Header{}
		cookie := ""
		if withCookie {
			cookie = "abc"
			header.Set("Cookie", "session="+cookie)
		}
		if site != "" {
			header.Set("Sec-Fetch-Site", site)
		}
		res := app.Request(method, "/do", nil, header)
		blocked := pendCSRFBlocked(true, false, true, false, method, cookie, site, "", "", nil)
		if blocked {
			if hits != 0 {
				ht.Fatalf("handler ran")
			}
			hpProblem(ht, res, http.StatusForbidden, "csrf check failed")
			return
		}
		if res.Status != http.StatusOK || hits != 1 {
			ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
		}
	})
}

func TestPropCSRFToken(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		strict := hegel.Draw(ht, hegel.Booleans())
		site := []string{"", "cross-site", "same-site", "same-origin"}[hegel.Draw(ht, hegel.Integers(0, 3))]
		headerMode := hegel.Draw(ht, hegel.Integers(0, 3))
		formMode := hegel.Draw(ht, hegel.Integers(0, 2))
		skip := hegel.Draw(ht, hegel.Booleans())
		tamper := hegel.Draw(ht, hegel.Booleans())
		opts := []gfast.Option{
			gfast.Sessions(gfast.SessionConfig{Secret: "test-secret", Secure: true}),
			gfast.CSRFToken(),
		}
		if strict {
			opts = append(opts, gfast.CSRFStrict())
		}
		app := gfast.New(opts...)
		app.Get("/token", func(ctx context.Context, in *struct{}) (*struct {
			Token string `json:"token"`
		}, error) {
			return &struct {
				Token string `json:"token"`
			}{Token: gfast.CSRFTokenFrom(ctx)}, nil
		})
		var hits int
		handle := func(ctx context.Context, in *struct{}) (*struct {
			Token string `json:"token"`
		}, error) {
			hits++
			return &struct {
				Token string `json:"token"`
			}{Token: gfast.CSRFTokenFrom(ctx)}, nil
		}
		app.Post("/do", handle)
		app.Post("/open", handle, gfast.SkipCSRF())

		first := app.Request(http.MethodGet, "/token", nil)
		if first.Status != http.StatusOK {
			ht.Fatalf("token %d %s", first.Status, first.Body)
		}
		var primed struct {
			Token string `json:"token"`
		}
		if err := first.JSON(&primed); err != nil || primed.Token == "" {
			ht.Fatalf("body %s err %v", first.Body, err)
		}
		session := pendCookie(ht, first, "session")
		csrf := pendCookie(ht, first, "csrf_token")
		if csrf.Value != primed.Token || csrf.HttpOnly || !csrf.Secure || csrf.Path != "/" {
			ht.Fatalf("csrf cookie %+v", csrf)
		}
		if !session.HttpOnly || session.Value == "" || session.Path != "/" {
			ht.Fatalf("session cookie %+v", session)
		}
		again := app.Request(http.MethodGet, "/token", nil, http.Header{"Cookie": []string{"session=" + session.Value + "; csrf_token=" + csrf.Value}})
		var kept struct {
			Token string `json:"token"`
		}
		if again.Status != http.StatusOK || again.JSON(&kept) != nil || kept.Token != primed.Token || again.Header.Get("Set-Cookie") != "" {
			ht.Fatalf("again %d cookie %q body %s", again.Status, again.Header.Get("Set-Cookie"), again.Body)
		}

		cookie := session.Value
		if tamper {
			cookie = pendTamper(session.Value)
		}
		header := http.Header{"Cookie": []string{"session=" + cookie}}
		if site != "" {
			header.Set("Sec-Fetch-Site", site)
		}
		sentHeader := ""
		switch headerMode {
		case 1:
			sentHeader = primed.Token
		case 2:
			sentHeader = " " + primed.Token + " "
		case 3:
			sentHeader = "nope"
		}
		if headerMode != 0 {
			header.Set("X-CSRF-Token", sentHeader)
		}
		form := ""
		var body []byte
		switch formMode {
		case 1:
			form = primed.Token
		case 2:
			form = "nope"
		}
		if formMode != 0 {
			header.Set("Content-Type", "application/x-www-form-urlencoded")
			body = []byte(url.Values{"csrf_token": {strings.TrimSpace(form)}}.Encode())
		}
		path := "/do"
		if skip {
			path = "/open"
		}
		res := app.Request(http.MethodPost, path, body, header)
		sourceBlocked := pendCSRFBlocked(true, false, strict, skip, http.MethodPost, "abc", site, "", "", nil)
		tokenOK := pendTokenOK(primed.Token, sentHeader, form)
		blocked := sourceBlocked || (!skip && !tamper && !tokenOK) || (!skip && tamper)
		if blocked {
			if hits != 0 {
				ht.Fatalf("handler ran")
			}
			hpProblem(ht, res, http.StatusForbidden, "csrf check failed")
			return
		}
		var got struct {
			Token string `json:"token"`
		}
		if res.Status != http.StatusOK || hits != 1 || res.JSON(&got) != nil {
			ht.Fatalf("accepted %d hits %d body %s", res.Status, hits, res.Body)
		}
		if !tamper && got.Token != primed.Token {
			ht.Fatalf("token %q want %q", got.Token, primed.Token)
		}
	})
}

func TestPropSkipCSRF(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		target := hegel.Draw(ht, hegel.Integers(0, 2))
		app := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}))
		var hits int
		handle := func(ctx context.Context, in *struct{}) (*struct {
			OK bool `json:"ok"`
		}, error) {
			hits++
			return &struct {
				OK bool `json:"ok"`
			}{OK: true}, nil
		}
		app.Post("/do", handle)
		app.Post("/open", handle, gfast.SkipCSRF())
		g := app.Group("/group", gfast.SkipCSRF())
		g.Post("/open", handle)
		paths := []string{"/do", "/open", "/group/open"}
		header := http.Header{
			"Cookie":         []string{"session=abc"},
			"Sec-Fetch-Site": []string{"cross-site"},
		}
		res := app.Request(http.MethodPost, paths[target], nil, header)
		if target == 0 {
			if hits != 0 {
				ht.Fatalf("handler ran")
			}
			hpProblem(ht, res, http.StatusForbidden, "csrf check failed")
			return
		}
		if res.Status != http.StatusOK || hits != 1 {
			ht.Fatalf("skip %d hits %d body %s", res.Status, hits, res.Body)
		}
	})
}

func TestPropBearerWithoutSessionCookie(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete}
		method := methods[hegel.Draw(ht, hegel.Integers(0, len(methods)-1))]
		withCookie := hegel.Draw(ht, hegel.Booleans())
		token := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		app := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}))
		var hits int
		handle := func(ctx context.Context, in *struct{}) (*struct {
			OK bool `json:"ok"`
		}, error) {
			hits++
			return &struct {
				OK bool `json:"ok"`
			}{OK: true}, nil
		}
		app.Get("/do", handle)
		app.Post("/do", handle)
		app.Put("/do", handle)
		app.Delete("/do", handle)
		header := http.Header{
			"Authorization":  []string{"Bearer " + token},
			"Sec-Fetch-Site": []string{"cross-site"},
		}
		cookie := ""
		if withCookie {
			cookie = "abc"
			header.Set("Cookie", "session="+cookie)
		}
		res := app.Request(method, "/do", nil, header)
		blocked := pendCSRFBlocked(true, false, false, false, method, cookie, "cross-site", "", "", nil)
		if blocked {
			if hits != 0 {
				ht.Fatalf("handler ran")
			}
			hpProblem(ht, res, http.StatusForbidden, "csrf check failed")
			return
		}
		if res.Status != http.StatusOK || hits != 1 {
			ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
		}
	})
}

func pendWrapOrder(ids []string, handler bool) []string {
	var order []string
	for _, id := range ids {
		order = append(order, id+"-in")
	}
	if handler {
		order = append(order, "handler")
	}
	for i := len(ids) - 1; i >= 0; i-- {
		order = append(order, ids[i]+"-out")
	}
	return order
}

func pendCORSAllows(origins, patterns []string, credentials bool, origin string) bool {
	if origin == "" {
		return false
	}
	exact := map[string]struct{}{}
	allowAll := len(origins) == 0
	var globs []*regexp.Regexp
	for _, item := range origins {
		if item == "*" {
			allowAll = true
			continue
		}
		if strings.Contains(item, "*") {
			globs = append(globs, pendOriginGlob(item))
			continue
		}
		exact[item] = struct{}{}
	}
	for _, pattern := range patterns {
		globs = append(globs, regexp.MustCompile(`\A(?:`+pattern+`)\z`))
	}
	if _, ok := exact[origin]; ok {
		return true
	}
	for _, re := range globs {
		if re.MatchString(origin) {
			return true
		}
	}
	return allowAll && !credentials
}

func pendOriginGlob(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString(`\A`)
	for _, r := range pattern {
		if r == '*' {
			b.WriteString(".*")
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	b.WriteString(`\z`)
	return regexp.MustCompile(b.String())
}

func pendExpose(values []string) string {
	var out []string
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return strings.Join(out, ", ")
}

func pendAcceptsGzip(header string) bool {
	best := 0.0
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := part
		q := 1.0
		if i := strings.Index(part, ";"); i >= 0 {
			name = strings.TrimSpace(part[:i])
			q = pendCodingQuality(part[i+1:])
		}
		name = strings.ToLower(name)
		if name != "gzip" && name != "*" {
			continue
		}
		if q > best {
			best = q
		}
	}
	return best > 0
}

func pendCodingQuality(param string) float64 {
	for _, piece := range strings.Split(param, ";") {
		piece = strings.TrimSpace(piece)
		raw, ok := strings.CutPrefix(strings.ToLower(piece), "q=")
		if !ok {
			continue
		}
		q, err := strconv.ParseFloat(raw, 64)
		if err != nil || q < 0 {
			return 0
		}
		if q > 1 {
			return 1
		}
		return q
	}
	return 0
}

func pendGunzip(body []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func pendServe(app *gfast.App, method, target, host string) *gfast.Result {
	req := httptest.NewRequest(method, target, nil)
	if host != "" {
		req.Host = host
	}
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	payload, _ := io.ReadAll(res.Body)
	return &gfast.Result{Status: res.StatusCode, Header: res.Header.Clone(), Body: payload}
}

func pendCSRFBlocked(sessions, noCSRF, strict, skip bool, method, cookie, site, origin, referer string, extra []string) bool {
	if !sessions || noCSRF || skip {
		return false
	}
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	if cookie == "" {
		return false
	}
	if strings.TrimSpace(site) != "" {
		if strings.EqualFold(site, "cross-site") {
			return true
		}
		if strict && strings.EqualFold(site, "same-site") {
			return true
		}
		return false
	}
	raw := strings.TrimSpace(origin)
	if raw == "" {
		raw = strings.TrimSpace(referer)
	}
	if raw == "" {
		return false
	}
	host, ok := pendOriginHost(raw)
	if !ok {
		return true
	}
	if host == "example.com" {
		return false
	}
	for _, allowed := range extra {
		if host == allowed {
			return false
		}
	}
	return true
}

func pendOriginHost(raw string) (string, bool) {
	if raw == "" || strings.EqualFold(raw, "null") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	host := u.Hostname()
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return "", false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host, true
}

func pendTokenOK(token, header, form string) bool {
	if token == "" {
		return false
	}
	if strings.TrimSpace(header) == token || strings.TrimSpace(form) == token {
		return true
	}
	return false
}

func pendFlip(b byte) string {
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	if b != alpha[0] {
		return alpha[:1]
	}
	return alpha[1:2]
}

// pendTamper flips the first signature character. The last base64 digit can
// change without changing the decoded HMAC.
func pendTamper(value string) string {
	pos := 0
	if i := strings.IndexByte(value, '.'); i >= 0 && i+1 < len(value) {
		pos = i + 1
	}
	if value == "" {
		return "x"
	}
	return value[:pos] + pendFlip(value[pos]) + value[pos+1:]
}

type pendSess struct {
	User  string  `json:"user"`
	N     float64 `json:"n"`
	NType string  `json:"ntype"`
}

func pendReadSession(ht *hegel.T, res *gfast.Result) pendSess {
	ht.Helper()
	if res.Status != http.StatusOK {
		ht.Fatalf("session read %d %s", res.Status, res.Body)
	}
	var got pendSess
	if err := res.JSON(&got); err != nil {
		ht.Fatal(err)
	}
	return got
}

func pendCookie(ht *hegel.T, res *gfast.Result, name string) *http.Cookie {
	ht.Helper()
	for _, c := range (&http.Response{Header: res.Header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	ht.Fatalf("cookie %s missing in %v", name, res.Header)
	return nil
}

func pendSpec(ht *hegel.T, app *gfast.App) map[string]any {
	ht.Helper()
	res := app.Request(http.MethodGet, "/openapi.json", nil)
	if res.Status != http.StatusOK {
		ht.Fatalf("openapi %d %s", res.Status, res.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(res.Body, &doc); err != nil {
		ht.Fatal(err)
	}
	return doc
}

func pendOp(ht *hegel.T, doc map[string]any, path, method string) map[string]any {
	ht.Helper()
	paths := pendObj(ht, doc["paths"], "paths")
	item := pendObj(ht, paths[path], path)
	return pendObj(ht, item[method], method)
}

func pendMediaSchema(ht *hegel.T, op map[string]any, request bool) map[string]any {
	ht.Helper()
	var content map[string]any
	if request {
		body := pendObj(ht, op["requestBody"], "requestBody")
		content = pendObj(ht, body["content"], "content")
	} else {
		responses := pendObj(ht, op["responses"], "responses")
		resp := pendObj(ht, responses["200"], "200")
		content = pendObj(ht, resp["content"], "content")
	}
	media := pendObj(ht, content["application/json"], "json")
	return pendObj(ht, media["schema"], "schema")
}

func pendSchemas(ht *hegel.T, doc map[string]any) map[string]any {
	ht.Helper()
	comps, _ := doc["components"].(map[string]any)
	if comps == nil {
		return nil
	}
	schemas, _ := comps["schemas"].(map[string]any)
	return schemas
}

func pendObj(ht *hegel.T, v any, what string) map[string]any {
	ht.Helper()
	obj, ok := v.(map[string]any)
	if !ok {
		ht.Fatalf("%s %#v", what, v)
	}
	return obj
}

func pendStr(v any) string {
	s, _ := v.(string)
	return s
}

func pendNum(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}
