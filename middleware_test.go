package gfast_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pyrex41/gfast"
)

func TestUseOrderAndCORSOutside(t *testing.T) {
	var order []string
	app := gfast.New(gfast.CORS("https://example.com"))
	app.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "a-in")
			w.Header().Set("X-From-MW", "a")
			next.ServeHTTP(w, r)
			order = append(order, "a-out")
		})
	})
	app.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "b-in")
			next.ServeHTTP(w, r)
			order = append(order, "b-out")
		})
	})
	app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		order = append(order, "handler")
		return &struct{ OK bool }{OK: true}, nil
	})

	pre := app.Request(http.MethodOptions, "/ping", nil, http.Header{"Origin": []string{"https://example.com"}})
	if pre.Status != http.StatusNoContent || pre.Header.Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Fatalf("preflight %d %q", pre.Status, pre.Header.Get("Access-Control-Allow-Origin"))
	}
	if len(order) != 0 || pre.Header.Get("X-From-MW") != "" {
		t.Fatalf("middleware ran on preflight %v %q", order, pre.Header.Get("X-From-MW"))
	}

	res := app.Request(http.MethodGet, "/ping", nil, http.Header{"Origin": []string{"https://example.com"}})
	if res.Status != http.StatusOK || res.Header.Get("X-From-MW") != "a" {
		t.Fatalf("get %d mw %q", res.Status, res.Header.Get("X-From-MW"))
	}
	if res.Header.Get("Access-Control-Allow-Origin") != "https://example.com" || res.Header.Get("Vary") != "Origin" {
		t.Fatalf("cors origin %q vary %q", res.Header.Get("Access-Control-Allow-Origin"), res.Header.Get("Vary"))
	}
	if strings.Join(order, ",") != "a-in,b-in,handler,b-out,a-out" {
		t.Fatalf("order %v", order)
	}

	mustPanic(t, "nil", func() { app.Use(nil) })
}

func TestCORSCredentialsPatternsAndLimits(t *testing.T) {
	open := gfast.New(gfast.CORS(), gfast.AllowCredentials(true))
	open.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})
	echo := open.Request(http.MethodGet, "/ping", nil, http.Header{"Origin": []string{"https://anywhere.example"}})
	if echo.Header.Get("Access-Control-Allow-Origin") != "" || echo.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("arbitrary origin echoed %q cred %q", echo.Header.Get("Access-Control-Allow-Origin"), echo.Header.Get("Access-Control-Allow-Credentials"))
	}

	star := gfast.New(gfast.CORS("*"), gfast.AllowCredentials(true))
	star.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})
	starred := star.Request(http.MethodGet, "/ping", nil, http.Header{"Origin": []string{"https://anywhere.example"}})
	if starred.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("star with credentials echoed %q", starred.Header.Get("Access-Control-Allow-Origin"))
	}

	app := gfast.New(
		gfast.CORS("https://ok.example", "https://*.example.com"),
		gfast.AllowOriginPattern(`https://api[.]docs[.]example`),
		gfast.AllowCredentials(true),
		gfast.ExposeHeaders("X-Request-Id", "X-Request-Id", " X-Trace "),
		gfast.MaxAge(600),
	)
	app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})

	ok := app.Request(http.MethodOptions, "/ping", nil, http.Header{"Origin": []string{"https://ok.example"}})
	if ok.Status != http.StatusNoContent {
		t.Fatalf("preflight %d", ok.Status)
	}
	if ok.Header.Get("Access-Control-Allow-Origin") != "https://ok.example" || ok.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("allow %q cred %q", ok.Header.Get("Access-Control-Allow-Origin"), ok.Header.Get("Access-Control-Allow-Credentials"))
	}
	if ok.Header.Get("Access-Control-Max-Age") != "600" {
		t.Fatalf("max-age %q", ok.Header.Get("Access-Control-Max-Age"))
	}
	if ok.Header.Get("Access-Control-Expose-Headers") != "" {
		t.Fatalf("expose on preflight %q", ok.Header.Get("Access-Control-Expose-Headers"))
	}
	if ok.Header.Get("Vary") != "Origin" {
		t.Fatalf("vary %q", ok.Header.Get("Vary"))
	}

	wild := app.Request(http.MethodGet, "/ping", nil, http.Header{"Origin": []string{"https://a.example.com"}})
	if wild.Header.Get("Access-Control-Allow-Origin") != "https://a.example.com" || wild.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("glob %q cred %q", wild.Header.Get("Access-Control-Allow-Origin"), wild.Header.Get("Access-Control-Allow-Credentials"))
	}
	if wild.Header.Get("Access-Control-Expose-Headers") != "X-Request-Id, X-Trace" {
		t.Fatalf("expose %q", wild.Header.Get("Access-Control-Expose-Headers"))
	}
	if wild.Header.Get("Access-Control-Max-Age") != "" {
		t.Fatalf("max-age on get %q", wild.Header.Get("Access-Control-Max-Age"))
	}

	re := app.Request(http.MethodGet, "/ping", nil, http.Header{"Origin": []string{"https://api.docs.example"}})
	if re.Header.Get("Access-Control-Allow-Origin") != "https://api.docs.example" {
		t.Fatalf("regex %q", re.Header.Get("Access-Control-Allow-Origin"))
	}

	denied := app.Request(http.MethodGet, "/ping", nil, http.Header{"Origin": []string{"https://evil.example"}})
	if denied.Header.Get("Access-Control-Allow-Origin") != "" || denied.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("denied origin %q cred %q", denied.Header.Get("Access-Control-Allow-Origin"), denied.Header.Get("Access-Control-Allow-Credentials"))
	}

	plain := gfast.New(gfast.CORS())
	plain.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})
	anyOrigin := plain.Request(http.MethodGet, "/ping", nil, http.Header{"Origin": []string{"https://other.example"}})
	if anyOrigin.Header.Get("Access-Control-Allow-Origin") != "https://other.example" || anyOrigin.Header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("open cors %q cred %q", anyOrigin.Header.Get("Access-Control-Allow-Origin"), anyOrigin.Header.Get("Access-Control-Allow-Credentials"))
	}

	mustPanic(t, "negative", func() { gfast.New(gfast.MaxAge(-1)) })
	mustPanic(t, "origin pattern", func() { gfast.New(gfast.AllowOriginPattern("(")) })
}

func TestGzipSkipsEncodedAndEvents(t *testing.T) {
	var seen []byte
	app := gfast.New(gfast.Gzip())
	app.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tw := &tapWriter{ResponseWriter: w}
			next.ServeHTTP(tw, r)
			seen = append([]byte(nil), tw.buf...)
		})
	})
	app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})
	app.Get("/raw", func(ctx context.Context, in *struct{}) (*string, error) {
		gfast.ResponseFrom(ctx).SetContentType("application/octet-stream")
		gfast.ResponseFrom(ctx).Header().Set("Content-Encoding", "deflate")
		s := "raw-body"
		return &s, nil
	})
	app.Get("/events", func(ctx context.Context, in *struct{}) (*gfast.Events, error) {
		return gfast.SSE(func(ctx context.Context, send func(gfast.Event) error) error {
			return send(gfast.Event{Data: "hi"})
		}), nil
	})

	res := app.Request(http.MethodGet, "/ping", nil, http.Header{"Accept-Encoding": []string{"deflate, gzip;q=0.8"}})
	if res.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("encoding %q", res.Header.Get("Content-Encoding"))
	}
	if !strings.Contains(res.Header.Get("Vary"), "Accept-Encoding") {
		t.Fatalf("vary %q", res.Header.Get("Vary"))
	}
	plain := gunzipBody(t, res.Body)
	if string(plain) != `{"OK":true}` || string(seen) != `{"OK":true}` {
		t.Fatalf("plain %s seen %s", plain, seen)
	}

	off := app.Request(http.MethodGet, "/ping", nil, http.Header{"Accept-Encoding": []string{"gzip;q=0, identity"}})
	if off.Header.Get("Content-Encoding") != "" || string(off.Body) != `{"OK":true}` {
		t.Fatalf("q=0 encoding %q body %s", off.Header.Get("Content-Encoding"), off.Body)
	}

	raw := app.Request(http.MethodGet, "/raw", nil, http.Header{"Accept-Encoding": []string{"gzip"}})
	if raw.Header.Get("Content-Encoding") != "deflate" || string(raw.Body) != "raw-body" {
		t.Fatalf("encoded %q body %q", raw.Header.Get("Content-Encoding"), raw.Body)
	}

	ev := app.Request(http.MethodGet, "/events", nil, http.Header{"Accept-Encoding": []string{"gzip"}})
	if ev.Header.Get("Content-Encoding") != "" || ev.Header.Get("Content-Type") != "text/event-stream" || !strings.Contains(string(ev.Body), "data: hi\n") {
		t.Fatalf("sse encoding %q type %q body %q", ev.Header.Get("Content-Encoding"), ev.Header.Get("Content-Type"), ev.Body)
	}

	head := app.Request(http.MethodHead, "/ping", nil, http.Header{"Accept-Encoding": []string{"gzip"}})
	if head.Status != http.StatusOK || len(head.Body) != 0 || head.Header.Get("Content-Encoding") != "" {
		t.Fatalf("head %d encoding %q body %q", head.Status, head.Header.Get("Content-Encoding"), head.Body)
	}

	mustPanic(t, "out of range", func() { gfast.New(gfast.Gzip(99)) })
}

func TestTrustedHostAndHTTPSRedirect(t *testing.T) {
	var hits int
	app := gfast.New(gfast.TrustedHost("api.example", "*.good.test"), gfast.HTTPSRedirect())
	app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		hits++
		return &struct{ OK bool }{OK: true}, nil
	})

	foreign := app.Request(http.MethodGet, "/ping", nil)
	if foreign.Status != http.StatusBadRequest || hits != 0 || !strings.Contains(string(foreign.Body), "Invalid host header") {
		t.Fatalf("foreign %d hits %d body %s", foreign.Status, hits, foreign.Body)
	}

	req := httptest.NewRequest(http.MethodGet, "/ping?x=1", nil)
	req.Host = "a.good.test:8443"
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusTemporaryRedirect || hits != 0 || rec.Header().Get("Location") != "https://a.good.test:8443/ping?x=1" {
		t.Fatalf("redirect %d loc %q hits %d", rec.Code, rec.Header().Get("Location"), hits)
	}

	secure := httptest.NewRequest(http.MethodGet, "https://api.example/ping", nil)
	secure.Host = "API.Example"
	secure.TLS = &tls.ConnectionState{}
	okRec := httptest.NewRecorder()
	app.Handler().ServeHTTP(okRec, secure)
	if okRec.Code != http.StatusOK || hits != 1 {
		t.Fatalf("allowed %d hits %d", okRec.Code, hits)
	}

	apex := gfast.New(gfast.TrustedHost("www.example.com"))
	apex.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})
	www := apex.Request(http.MethodGet, "/ping", nil)
	if www.Status != http.StatusTemporaryRedirect || www.Header.Get("Location") != "http://www.example.com/ping" {
		t.Fatalf("www %d %q", www.Status, www.Header.Get("Location"))
	}

	anyHost := gfast.New(gfast.TrustedHost("*"))
	anyHost.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})
	if res := anyHost.Request(http.MethodGet, "/ping", nil); res.Status != http.StatusOK {
		t.Fatalf("any host %d", res.Status)
	}

	onlyHTTPS := gfast.New(gfast.HTTPSRedirect())
	onlyHTTPS.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		hits++
		return &struct{ OK bool }{OK: true}, nil
	})
	before := hits
	redir := onlyHTTPS.Request(http.MethodPost, "/ping?x=1", []byte(`{"a":1}`))
	if redir.Status != http.StatusTemporaryRedirect || redir.Header.Get("Location") != "https://example.com/ping?x=1" || hits != before {
		t.Fatalf("https %d loc %q hits %d", redir.Status, redir.Header.Get("Location"), hits)
	}

	mustPanic(t, "wildcard", func() { gfast.New(gfast.TrustedHost("*example.com")) })
	mustPanic(t, "requires", func() { gfast.New(gfast.TrustedHost()) })
}

type tapWriter struct {
	http.ResponseWriter
	buf []byte
}

func (t *tapWriter) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	return t.ResponseWriter.Write(p)
}

func gunzipBody(t *testing.T, body []byte) []byte {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
