package gfast

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"testing"
)

type benchmarkResource struct{}

func (*benchmarkResource) Close() error { return nil }

type benchmarkChild struct{ root *benchmarkResource }

var benchmarkRootProvider = Dep("benchmarkRoot", func(context.Context) (*benchmarkResource, error) { return &benchmarkResource{}, nil })
var benchmarkChildProvider = Dep("benchmarkChild", func(_ context.Context, root *benchmarkResource) (*benchmarkChild, error) {
	return &benchmarkChild{root}, nil
})

func benchmarkServe(b *testing.B, handler http.Handler, method, path string, body []byte, headers http.Header) {
	b.Helper()
	w := &benchmarkWriter{header: make(http.Header)}
	b.ReportAllocs()
	for b.Loop() {
		clear(w.header)
		w.status = 0
		r, _ := http.NewRequest(method, "http://example.com"+path, bytes.NewReader(body))
		r.Header = headers.Clone()
		handler.ServeHTTP(w, r)
		if w.status != 200 {
			b.Fatalf("unexpected status %d", w.status)
		}
	}
}

func BenchmarkDependencyGraph(b *testing.B) {
	app := New(Docs(false))
	app.Get("/", func(_ context.Context, in *struct {
		A *benchmarkChild    `gfast:"dep=benchmarkChild"`
		B *benchmarkResource `gfast:"dep=benchmarkRoot"`
	}) (*benchmarkBody, error) {
		if in.A.root != in.B {
			panic("memoization failed")
		}
		return &benchmarkBody{Name: "widget", Count: 3}, nil
	}, Require(BearerAuth()))
	benchmarkServe(b, app.Handler(), "GET", "/", nil, http.Header{"Authorization": {"Bearer benchmark"}})
}

func BenchmarkMultipart(b *testing.B) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("upload", "payload.bin")
	if err != nil {
		b.Fatal(err)
	}
	if _, err := part.Write(bytes.Repeat([]byte("x"), 4096)); err != nil {
		b.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		b.Fatal(err)
	}
	app := New(Docs(false))
	app.Post("/", func(_ context.Context, in *struct {
		File *multipart.FileHeader `file:"upload" required:"true"`
	}) (*benchmarkBody, error) {
		file, err := in.File.Open()
		if err != nil {
			return nil, err
		}
		defer file.Close()
		if _, err := io.Copy(io.Discard, file); err != nil {
			return nil, err
		}
		return &benchmarkBody{Name: in.File.Filename, Count: 1}, nil
	})
	benchmarkServe(b, app.Handler(), "POST", "/", body.Bytes(), http.Header{"Content-Type": {writer.FormDataContentType()}})
}

func BenchmarkSessionRoundTrip(b *testing.B) {
	app := New(Docs(false), Sessions(SessionConfig{Secret: "benchmark-only-secret"}))
	app.Get("/set", func(ctx context.Context, _ *struct{}) (*struct{}, error) {
		SessionFrom(ctx)["user"] = "ada"
		return &struct{}{}, nil
	})
	app.Get("/get", func(ctx context.Context, _ *struct{}) (*benchmarkBody, error) {
		return &benchmarkBody{Name: SessionFrom(ctx)["user"].(string), Count: 1}, nil
	})
	setup := app.Request("GET", "/set", nil)
	cookies := (&http.Response{Header: setup.Header}).Cookies()
	if len(cookies) != 1 {
		b.Fatal("missing session cookie")
	}
	benchmarkServe(b, app.Handler(), "GET", "/get", nil, http.Header{"Cookie": {cookies[0].Name + "=" + cookies[0].Value}})
}
