package gfast

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	jsonv2 "encoding/json/v2"
)

type benchmarkBody struct {
	Name  string `json:"name" required:"true" minLength:"1" maxLength:"80"`
	Count int    `json:"count" ge:"1" le:"100"`
}

type benchmarkQuery struct {
	A string `query:"a"`
	B int    `query:"b"`
	C string `query:"c"`
	D int    `query:"d"`
	E string `query:"e"`
	F int    `query:"f"`
}

// A reusable writer avoids measuring ResponseRecorder's body buffering. Each
// iteration still creates a fresh request/body, identically for both servers.
type benchmarkWriter struct {
	header http.Header
	status int
}

func (w *benchmarkWriter) Header() http.Header         { return w.header }
func (w *benchmarkWriter) WriteHeader(n int)           { w.status = n }
func (w *benchmarkWriter) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkHTTP(b *testing.B) {
	app := New(Docs(false))
	app.Get("/json", func(context.Context, *struct{}) (*benchmarkBody, error) {
		return &benchmarkBody{Name: "widget", Count: 3}, nil
	})
	app.Get("/query", func(_ context.Context, in *benchmarkQuery) (*benchmarkQuery, error) { return in, nil })
	app.Post("/validated", func(_ context.Context, in *struct{ Body benchmarkBody }) (*benchmarkBody, error) {
		return &in.Body, nil
	})
	app.Get("/auth", func(context.Context, *struct{}) (*benchmarkBody, error) {
		return &benchmarkBody{Name: "widget", Count: 3}, nil
	}, Require(BearerAuth()))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /json", func(w http.ResponseWriter, r *http.Request) {
		payload, _ := jsonv2.Marshal(&benchmarkBody{Name: "widget", Count: 3})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(payload)
	})
	for _, tc := range []struct {
		name, method, target, body string
		handler                    http.Handler
		status                     int
	}{
		{"GfastJSON", "GET", "/json", "", app.Handler(), 200},
		{"NetHTTPJSON", "GET", "/json", "", mux, 200},
		{"Query6", "GET", "/query?a=one&b=2&c=three&d=4&e=five&f=6", "", app.Handler(), 200},
		{"Validated", "POST", "/validated", `{"name":"widget","count":3}`, app.Handler(), 200},
		{"Invalid", "POST", "/validated", `{"name":"","count":0}`, app.Handler(), 422},
		{"Auth", "GET", "/auth", "", app.Handler(), 200},
	} {
		b.Run(tc.name, func(b *testing.B) {
			w := &benchmarkWriter{header: make(http.Header)}
			b.ReportAllocs()
			for b.Loop() {
				clear(w.header)
				w.status = 0
				r, _ := http.NewRequest(tc.method, "http://example.com"+tc.target, bytes.NewBufferString(tc.body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Authorization", "Bearer test-token")
				tc.handler.ServeHTTP(w, r)
				if w.status != tc.status {
					b.Fatalf("status %d want %d", w.status, tc.status)
				}
			}
		})
	}
}

func BenchmarkBindQuery(b *testing.B) {
	plan := planInput(reflect.TypeFor[benchmarkQuery]())
	r := httptest.NewRequest("GET", "/?a=one&b=2&c=three&d=4&e=five&f=6", nil)
	b.ReportAllocs()
	for b.Loop() {
		var in benchmarkQuery
		if err := bindInput(r, reflect.ValueOf(&in).Elem(), plan); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJSON(b *testing.B) {
	v := benchmarkBody{Name: "widget", Count: 3}
	b.ReportAllocs()
	for b.Loop() {
		if err := jsonv2.MarshalWrite(io.Discard, &v); err != nil {
			b.Fatal(err)
		}
	}
}

// P01 is an allocation budget, not a timing assertion. It tolerates small
// toolchain changes while detecting the former per-field query parsing.
func TestQueryBindingAllocationBudget(t *testing.T) {
	plan := planInput(reflect.TypeFor[benchmarkQuery]())
	r := httptest.NewRequest("GET", "/?a=one&b=2&c=three&d=4&e=five&f=6", nil)
	allocs := testing.AllocsPerRun(100, func() {
		var in benchmarkQuery
		if err := bindInput(r, reflect.ValueOf(&in).Elem(), plan); err != nil {
			panic(err)
		}
	})
	if allocs > 32 {
		t.Fatalf("P01: %.0f allocations per six-field bind; budget 32", allocs)
	}
}
