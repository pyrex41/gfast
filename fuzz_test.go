package gfast

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// FuzzJSONBinding exercises the public HTTP boundary, including the body cap.
// It asserts safety and that success actually dispatched the handler.
func FuzzJSONBinding(f *testing.F) {
	for _, s := range []string{`{"name":"ok","count":1}`, `{}`, `null`, `{"name":"a","name":"b"}`, "{\"name\":\"\xff\"}", `{"count":1e999}`, `[]`} {
		f.Add([]byte(s))
	}
	f.Add(bytes.Repeat([]byte(" "), 4097))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			t.Skip()
		}
		called := false
		app := New(Docs(false), MaxBodyBytes(4096))
		app.Post("/", func(_ context.Context, in *struct{ Body benchmarkBody }) (*benchmarkBody, error) {
			called = true
			return &in.Body, nil
		})
		r := httptest.NewRequest("POST", "/", bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, r)
		if !json.Valid(w.Body.Bytes()) {
			t.Fatalf("invalid response JSON: %q", w.Body.Bytes())
		}
		if w.Code != 200 && w.Code != 400 && w.Code != 413 && w.Code != 422 {
			t.Fatalf("unexpected status %d", w.Code)
		}
		if called != (w.Code == 200) {
			t.Fatalf("handler=%v status=%d", called, w.Code)
		}
		if len(data) > 4096 && w.Code != 413 {
			t.Fatalf("body cap bypass: %d", w.Code)
		}
	})
}

func FuzzMultipart(f *testing.F) {
	f.Add([]byte("--x--\r\n"), "multipart/form-data; boundary=x")
	f.Add([]byte("broken"), "multipart/form-data")
	f.Fuzz(func(t *testing.T, data []byte, contentType string) {
		if len(data) > 8192 || len(contentType) > 1024 {
			t.Skip()
		}
		app := New(Docs(false), MaxBodyBytes(4096))
		app.Post("/", func(_ context.Context, in *struct {
			Name string `form:"name" required:"true"`
		}) (*struct{}, error) {
			return &struct{}{}, nil
		})
		r := httptest.NewRequest("POST", "/", bytes.NewReader(data))
		r.Header.Set("Content-Type", contentType)
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, r)
		if w.Code >= 500 {
			t.Fatalf("malformed input caused %d: %s", w.Code, w.Body.String())
		}
	})
}

func FuzzAccessToken(f *testing.F) {
	key := []byte("fuzz-only-key-not-used-by-any-server")
	valid, err := signAccess(key, jwtClaims{Sub: "user", CID: "client", Exp: 12345})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add("")
	f.Add("e30.e30.invalid")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 8192 {
			t.Skip()
		}
		claims, err := parseAccess(key, raw)
		if err == nil && (claims.Sub != "user" || claims.CID != "client" || claims.Exp != 12345) {
			t.Fatalf("accepted forged claims: %+v", claims)
		}
	})
}
