package gfast_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pyrex41/gfast"
)

func TestPropUnmatchedProblemJSON(t *testing.T) {
	app := gfast.New()
	app.Get("/only", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})
	app.Post("/only", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})

	missing := app.Request(http.MethodGet, "/missing", nil)
	assertProblem(t, missing, http.StatusNotFound, "Not Found")
	if missing.Header.Get("Allow") != "" {
		t.Fatalf("allow %q", missing.Header.Get("Allow"))
	}
	head := app.Request(http.MethodHead, "/missing", nil)
	if head.Status != http.StatusNotFound || len(head.Body) != 0 || head.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("head %d type %s body %q", head.Status, head.Header.Get("Content-Type"), head.Body)
	}
	wrong := app.Request(http.MethodDelete, "/only", nil)
	assertProblem(t, wrong, http.StatusMethodNotAllowed, "Method Not Allowed")
	if wrong.Header.Get("Allow") != "GET, HEAD, POST" {
		t.Fatalf("allow %q", wrong.Header.Get("Allow"))
	}

	app.Get("/gone", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		return nil, gfast.NotFound("gone")
	})
	assertProblem(t, app.Request(http.MethodGet, "/gone", nil), http.StatusNotFound, "gone")
}

func TestPropMountAndStatic(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "nested.txt"), []byte("nest"), 0o644); err != nil {
		t.Fatal(err)
	}

	var saw string
	app := gfast.New()
	app.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-MW", "1")
			next.ServeHTTP(w, r)
		})
	})
	app.Get("/only", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		return &struct{ OK bool }{OK: true}, nil
	})
	app.Mount("/extra", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		saw = r.URL.Path + "?" + r.URL.RawQuery
		if r.URL.Path == "/plain" {
			http.Error(w, "custom missing", http.StatusNotFound)
			return
		}
		if r.URL.Path == "/json" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"keep":true}`))
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("mounted"))
	}))
	gfast.Static(app.Group("/v1"), "/assets", dir)

	got := app.Request(http.MethodGet, "/extra/a/b?x=1", nil)
	if got.Status != http.StatusOK || string(got.Body) != "mounted" || saw != "/a/b?x=1" || got.Header.Get("X-MW") != "1" {
		t.Fatalf("mount %d saw %q mw %q body %s", got.Status, saw, got.Header.Get("X-MW"), got.Body)
	}
	root := app.Request(http.MethodGet, "/extra/", nil)
	if root.Status != http.StatusOK || saw != "/?" {
		t.Fatalf("mount root %d saw %q", root.Status, saw)
	}
	redir := app.Request(http.MethodGet, "/extra?x=1", nil)
	if redir.Status != http.StatusTemporaryRedirect || redir.Header.Get("Location") != "/extra/?x=1" {
		t.Fatalf("redirect %d location %q", redir.Status, redir.Header.Get("Location"))
	}
	custom := app.Request(http.MethodGet, "/extra/plain", nil)
	assertProblem(t, custom, http.StatusNotFound, "custom missing")
	kept := app.Request(http.MethodGet, "/extra/json", nil)
	if kept.Status != http.StatusNotFound || kept.Header.Get("Content-Type") != "application/json" || string(kept.Body) != `{"keep":true}` {
		t.Fatalf("kept %d type %s body %s", kept.Status, kept.Header.Get("Content-Type"), kept.Body)
	}

	file := app.Request(http.MethodGet, "/v1/assets/hello.txt", nil)
	if file.Status != http.StatusOK || string(file.Body) != "hi" || !strings.Contains(file.Header.Get("Content-Type"), "text/plain") || file.Header.Get("X-MW") != "1" {
		t.Fatalf("file %d type %s body %q", file.Status, file.Header.Get("Content-Type"), file.Body)
	}
	nested := app.Request(http.MethodGet, "/v1/assets/sub/nested.txt", nil)
	if nested.Status != http.StatusOK || string(nested.Body) != "nest" {
		t.Fatalf("nested %d %s", nested.Status, nested.Body)
	}
	fileHead := app.Request(http.MethodHead, "/v1/assets/hello.txt", nil)
	if fileHead.Status != http.StatusOK || len(fileHead.Body) != 0 || !strings.Contains(fileHead.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("file head %d type %s body %q", fileHead.Status, fileHead.Header.Get("Content-Type"), fileHead.Body)
	}
	miss := app.Request(http.MethodGet, "/v1/assets/missing.txt", nil)
	assertProblem(t, miss, http.StatusNotFound, "Not Found")
	if miss.Header.Get("X-MW") != "1" {
		t.Fatalf("static miss mw %q", miss.Header.Get("X-MW"))
	}
	post := app.Request(http.MethodPost, "/v1/assets/hello.txt", nil)
	assertProblem(t, post, http.StatusMethodNotAllowed, "Method Not Allowed")
	if post.Header.Get("Allow") != "GET, HEAD" || strings.Contains(string(post.Body), "hi") {
		t.Fatalf("static method %d allow %q body %s", post.Status, post.Header.Get("Allow"), post.Body)
	}
	slash := app.Request(http.MethodGet, "/v1/assets?x=1", nil)
	if slash.Status != http.StatusTemporaryRedirect || slash.Header.Get("Location") != "/v1/assets/?x=1" {
		t.Fatalf("static redirect %d %q", slash.Status, slash.Header.Get("Location"))
	}
	up := app.Request(http.MethodGet, "/v1/assets/../secret.txt", nil)
	if up.Status != http.StatusTemporaryRedirect || up.Header.Get("Location") != "/v1/secret.txt" {
		t.Fatalf("escape %d location %q body %s", up.Status, up.Header.Get("Location"), up.Body)
	}
	spec := app.Request(http.MethodGet, "/openapi.json", nil)
	if spec.Status != http.StatusOK || strings.Contains(string(spec.Body), "/v1/assets") || strings.Contains(string(spec.Body), "/extra") {
		t.Fatalf("spec leaked mount %s", spec.Body)
	}

	mustPanic(t, "nil handler", func() { app.Mount("/nope", nil) })
	mustPanic(t, "empty directory", func() { app.Static("/nope", " ") })
}
