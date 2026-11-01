package gfast_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pyrex41/gfast"
)

func TestDynamicStatusHeadersAndNil(t *testing.T) {
	app := gfast.New()
	app.Post("/made", func(ctx context.Context, in *struct{}) (*struct {
		ID string `json:"id"`
	}, error) {
		res := gfast.ResponseFrom(ctx)
		res.SetStatus(http.StatusAccepted)
		res.Header().Set("X-Trace", "abc")
		res.SetCookie(&http.Cookie{Name: "sid", Value: "xyz", Path: "/"})
		return &struct {
			ID string `json:"id"`
		}{ID: "1"}, nil
	}, gfast.Status(http.StatusCreated))
	app.Delete("/drop", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		res := gfast.ResponseFrom(ctx)
		res.SetStatus(http.StatusAccepted)
		res.Header().Set("X-Trace", "gone")
		res.SetCookie(&http.Cookie{Name: "sid", Value: "xyz", Path: "/"})
		return nil, nil
	}, gfast.Status(http.StatusCreated))

	made := app.Request(http.MethodPost, "/made", nil)
	if made.Status != http.StatusAccepted || made.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("made %d %s type %s", made.Status, made.Body, made.Header.Get("Content-Type"))
	}
	if made.Header.Get("X-Trace") != "abc" || !strings.Contains(made.Header.Get("Set-Cookie"), "sid=xyz") {
		t.Fatalf("made headers %#v", made.Header)
	}
	var got struct {
		ID string `json:"id"`
	}
	if err := made.JSON(&got); err != nil || got.ID != "1" {
		t.Fatalf("made body %s err %v", made.Body, err)
	}

	drop := app.Request(http.MethodDelete, "/drop", nil)
	if drop.Status != http.StatusNoContent || len(drop.Body) != 0 || drop.Header.Get("Content-Type") != "" {
		t.Fatalf("nil result %d type %q body %s", drop.Status, drop.Header.Get("Content-Type"), drop.Body)
	}
	if drop.Header.Get("X-Trace") != "gone" || !strings.Contains(drop.Header.Get("Set-Cookie"), "sid=xyz") {
		t.Fatalf("nil headers %#v", drop.Header)
	}

	mustPanic(t, "no request", func() {
		gfast.ResponseFrom(context.Background())
	})
}

func TestOutputValidateIsServerError(t *testing.T) {
	app := gfast.New()
	app.Get("/n", func(ctx context.Context, in *struct {
		N int `query:"n"`
	}) (*countedOut, error) {
		return &countedOut{N: in.N}, nil
	})

	ok := app.Request(http.MethodGet, "/n?n=2", nil)
	if ok.Status != http.StatusOK || ok.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("ok %d %s", ok.Status, ok.Body)
	}
	var got countedOut
	if err := ok.JSON(&got); err != nil || got.N != 2 {
		t.Fatalf("ok body %s err %v", ok.Body, err)
	}

	secret := app.Request(http.MethodGet, "/n?n=-1", nil)
	assertProblem(t, secret, http.StatusInternalServerError, "unexpected error occurred")
	if strings.Contains(string(secret.Body), "zz-secret-out") {
		t.Fatalf("validation detail leaked: %s", secret.Body)
	}
	statusErr := app.Request(http.MethodGet, "/n?n=1", nil)
	assertProblem(t, statusErr, http.StatusInternalServerError, "unexpected error occurred")
	if statusErr.Status == http.StatusBadRequest || strings.Contains(string(statusErr.Body), "zz-nope") {
		t.Fatalf("status error from Validate escaped: %d %s", statusErr.Status, statusErr.Body)
	}
}

type countedOut struct {
	N int `json:"n"`
}

func (c *countedOut) Validate() error {
	if c.N < 0 {
		return errors.New("zz-secret-out")
	}
	if c.N == 1 {
		return gfast.BadRequest("zz-nope")
	}
	return nil
}

func TestRawHTMLAndBytes(t *testing.T) {
	app := gfast.New()
	app.Get("/page", func(ctx context.Context, in *struct{}) (*string, error) {
		gfast.ResponseFrom(ctx).SetStatus(http.StatusCreated)
		gfast.ResponseFrom(ctx).SetContentType("text/html; charset=utf-8")
		s := "<p>Hi & co</p>"
		return &s, nil
	})
	app.Get("/plain", func(ctx context.Context, in *struct{}) (*string, error) {
		s := "Hi"
		return &s, nil
	})
	app.Get("/bin", func(ctx context.Context, in *struct{}) (*[]byte, error) {
		gfast.ResponseFrom(ctx).Header().Set("Content-Type", "text/html")
		b := []byte("<b>x</b>")
		return &b, nil
	})

	page := app.Request(http.MethodGet, "/page", nil)
	if page.Status != http.StatusCreated || page.Header.Get("Content-Type") != "text/html; charset=utf-8" || string(page.Body) != "<p>Hi & co</p>" {
		t.Fatalf("page %d type %s body %q", page.Status, page.Header.Get("Content-Type"), page.Body)
	}
	plain := app.Request(http.MethodGet, "/plain", nil)
	if plain.Status != http.StatusOK || plain.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("plain %d type %s body %s", plain.Status, plain.Header.Get("Content-Type"), plain.Body)
	}
	var text string
	if err := plain.JSON(&text); err != nil || text != "Hi" {
		t.Fatalf("plain json %s err %v", plain.Body, err)
	}
	bin := app.Request(http.MethodGet, "/bin", nil)
	if bin.Header.Get("Content-Type") != "text/html" || string(bin.Body) != "<b>x</b>" {
		t.Fatalf("bin type %s body %q", bin.Header.Get("Content-Type"), bin.Body)
	}
}

func TestStreamFlushAndSSE(t *testing.T) {
	app := gfast.New()
	app.Get("/stream", func(ctx context.Context, in *struct{}) (*chunkReader, error) {
		return &chunkReader{parts: []string{"ab", "cd"}}, nil
	})
	app.Get("/events", func(ctx context.Context, in *struct{}) (*gfast.Events, error) {
		return gfast.SSE(func(ctx context.Context, send func(gfast.Event) error) error {
			if err := send(gfast.Event{ID: "1\n2", Event: "ping", Data: "hello\nworld"}); err != nil {
				return err
			}
			return send(gfast.Event{Data: "bye", Retry: 1500})
		}), nil
	})

	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	rec := httptest.NewRecorder()
	flushed := &flushCounter{ResponseRecorder: rec}
	app.Handler().ServeHTTP(flushed, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "abcd" || flushed.n != 2 {
		t.Fatalf("stream status %d flushes %d body %q type %s", rec.Code, flushed.n, rec.Body.String(), rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("stream type %s", rec.Header().Get("Content-Type"))
	}

	bare := &bareWriter{}
	app.Handler().ServeHTTP(bare, httptest.NewRequest(http.MethodGet, "/stream", nil))
	if bare.code != http.StatusOK || bare.b.String() != "abcd" {
		t.Fatalf("bare status %d body %q", bare.code, bare.b.String())
	}

	evReq := httptest.NewRequest(http.MethodGet, "/events", nil)
	evRec := httptest.NewRecorder()
	evFlush := &flushCounter{ResponseRecorder: evRec}
	app.Handler().ServeHTTP(evFlush, evReq)
	want := "id: 12\nevent: ping\ndata: hello\ndata: world\n\ndata: bye\nretry: 1500\n\n"
	if evRec.Code != http.StatusOK || evFlush.n != 2 || evRec.Body.String() != want {
		t.Fatalf("sse status %d flushes %d body %q", evRec.Code, evFlush.n, evRec.Body.String())
	}
	if evRec.Header().Get("Content-Type") != "text/event-stream" || evRec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("sse headers %#v", evRec.Header())
	}
	head := app.Request(http.MethodHead, "/events", nil)
	if head.Status != http.StatusOK || len(head.Body) != 0 || head.Header.Get("Content-Type") != "text/event-stream" || head.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("sse head %d type %s cache %s body %q", head.Status, head.Header.Get("Content-Type"), head.Header.Get("Cache-Control"), head.Body)
	}

	closed := app.Request(http.MethodGet, "/stream", nil)
	if closed.Status != http.StatusOK || string(closed.Body) != "abcd" {
		t.Fatalf("recorded stream %d %q", closed.Status, closed.Body)
	}
}

type chunkReader struct {
	parts []string
	i     int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.i >= len(c.parts) {
		return 0, io.EOF
	}
	n := copy(p, c.parts[c.i])
	c.i++
	return n, nil
}

type flushCounter struct {
	*httptest.ResponseRecorder
	n int
}

func (f *flushCounter) Flush() {
	f.n++
	f.ResponseRecorder.Flush()
}

type bareWriter struct {
	h    http.Header
	b    bytes.Buffer
	code int
}

func (b *bareWriter) Header() http.Header {
	if b.h == nil {
		b.h = make(http.Header)
	}
	return b.h
}

func (b *bareWriter) Write(p []byte) (int, error) { return b.b.Write(p) }

func (b *bareWriter) WriteHeader(code int) {
	if b.code == 0 {
		b.code = code
	}
}

func TestFileAndRedirect(t *testing.T) {
	mod := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)
	var closed int
	app := gfast.New()
	app.Get("/file", func(ctx context.Context, in *struct{}) (*gfast.FileResponse, error) {
		body := &closeSeeker{Reader: bytes.NewReader([]byte("hello"))}
		body.close = func() { closed++ }
		return &gfast.FileResponse{Name: "note.txt", ModTime: mod, Content: body}, nil
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "note.html")
	if err := os.WriteFile(path, []byte("<p>hi</p>"), 0o644); err != nil {
		t.Fatal(err)
	}
	app.Get("/open", func(ctx context.Context, in *struct{}) (*gfast.FileResponse, error) {
		return gfast.OpenFile(path)
	})
	app.Get("/missing", func(ctx context.Context, in *struct{}) (*gfast.FileResponse, error) {
		return gfast.OpenFile(filepath.Join(dir, "nope.txt"))
	})
	app.Get("/go", func(ctx context.Context, in *struct{}) (*gfast.Redirect, error) {
		return gfast.RedirectTo("/next", 0), nil
	})
	app.Get("/perm", func(ctx context.Context, in *struct{}) (*gfast.Redirect, error) {
		return gfast.RedirectTo("/next", 0), nil
	}, gfast.Status(http.StatusMovedPermanently))
	app.Post("/see", func(ctx context.Context, in *struct{}) (*gfast.Redirect, error) {
		gfast.ResponseFrom(ctx).SetStatus(http.StatusSeeOther)
		return gfast.RedirectTo("/next", 0), nil
	})
	app.Get("/found", func(ctx context.Context, in *struct{}) (*gfast.Redirect, error) {
		return gfast.RedirectTo("/next", http.StatusFound), nil
	}, gfast.Status(http.StatusMovedPermanently))

	file := app.Request(http.MethodGet, "/file", nil)
	if file.Status != http.StatusOK || string(file.Body) != "hello" || closed != 1 {
		t.Fatalf("file %d closed %d body %q type %s", file.Status, closed, file.Body, file.Header.Get("Content-Type"))
	}
	if !strings.Contains(file.Header.Get("Content-Type"), "text/plain") || file.Header.Get("Accept-Ranges") != "bytes" {
		t.Fatalf("file headers %#v", file.Header)
	}
	if file.Header.Get("Last-Modified") != mod.Format(http.TimeFormat) {
		t.Fatalf("modtime %q", file.Header.Get("Last-Modified"))
	}
	head := app.Request(http.MethodHead, "/file", nil)
	if head.Status != http.StatusOK || len(head.Body) != 0 || head.Header.Get("Content-Length") != file.Header.Get("Content-Length") || head.Header.Get("Content-Type") != file.Header.Get("Content-Type") {
		t.Fatalf("file head %d len %q type %s body %q", head.Status, head.Header.Get("Content-Length"), head.Header.Get("Content-Type"), head.Body)
	}
	part := app.Request(http.MethodGet, "/file", nil, http.Header{"Range": []string{"bytes=0-2"}})
	if part.Status != http.StatusPartialContent || string(part.Body) != "hel" || !strings.Contains(part.Header.Get("Content-Range"), "bytes 0-2/5") {
		t.Fatalf("range %d range %q body %q", part.Status, part.Header.Get("Content-Range"), part.Body)
	}
	same := app.Request(http.MethodGet, "/file", nil, http.Header{"If-Modified-Since": []string{mod.Format(http.TimeFormat)}})
	if same.Status != http.StatusNotModified || len(same.Body) != 0 {
		t.Fatalf("not modified %d body %q type %s", same.Status, same.Body, same.Header.Get("Content-Type"))
	}

	opened := app.Request(http.MethodGet, "/open", nil)
	if opened.Status != http.StatusOK || string(opened.Body) != "<p>hi</p>" || !strings.Contains(opened.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("open %d type %s body %q", opened.Status, opened.Header.Get("Content-Type"), opened.Body)
	}
	assertProblem(t, app.Request(http.MethodGet, "/missing", nil), http.StatusNotFound, "file not found")

	goRes := app.Request(http.MethodGet, "/go", nil)
	if goRes.Status != http.StatusTemporaryRedirect || goRes.Header.Get("Location") != "/next" || !strings.Contains(string(goRes.Body), "/next") {
		t.Fatalf("redirect %d location %q body %q", goRes.Status, goRes.Header.Get("Location"), goRes.Body)
	}
	goHead := app.Request(http.MethodHead, "/go", nil)
	if goHead.Status != http.StatusTemporaryRedirect || goHead.Header.Get("Location") != "/next" || len(goHead.Body) != 0 {
		t.Fatalf("redirect head %d location %q body %q", goHead.Status, goHead.Header.Get("Location"), goHead.Body)
	}
	perm := app.Request(http.MethodGet, "/perm", nil)
	if perm.Status != http.StatusMovedPermanently || perm.Header.Get("Location") != "/next" {
		t.Fatalf("perm %d location %q", perm.Status, perm.Header.Get("Location"))
	}
	see := app.Request(http.MethodPost, "/see", nil)
	if see.Status != http.StatusSeeOther || see.Header.Get("Location") != "/next" {
		t.Fatalf("see %d location %q", see.Status, see.Header.Get("Location"))
	}
	found := app.Request(http.MethodGet, "/found", nil)
	if found.Status != http.StatusFound || found.Header.Get("Location") != "/next" {
		t.Fatalf("found %d location %q", found.Status, found.Header.Get("Location"))
	}
}

type closeSeeker struct {
	*bytes.Reader
	close func()
}

func (c *closeSeeker) Close() error {
	if c.close != nil {
		c.close()
	}
	return nil
}

func TestHEADMatchesGETHeaders(t *testing.T) {
	app := gfast.New()
	app.Get("/items/{id}", func(ctx context.Context, in *struct {
		ID string `path:"id"`
	}) (*struct {
		ID string `json:"id"`
	}, error) {
		gfast.ResponseFrom(ctx).Header().Set("X-ID", in.ID)
		gfast.ResponseFrom(ctx).SetCookie(&http.Cookie{Name: "sid", Value: in.ID, Path: "/"})
		return &struct {
			ID string `json:"id"`
		}{ID: in.ID}, nil
	})

	get := app.Request(http.MethodGet, "/items/42", nil)
	head := app.Request(http.MethodHead, "/items/42", nil)
	if get.Status != http.StatusOK || head.Status != get.Status || len(head.Body) != 0 {
		t.Fatalf("get %d head %d body %q / %q", get.Status, head.Status, get.Body, head.Body)
	}
	if !strings.Contains(string(get.Body), "42") {
		t.Fatalf("get body %s", get.Body)
	}
	if head.Header.Get("Content-Type") != get.Header.Get("Content-Type") || head.Header.Get("X-ID") != "42" || head.Header.Get("X-ID") != get.Header.Get("X-ID") {
		t.Fatalf("head %#v get %#v", head.Header, get.Header)
	}
	if !strings.Contains(head.Header.Get("Set-Cookie"), "sid=42") {
		t.Fatalf("cookie %q", head.Header.Get("Set-Cookie"))
	}

	spec := app.Request(http.MethodHead, "/openapi.json", nil)
	full := app.Request(http.MethodGet, "/openapi.json", nil)
	if spec.Status != http.StatusOK || len(spec.Body) != 0 || spec.Header.Get("Content-Type") != full.Header.Get("Content-Type") || len(full.Body) == 0 {
		t.Fatalf("spec head %d type %s body %d full %d", spec.Status, spec.Header.Get("Content-Type"), len(spec.Body), len(full.Body))
	}
	docs := app.Request(http.MethodHead, "/docs", nil)
	if docs.Status != http.StatusOK || len(docs.Body) != 0 || !strings.Contains(docs.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("docs head %d type %s body %d", docs.Status, docs.Header.Get("Content-Type"), len(docs.Body))
	}
}

type noteDoc struct {
	Text string `json:"text"`
}

func TestExtraResponsesAndSpecialSchemas(t *testing.T) {
	app := gfast.New()
	group := app.Group("/v1", gfast.Responses(gfast.ResponseDoc{
		Status:      http.StatusNotFound,
		Description: "Missing",
		Model:       (*noteDoc)(nil),
	}))
	group.Get("/n", func(ctx context.Context, in *struct{}) (*noteDoc, error) {
		return &noteDoc{Text: "ok"}, nil
	}, gfast.Responses(gfast.ResponseDoc{Status: http.StatusForbidden, Description: "No"}))
	app.Get("/away", func(ctx context.Context, in *struct{}) (*gfast.Redirect, error) {
		return gfast.RedirectTo("/n", 0), nil
	})
	app.Get("/away-perm", func(ctx context.Context, in *struct{}) (*gfast.Redirect, error) {
		return gfast.RedirectTo("/n", 0), nil
	}, gfast.Status(http.StatusMovedPermanently))
	app.Get("/dl", func(ctx context.Context, in *struct{}) (*gfast.FileResponse, error) {
		return &gfast.FileResponse{Name: "a.bin", Content: bytes.NewReader(nil)}, nil
	})
	app.Get("/feed", func(ctx context.Context, in *struct{}) (*gfast.Events, error) {
		return gfast.SSE(func(ctx context.Context, send func(gfast.Event) error) error { return nil }), nil
	})
	app.Get("/raw", func(ctx context.Context, in *struct{}) (*bytes.Reader, error) {
		return bytes.NewReader([]byte("xyz")), nil
	})

	spec := openAPI(t, app)
	item := spec.paths["/v1/n"]["get"]["responses"].(map[string]any)
	ok := item["200"].(map[string]any)
	okSchema := spec.deref(ok["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any))
	if ok["description"] != "Success" || okSchema["properties"].(map[string]any)["text"].(map[string]any)["type"] != "string" {
		t.Fatalf("success %#v", ok)
	}
	missing := item["404"].(map[string]any)
	if missing["description"] != "Missing" {
		t.Fatalf("404 %#v", missing)
	}
	text := spec.deref(missing["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any))["properties"].(map[string]any)["text"].(map[string]any)
	if text["type"] != "string" {
		t.Fatalf("404 schema %#v", missing)
	}
	forbidden := item["403"].(map[string]any)
	if forbidden["description"] != "No" {
		t.Fatalf("403 %#v", forbidden)
	}
	if _, exists := forbidden["content"]; exists {
		t.Fatalf("403 content %#v", forbidden)
	}

	away := spec.paths["/away"]["get"]["responses"].(map[string]any)
	if _, exists := away["200"]; exists {
		t.Fatalf("redirect documented 200: %#v", away)
	}
	if away["307"].(map[string]any)["description"] != "Redirect" {
		t.Fatalf("307 %#v", away["307"])
	}
	if _, exists := away["307"].(map[string]any)["content"]; exists {
		t.Fatalf("redirect content %#v", away["307"])
	}
	perm := spec.paths["/away-perm"]["get"]["responses"].(map[string]any)
	if perm["301"].(map[string]any)["description"] != "Redirect" {
		t.Fatalf("301 %#v", perm)
	}
	dl := spec.paths["/dl"]["get"]["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/octet-stream"].(map[string]any)["schema"].(map[string]any)
	if dl["type"] != "string" || dl["format"] != "binary" {
		t.Fatalf("file schema %#v", dl)
	}
	feed := spec.paths["/feed"]["get"]["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)
	if _, ok := feed["text/event-stream"]; !ok {
		t.Fatalf("sse schema %#v", feed)
	}
	raw := spec.paths["/raw"]["get"]["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/octet-stream"].(map[string]any)["schema"].(map[string]any)
	if raw["format"] != "binary" {
		t.Fatalf("reader schema %#v", raw)
	}
	body := app.Request(http.MethodGet, "/raw", nil)
	if body.Status != http.StatusOK || string(body.Body) != "xyz" || body.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("raw %d type %s body %q", body.Status, body.Header.Get("Content-Type"), body.Body)
	}

	mustPanic(t, "status", func() {
		gfast.New().Get("/z", func(ctx context.Context, in *struct{}) (*struct{}, error) {
			return &struct{}{}, nil
		}, gfast.Responses(gfast.ResponseDoc{}))
	})
}
