package gfast_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jsonv2 "encoding/json/v2"
	"hegel.dev/go/hegel"

	"github.com/pyrex41/gfast"
)

// hpFormatEvent is the server-sent event encoding: CR and LF leave id and
// event names, data splits on LF after CR is normalized, and retry is omitted
// unless it is positive.
func hpFormatEvent(e gfast.Event) string {
	var b strings.Builder
	id := strings.ReplaceAll(strings.ReplaceAll(e.ID, "\r", ""), "\n", "")
	if id != "" {
		b.WriteString("id: ")
		b.WriteString(id)
		b.WriteByte('\n')
	}
	name := strings.ReplaceAll(strings.ReplaceAll(e.Event, "\r", ""), "\n", "")
	if name != "" {
		b.WriteString("event: ")
		b.WriteString(name)
		b.WriteByte('\n')
	}
	data := strings.ReplaceAll(e.Data, "\r\n", "\n")
	data = strings.ReplaceAll(data, "\r", "\n")
	if data == "" {
		b.WriteString("data: \n")
	} else {
		for line := range strings.SplitSeq(data, "\n") {
			b.WriteString("data: ")
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if e.Retry > 0 {
		b.WriteString("retry: ")
		b.WriteString(strconv.Itoa(e.Retry))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	return b.String()
}

func TestPropRawStreamAndOutputValidate(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		mode := hegel.Draw(ht, hegel.Integers(0, 6))
		text := hegel.Draw(ht, hegel.Text().Alphabet("ab\"\\\n").MaxSize(8))
		raw := hegel.Draw(ht, hegel.Binary(0, 8))
		parts := hegel.Draw(ht, hegel.Lists(hegel.Binary(0, 8)).MaxSize(3))
		n := hegel.Draw(ht, hegel.Integers(-3, 3))
		status := hegel.Draw(ht, hegel.Integers(200, 299))
		registered := hegel.Draw(ht, hegel.Integers(200, 299))
		setStatus := hegel.Draw(ht, hegel.Booleans())
		ctMode := hegel.Draw(ht, hegel.Integers(0, 3))
		nilSlice := hegel.Draw(ht, hegel.Booleans())
		mark := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		cookie := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		secret := "Z" + hegel.Draw(ht, hegel.Text().Alphabet("XYZ").MinSize(2).MaxSize(6))
		hpOutSecret = secret

		wantStatus := registered
		if setStatus {
			wantStatus = status
		}
		var wantType string
		switch ctMode {
		case 1, 3:
			wantType = "text/plain"
		case 2:
			wantType = "text/html"
		}

		app := gfast.New()
		switch mode {
		case 0, 1:
			app.Get("/t", func(ctx context.Context, in *struct{}) (*string, error) {
				res := gfast.ResponseFrom(ctx)
				if setStatus {
					res.SetStatus(status)
				}
				switch ctMode {
				case 1:
					res.SetContentType("text/plain")
				case 2:
					res.Header().Set("Content-Type", "text/html")
				case 3:
					res.SetContentType("text/plain")
					res.Header().Set("Content-Type", "text/html")
				}
				s := text
				return &s, nil
			}, gfast.Status(registered))
		case 2:
			app.Get("/t", func(ctx context.Context, in *struct{}) (*[]byte, error) {
				res := gfast.ResponseFrom(ctx)
				if setStatus {
					res.SetStatus(status)
				}
				switch ctMode {
				case 1:
					res.SetContentType("text/plain")
				case 2:
					res.Header().Set("Content-Type", "text/html")
				case 3:
					res.SetContentType("text/plain")
					res.Header().Set("Content-Type", "text/html")
				}
				if nilSlice {
					var b []byte
					return &b, nil
				}
				b := append([]byte(nil), raw...)
				return &b, nil
			}, gfast.Status(registered))
		case 3:
			app.Get("/t", func(ctx context.Context, in *struct{}) (*[]byte, error) {
				res := gfast.ResponseFrom(ctx)
				if setStatus {
					res.SetStatus(status)
				}
				res.Header().Set("Content-Type", "text/plain")
				res.Header().Set("X-Mark", mark)
				return nil, nil
			}, gfast.Status(registered))
		case 4:
			var closed int
			app.Get("/t", func(ctx context.Context, in *struct{}) (*hpChunks, error) {
				res := gfast.ResponseFrom(ctx)
				if setStatus {
					res.SetStatus(status)
				}
				switch ctMode {
				case 1:
					res.SetContentType("text/plain")
				case 2:
					res.Header().Set("Content-Type", "text/html")
				case 3:
					res.SetContentType("text/plain")
					res.Header().Set("Content-Type", "text/html")
				}
				return &hpChunks{parts: parts, closed: &closed}, nil
			}, gfast.Status(registered))
			res := app.Request(http.MethodGet, "/t", nil)
			if res.Status != wantStatus {
				ht.Fatalf("stream status %d want %d body %q", res.Status, wantStatus, res.Body)
			}
			gotType := wantType
			if gotType == "" {
				gotType = "application/octet-stream"
			}
			if res.Header.Get("Content-Type") != gotType || closed != 1 {
				ht.Fatalf("stream type %q want %q closed %d", res.Header.Get("Content-Type"), gotType, closed)
			}
			var want bytes.Buffer
			for _, part := range parts {
				want.Write(part)
			}
			if !bytes.Equal(res.Body, want.Bytes()) {
				ht.Fatalf("stream %q want %q", res.Body, want.Bytes())
			}
			return
		case 5, 6:
			app.Get("/t", func(ctx context.Context, in *struct {
				N int `query:"n"`
			}) (*hpCheckedOut, error) {
				res := gfast.ResponseFrom(ctx)
				if setStatus {
					res.SetStatus(status)
				}
				res.SetContentType("text/plain")
				res.Header().Set("X-Mark", mark)
				res.SetCookie(&http.Cookie{Name: "sid", Value: cookie, Path: "/"})
				return &hpCheckedOut{N: in.N}, nil
			}, gfast.Status(registered))
			res := app.Request(http.MethodGet, "/t?n="+strconv.Itoa(n), nil)
			if n <= 0 {
				hpProblem(ht, res, http.StatusInternalServerError, "unexpected error occurred")
				if strings.Contains(string(res.Body), secret) || res.Status == http.StatusBadRequest {
					ht.Fatalf("validation escaped %d %s", res.Status, res.Body)
				}
				if res.Header.Get("X-Mark") != mark || !strings.Contains(res.Header.Get("Set-Cookie"), "sid="+cookie) {
					ht.Fatalf("headers %#v", res.Header)
				}
				return
			}
			if res.Status != wantStatus || res.Header.Get("Content-Type") != "application/json" {
				ht.Fatalf("json %d type %s body %s", res.Status, res.Header.Get("Content-Type"), res.Body)
			}
			var got hpCheckedOut
			if err := res.JSON(&got); err != nil || got.N != n {
				ht.Fatalf("body %s err %v", res.Body, err)
			}
			if res.Header.Get("X-Mark") != mark {
				ht.Fatalf("mark %q", res.Header.Get("X-Mark"))
			}
			return
		}

		res := app.Request(http.MethodGet, "/t", nil)
		if mode == 3 {
			if res.Status != http.StatusNoContent || len(res.Body) != 0 {
				ht.Fatalf("nil %d %q", res.Status, res.Body)
			}
			if res.Header.Get("Content-Type") != "text/plain" || res.Header.Get("X-Mark") != mark {
				ht.Fatalf("nil headers %#v", res.Header)
			}
			return
		}
		rawBody := wantType != ""
		if mode <= 1 {
			if rawBody {
				if res.Status != wantStatus || res.Header.Get("Content-Type") != wantType || string(res.Body) != text {
					ht.Fatalf("raw string %d type %s body %q want %q", res.Status, res.Header.Get("Content-Type"), res.Body, text)
				}
				return
			}
			payload, err := jsonv2.Marshal(text)
			if err != nil {
				ht.Fatal(err)
			}
			if res.Status != wantStatus || res.Header.Get("Content-Type") != "application/json" || !bytes.Equal(res.Body, payload) {
				ht.Fatalf("json string %d type %s body %q want %q", res.Status, res.Header.Get("Content-Type"), res.Body, payload)
			}
			return
		}
		var payload []byte
		if nilSlice {
			payload = []byte{}
		} else {
			payload = raw
		}
		if rawBody {
			if res.Status != wantStatus || res.Header.Get("Content-Type") != wantType || !bytes.Equal(res.Body, payload) {
				ht.Fatalf("raw bytes %d type %s body %q want %q", res.Status, res.Header.Get("Content-Type"), res.Body, payload)
			}
			return
		}
		encoded, err := jsonv2.Marshal(payload)
		if err != nil {
			ht.Fatal(err)
		}
		if res.Status != wantStatus || res.Header.Get("Content-Type") != "application/json" || !bytes.Equal(res.Body, encoded) {
			ht.Fatalf("json bytes %d type %s body %q want %q", res.Status, res.Header.Get("Content-Type"), res.Body, encoded)
		}
	})
}

var hpOutSecret string

type hpCheckedOut struct {
	N int `json:"n"`
}

func (o *hpCheckedOut) Validate() error {
	if o.N < 0 {
		return errors.New(hpOutSecret)
	}
	if o.N == 0 {
		return gfast.BadRequest(hpOutSecret)
	}
	return nil
}

type hpChunks struct {
	parts  [][]byte
	i      int
	closed *int
}

func (c *hpChunks) Read(p []byte) (int, error) {
	for c.i < len(c.parts) && len(c.parts[c.i]) == 0 {
		c.i++
	}
	if c.i >= len(c.parts) {
		return 0, io.EOF
	}
	n := copy(p, c.parts[c.i])
	if n < len(c.parts[c.i]) {
		c.parts[c.i] = c.parts[c.i][n:]
		return n, nil
	}
	c.i++
	return n, nil
}

func (c *hpChunks) Close() error {
	*c.closed++
	return nil
}

func TestPropRedirectAndDocs(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		seg := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		query := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MaxSize(6))
		withQuery := hegel.Draw(ht, hegel.Booleans())
		useExplicit := hegel.Draw(ht, hegel.Booleans())
		explicit := hegel.Draw(ht, hegel.SampledFrom([]int{
			http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
			http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
			http.StatusOK, http.StatusNotFound,
		}))
		useSet := hegel.Draw(ht, hegel.Booleans())
		setCode := hegel.Draw(ht, hegel.SampledFrom([]int{
			http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
			http.StatusOK, http.StatusAccepted,
		}))
		registered := hegel.Draw(ht, hegel.SampledFrom([]int{
			http.StatusOK, http.StatusCreated, http.StatusMovedPermanently,
			http.StatusFound, http.StatusTemporaryRedirect, http.StatusNotFound,
		}))
		method := hegel.Draw(ht, hegel.SampledFrom([]string{http.MethodGet, http.MethodHead, http.MethodPost}))
		hadCT := hegel.Draw(ht, hegel.Booleans())

		target := "/" + seg
		if withQuery && query != "" {
			target += "?q=" + query
		}
		code := registered
		if useSet {
			code = setCode
		}
		if useExplicit {
			code = explicit
		} else if code < 300 || code > 399 {
			code = http.StatusTemporaryRedirect
		}
		docCode := registered
		if docCode < 300 || docCode > 399 {
			docCode = http.StatusTemporaryRedirect
		}

		app := gfast.New()
		app.Get("/go", func(ctx context.Context, in *struct{}) (*gfast.Redirect, error) {
			if useSet {
				gfast.ResponseFrom(ctx).SetStatus(setCode)
			}
			if hadCT {
				gfast.ResponseFrom(ctx).Header().Set("Content-Type", "text/plain")
			}
			redir := 0
			if useExplicit {
				redir = explicit
			}
			return gfast.RedirectTo(target, redir), nil
		}, gfast.Status(registered))
		// POST uses the same redirect helper through a second route so the
		// method is not limited to the implicit HEAD/GET pair.
		app.Post("/go", func(ctx context.Context, in *struct{}) (*gfast.Redirect, error) {
			if useSet {
				gfast.ResponseFrom(ctx).SetStatus(setCode)
			}
			if hadCT {
				gfast.ResponseFrom(ctx).Header().Set("Content-Type", "text/plain")
			}
			redir := 0
			if useExplicit {
				redir = explicit
			}
			return gfast.RedirectTo(target, redir), nil
		}, gfast.Status(registered))

		res := app.Request(method, "/go", nil)
		if res.Status != code || res.Header.Get("Location") != target {
			ht.Fatalf("%s %d location %q want %d %q body %q", method, res.Status, res.Header.Get("Location"), code, target, res.Body)
		}
		switch {
		case hadCT:
			if res.Header.Get("Content-Type") != "text/plain" || len(res.Body) != 0 {
				ht.Fatalf("preset type %s body %q", res.Header.Get("Content-Type"), res.Body)
			}
		case method == http.MethodGet:
			want := "<a href=\"" + target + "\">" + http.StatusText(code) + "</a>.\n\n"
			if res.Header.Get("Content-Type") != "text/html; charset=utf-8" || string(res.Body) != want {
				ht.Fatalf("get body %q type %s", res.Body, res.Header.Get("Content-Type"))
			}
		case method == http.MethodHead:
			if len(res.Body) != 0 || res.Header.Get("Content-Type") != "text/html; charset=utf-8" {
				ht.Fatalf("head body %q type %s", res.Body, res.Header.Get("Content-Type"))
			}
		default:
			if len(res.Body) != 0 || res.Header.Get("Content-Type") != "" {
				ht.Fatalf("post body %q type %s", res.Body, res.Header.Get("Content-Type"))
			}
		}

		op := hpSpec(ht, app).op("/go", "get")
		docKey := strconv.Itoa(docCode)
		docResp, ok := op.Responses[docKey]
		if !ok || docResp.Description != "Redirect" || len(docResp.Content) != 0 {
			ht.Fatalf("docs %s %#v", docKey, op.Responses)
		}
		if _, extra := op.Responses["200"]; extra && docKey != "200" {
			ht.Fatalf("redirect kept 200 %#v", op.Responses)
		}
	})
}

func TestPropSSEFormat(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		line := hegel.Text().Alphabet("ab\r\n")
		n := hegel.Draw(ht, hegel.Integers(0, 3))
		events := make([]gfast.Event, n)
		for i := range events {
			events[i] = gfast.Event{
				ID:    hegel.Draw(ht, line.MaxSize(6)),
				Event: hegel.Draw(ht, line.MaxSize(6)),
				Data:  hegel.Draw(ht, line.MaxSize(12)),
				Retry: hegel.Draw(ht, hegel.Integers(-2, 20)),
			}
		}
		fail := hegel.Draw(ht, hegel.Integers(0, 2))
		ctMode := hegel.Draw(ht, hegel.Integers(0, 2))
		cache := hegel.Draw(ht, hegel.Booleans())
		setStatus := hegel.Draw(ht, hegel.Booleans())
		status := hegel.Draw(ht, hegel.Integers(200, 299))
		registered := hegel.Draw(ht, hegel.Integers(200, 299))
		const leak = "ZZZ"

		wantStatus := registered
		if setStatus {
			wantStatus = status
		}
		wantType := "text/event-stream"
		if ctMode == 1 {
			wantType = "text/plain"
		}
		if ctMode == 2 {
			wantType = "text/html"
		}
		wantCache := "no-cache"
		if cache {
			wantCache = "private"
		}
		sent := events
		switch fail {
		case 1:
			sent = nil
		case 2:
			if len(events) > 0 {
				sent = events[:1]
			}
		}
		var want strings.Builder
		for _, ev := range sent {
			want.WriteString(hpFormatEvent(ev))
		}

		app := gfast.New()
		app.Get("/feed", func(ctx context.Context, in *struct{}) (*gfast.Events, error) {
			res := gfast.ResponseFrom(ctx)
			if setStatus {
				res.SetStatus(status)
			}
			switch ctMode {
			case 1:
				res.SetContentType("text/plain")
			case 2:
				res.Header().Set("Content-Type", "text/html")
			}
			if cache {
				res.Header().Set("Cache-Control", "private")
			}
			return gfast.SSE(func(ctx context.Context, send func(gfast.Event) error) error {
				if fail == 1 {
					return errors.New(leak)
				}
				for i, ev := range events {
					if err := send(ev); err != nil {
						return err
					}
					if fail == 2 && i == 0 {
						return errors.New(leak)
					}
				}
				return nil
			}), nil
		}, gfast.Status(registered))

		for _, method := range []string{http.MethodGet, http.MethodHead} {
			res := app.Request(method, "/feed", nil)
			if res.Status != wantStatus || res.Header.Get("Content-Type") != wantType || res.Header.Get("Cache-Control") != wantCache {
				ht.Fatalf("%s %d type %s cache %s", method, res.Status, res.Header.Get("Content-Type"), res.Header.Get("Cache-Control"))
			}
			if strings.Contains(string(res.Body), leak) {
				ht.Fatalf("producer error leaked %s", res.Body)
			}
			if method == http.MethodHead {
				if len(res.Body) != 0 {
					ht.Fatalf("head body %q", res.Body)
				}
				continue
			}
			if string(res.Body) != want.String() {
				ht.Fatalf("body %q want %q", res.Body, want.String())
			}
		}
	})
}

type hpSeek struct {
	*bytes.Reader
	closed *int
}

func (s *hpSeek) Close() error {
	*s.closed++
	return nil
}

func TestPropFileResponses(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		mode := hegel.Draw(ht, hegel.Integers(0, 4))
		body := hegel.Draw(ht, hegel.Binary(0, 24))
		ext := hegel.Draw(ht, hegel.SampledFrom([]string{".txt", ".html", ".json", ".css"}))
		preset := hegel.Draw(ht, hegel.Booleans())
		sub := hegel.Draw(ht, hegel.Integers(0, 3))
		head := hegel.Draw(ht, hegel.Booleans())
		mark := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(4))
		mod := time.Unix(1_700_000_000+int64(hegel.Draw(ht, hegel.Integers(0, 100000))), 0).UTC()

		switch mode {
		case 1:
			dir := htTemp(ht)
			defer os.RemoveAll(dir)
			path := filepath.Join(dir, "note"+ext)
			if err := os.WriteFile(path, body, 0o644); err != nil {
				ht.Fatal(err)
			}
			app := gfast.New()
			app.Get("/open", func(ctx context.Context, in *struct{}) (*gfast.FileResponse, error) {
				return gfast.OpenFile(path)
			})
			res := app.Request(http.MethodGet, "/open", nil)
			wantType := mime.TypeByExtension(ext)
			if res.Status != http.StatusOK || !bytes.Equal(res.Body, body) || res.Header.Get("Content-Type") != wantType {
				ht.Fatalf("open %d type %s want %s body %q", res.Status, res.Header.Get("Content-Type"), wantType, res.Body)
			}
			if res.Header.Get("Accept-Ranges") != "bytes" {
				ht.Fatalf("ranges %q", res.Header.Get("Accept-Ranges"))
			}
		case 2:
			dir := htTemp(ht)
			defer os.RemoveAll(dir)
			name := "missing-" + hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6)) + ext
			app := gfast.New()
			app.Get("/missing", func(ctx context.Context, in *struct{}) (*gfast.FileResponse, error) {
				return gfast.OpenFile(filepath.Join(dir, name))
			})
			hpProblem(ht, app.Request(http.MethodGet, "/missing", nil), http.StatusNotFound, "file not found")
		case 3:
			app := gfast.New()
			app.Get("/empty", func(ctx context.Context, in *struct{}) (*gfast.FileResponse, error) {
				gfast.ResponseFrom(ctx).Header().Set("X-Mark", mark)
				return &gfast.FileResponse{Name: "note" + ext}, nil
			})
			res := app.Request(http.MethodGet, "/empty", nil)
			hpProblem(ht, res, http.StatusInternalServerError, "unexpected error occurred")
			if strings.Contains(string(res.Body), "empty file") || res.Header.Get("X-Mark") != mark {
				ht.Fatalf("empty file leaked %s %#v", res.Body, res.Header)
			}
		case 4:
			app := gfast.New()
			app.Get("/nil", func(ctx context.Context, in *struct{}) (*gfast.FileResponse, error) {
				gfast.ResponseFrom(ctx).Header().Set("X-Mark", mark)
				return nil, nil
			})
			res := app.Request(http.MethodGet, "/nil", nil)
			if res.Status != http.StatusNoContent || len(res.Body) != 0 || res.Header.Get("X-Mark") != mark {
				ht.Fatalf("nil file %d %q %#v", res.Status, res.Body, res.Header)
			}
		default:
			var closed int
			app := gfast.New()
			app.Get("/file", func(ctx context.Context, in *struct{}) (*gfast.FileResponse, error) {
				if preset {
					gfast.ResponseFrom(ctx).SetContentType("text/plain; charset=utf-8")
				}
				return &gfast.FileResponse{
					Name:    "note" + ext,
					ModTime: mod,
					Content: &hpSeek{Reader: bytes.NewReader(body), closed: &closed},
				}, nil
			})
			method := http.MethodGet
			if head {
				method = http.MethodHead
			}
			header := http.Header{}
			wantStatus := http.StatusOK
			wantBody := body
			var wantRange string
			switch sub {
			case 1:
				if len(body) == 0 {
					break
				}
				start := hegel.Draw(ht, hegel.Integers(0, len(body)-1))
				end := hegel.Draw(ht, hegel.Integers(start, len(body)-1))
				header.Set("Range", "bytes="+strconv.Itoa(start)+"-"+strconv.Itoa(end))
				wantStatus = http.StatusPartialContent
				wantBody = body[start : end+1]
				wantRange = "bytes " + strconv.Itoa(start) + "-" + strconv.Itoa(end) + "/" + strconv.Itoa(len(body))
			case 2:
				header.Set("If-Modified-Since", mod.Format(http.TimeFormat))
				wantStatus = http.StatusNotModified
				wantBody = nil
			case 3:
				if len(body) == 0 {
					break
				}
				header.Set("Range", "bytes="+strconv.Itoa(len(body)+5)+"-"+strconv.Itoa(len(body)+8))
				wantStatus = http.StatusRequestedRangeNotSatisfiable
				wantBody = []byte("invalid range: failed to overlap\n")
				wantRange = "bytes */" + strconv.Itoa(len(body))
			}
			res := app.Request(method, "/file", nil, header)
			if closed != 1 {
				ht.Fatalf("closed %d", closed)
			}
			wantLen := len(wantBody)
			if head {
				wantBody = nil
			}
			if res.Status != wantStatus || !bytes.Equal(res.Body, wantBody) {
				ht.Fatalf("file %s %d body %q want %d %q", method, res.Status, res.Body, wantStatus, wantBody)
			}
			if wantRange != "" && res.Header.Get("Content-Range") != wantRange {
				ht.Fatalf("range %q want %q", res.Header.Get("Content-Range"), wantRange)
			}
			switch wantStatus {
			case http.StatusNotModified:
				if res.Header.Get("Content-Type") != "" || res.Header.Get("Last-Modified") != mod.Format(http.TimeFormat) || res.Header.Get("Accept-Ranges") != "" {
					ht.Fatalf("not modified %#v", res.Header)
				}
			case http.StatusRequestedRangeNotSatisfiable:
				if res.Header.Get("Content-Type") != "text/plain; charset=utf-8" || res.Header.Get("Last-Modified") != "" {
					ht.Fatalf("416 %#v", res.Header)
				}
			default:
				wantType := mime.TypeByExtension(ext)
				if preset {
					wantType = "text/plain; charset=utf-8"
				}
				if res.Header.Get("Content-Type") != wantType || res.Header.Get("Accept-Ranges") != "bytes" {
					ht.Fatalf("type %s ranges %s want %s", res.Header.Get("Content-Type"), res.Header.Get("Accept-Ranges"), wantType)
				}
				if res.Header.Get("Last-Modified") != mod.Format(http.TimeFormat) {
					ht.Fatalf("mod %q", res.Header.Get("Last-Modified"))
				}
				if res.Header.Get("Content-Length") != strconv.Itoa(wantLen) {
					ht.Fatalf("length %s want %d", res.Header.Get("Content-Length"), wantLen)
				}
			}
		}
	})
}

func htTemp(ht *hegel.T) string {
	ht.Helper()
	dir, err := os.MkdirTemp("", "gfast-hp-")
	if err != nil {
		ht.Fatal(err)
	}
	return dir
}

func TestPropExtraResponses(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		groupBad := hegel.Draw(ht, hegel.Booleans())
		routeBad := hegel.Draw(ht, hegel.Booleans())
		groupStatus := hegel.Draw(ht, hegel.Integers(200, 599))
		routeStatus := hegel.Draw(ht, hegel.Integers(200, 599))
		if groupBad {
			groupStatus = hegel.Draw(ht, hegel.Integers(-3, 0))
		}
		if routeBad {
			routeStatus = hegel.Draw(ht, hegel.Integers(-3, 0))
		}
		words := hegel.Text().Alphabet("abc ")
		groupDesc := hegel.Draw(ht, words.MaxSize(8))
		routeDesc := hegel.Draw(ht, words.MaxSize(8))
		groupModel := hegel.Draw(ht, hegel.Booleans())
		routeModel := hegel.Draw(ht, hegel.Booleans())
		groupMedia := hegel.Draw(ht, hegel.SampledFrom([]string{"", "text/plain"}))
		routeMedia := hegel.Draw(ht, hegel.SampledFrom([]string{"", "text/plain"}))

		var recovered any
		var app *gfast.App
		func() {
			defer func() { recovered = recover() }()
			app = gfast.New()
			group := app.Group("/v1", gfast.Responses(gfast.ResponseDoc{
				Status:      groupStatus,
				Description: groupDesc,
				Model:       hpExtraModel(groupModel),
				ContentType: groupMedia,
			}))
			group.Get("/n", func(ctx context.Context, in *struct{}) (*hpNote, error) {
				return &hpNote{Text: "ok"}, nil
			}, gfast.Responses(gfast.ResponseDoc{
				Status:      routeStatus,
				Description: routeDesc,
				Model:       hpExtraModel(routeModel),
				ContentType: routeMedia,
			}))
		}()
		if groupBad || routeBad {
			if recovered == nil || !strings.Contains(hpRecovered(recovered), "gfast: response status must be set") {
				ht.Fatalf("panic %v", recovered)
			}
			return
		}
		if recovered != nil {
			ht.Fatalf("unexpected panic %v", recovered)
		}

		type media struct {
			schema bool
		}
		type resp struct {
			description string
			content     map[string]media
		}
		responses := map[string]*resp{
			"200": {description: "Success", content: map[string]media{"application/json": {schema: true}}},
		}
		apply := func(status int, desc, kind string, model bool) {
			key := strconv.Itoa(status)
			item := responses[key]
			if item == nil {
				item = &resp{}
				responses[key] = item
			}
			if desc != "" {
				item.description = desc
			}
			if item.description == "" {
				item.description = http.StatusText(status)
			}
			if item.description == "" {
				item.description = "Response"
			}
			if model || kind != "" {
				if kind == "" {
					kind = "application/json"
				}
				if item.content == nil {
					item.content = map[string]media{}
				}
				item.content[kind] = media{schema: model}
			}
		}
		apply(groupStatus, groupDesc, groupMedia, groupModel)
		apply(routeStatus, routeDesc, routeMedia, routeModel)

		parsed := hpSpec(ht, app)
		got := parsed.op("/v1/n", "get").Responses
		if len(got) != len(responses) {
			ht.Fatalf("responses %#v want %d", got, len(responses))
		}
		for key, want := range responses {
			item, ok := got[key]
			if !ok || item.Description != want.description || len(item.Content) != len(want.content) {
				ht.Fatalf("response %s %#v want %#v", key, item, want)
			}
			for kind, meta := range want.content {
				mediaItem, ok := item.Content[kind]
				if !ok {
					ht.Fatalf("missing %s %s", key, kind)
				}
				resolved := parsed.expand(mediaItem.Schema)
				hasSchema := resolved.Type != "" || len(resolved.Properties) != 0
				if meta.schema != hasSchema {
					ht.Fatalf("schema %s %s %#v", key, kind, mediaItem.Schema)
				}
				if meta.schema {
					text := resolved.Properties["text"]
					if resolved.Type != "object" || text == nil || text.Type != "string" {
						ht.Fatalf("note schema %#v", resolved)
					}
				}
			}
		}
	})
}

type hpNote struct {
	Text string `json:"text"`
}

func hpExtraModel(model bool) any {
	if !model {
		return nil
	}
	return (*hpNote)(nil)
}

func hpRecovered(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case error:
		return x.Error()
	default:
		return ""
	}
}

func TestPropFormFields(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		names := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abcXYZ ").MaxSize(6)).MaxSize(3))
		nRaws := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("0123456789+x").MinSize(1).MaxSize(6)).MaxSize(3))
		tags := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abc").MaxSize(4)).MaxSize(3))
		mode := hegel.Draw(ht, hegel.Integers(0, 3))

		app := gfast.New()
		app.Post("/form", func(ctx context.Context, in *hpFormIn) (*hpFormIn, error) {
			return in, nil
		})
		spec := hpSpec(ht, app)
		op := spec.op("/form", "post")
		if len(op.Parameters) != 0 || op.RequestBody == nil || !op.RequestBody.Required {
			ht.Fatalf("form spec params %#v body %#v", op.Parameters, op.RequestBody)
		}
		rawBody := spec.raw["paths"].(map[string]any)["/form"].(map[string]any)["post"].(map[string]any)["requestBody"].(map[string]any)
		content := rawBody["content"].(map[string]any)
		schema := content["application/x-www-form-urlencoded"].(map[string]any)["schema"].(map[string]any)
		props := schema["properties"].(map[string]any)
		nameSchema := props["name"].(map[string]any)
		nSchema := props["n"].(map[string]any)
		tagSchema := props["tag"].(map[string]any)
		if nameSchema["type"] != "string" || nameSchema["description"] != "Given" || nSchema["type"] != "integer" || nSchema["default"] != float64(7) {
			ht.Fatalf("schemas name %#v n %#v", nameSchema, nSchema)
		}
		if tagSchema["type"] != "array" || tagSchema["minItems"] != float64(1) || tagSchema["items"].(map[string]any)["type"] != "string" {
			ht.Fatalf("tag %#v", tagSchema)
		}
		required, _ := schema["required"].([]any)
		if len(required) != 1 || required[0] != "name" {
			ht.Fatalf("required %#v", schema["required"])
		}
		if _, ok := content["multipart/form-data"]; ok {
			ht.Fatalf("form became multipart %#v", content)
		}

		header := http.Header{}
		var body []byte
		switch mode {
		case 0:
			header.Set("Content-Type", "application/x-www-form-urlencoded")
			v := url.Values{}
			if len(names) > 0 {
				v["name"] = names
			}
			if len(nRaws) > 0 {
				v["n"] = nRaws
			}
			if len(tags) > 0 {
				v["tag"] = tags
			}
			body = []byte(v.Encode())
		case 2:
			header.Set("Content-Type", "application/json")
			body = []byte(`{"name":"a"}`)
		case 3:
			header.Set("Content-Type", "a/b/c")
			body = []byte("x")
		}
		res := app.Request(http.MethodPost, "/form", body, header)
		switch mode {
		case 2:
			hpProblem(ht, res, http.StatusBadRequest, "expected form body")
			return
		case 3:
			hpProblem(ht, res, http.StatusBadRequest, "invalid content type")
			return
		}
		if mode != 0 {
			names, nRaws, tags = nil, nil, nil
		}
		if len(nRaws) > 0 {
			if _, err := strconv.ParseInt(nRaws[0], 10, 64); err != nil {
				hpProblem(ht, res, http.StatusBadRequest, "n: "+err.Error())
				return
			}
		}
		var issues []string
		if len(names) == 0 {
			issues = append(issues, "name is required")
		}
		if len(tags) == 0 {
			issues = append(issues, "tag must have at least 1 items")
		}
		if len(issues) > 0 {
			hpProblem(ht, res, http.StatusUnprocessableEntity, strings.Join(issues, "; "))
			return
		}
		if res.Status != http.StatusOK {
			ht.Fatalf("form %d %s", res.Status, res.Body)
		}
		var got hpFormIn
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		wantN := 7
		if len(nRaws) > 0 {
			n, err := strconv.Atoi(nRaws[0])
			if err != nil {
				ht.Fatal(err)
			}
			wantN = n
		}
		if got.Name != names[0] || got.N != wantN || !sameStringList(got.Tag, tags) {
			ht.Fatalf("got %+v names %q n %q tags %q", got, names, nRaws, tags)
		}
	})
}

type hpFormIn struct {
	Name string   `form:"name" required:"true" doc:"Given"`
	N    int      `form:"n" default:"7"`
	Tag  []string `form:"tag" minItems:"1"`
}

func TestPropMultipartFiles(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		titles := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abc ").MaxSize(6)).MaxSize(2))
		onePresent := hegel.Draw(ht, hegel.Booleans())
		oneCount := 0
		if onePresent {
			oneCount = hegel.Draw(ht, hegel.Integers(1, 2))
		}
		manyCount := hegel.Draw(ht, hegel.Integers(0, 2))
		mode := hegel.Draw(ht, hegel.Integers(0, 3))
		names := hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(6)
		type filePart struct {
			name string
			body []byte
		}
		ones := make([]filePart, oneCount)
		for i := range ones {
			ones[i] = filePart{name: hegel.Draw(ht, names), body: hegel.Draw(ht, hegel.Binary(0, 8))}
		}
		manys := make([]filePart, manyCount)
		for i := range manys {
			manys[i] = filePart{name: hegel.Draw(ht, names), body: hegel.Draw(ht, hegel.Binary(0, 8))}
		}

		app := gfast.New()
		app.Post("/upload", func(ctx context.Context, in *hpUploadIn) (*hpUploadOut, error) {
			out := &hpUploadOut{Title: in.Title}
			if in.One != nil {
				out.One = hpFilePart(in.One)
			}
			for i := range in.Many {
				out.Many = append(out.Many, hpFilePart(&in.Many[i]))
			}
			return out, nil
		})
		spec := hpSpec(ht, app)
		op := spec.op("/upload", "post")
		if len(op.Parameters) != 0 || op.RequestBody == nil || !op.RequestBody.Required {
			ht.Fatalf("upload spec %#v", op)
		}
		rawBody := spec.raw["paths"].(map[string]any)["/upload"].(map[string]any)["post"].(map[string]any)["requestBody"].(map[string]any)
		content := rawBody["content"].(map[string]any)
		schema := content["multipart/form-data"].(map[string]any)["schema"].(map[string]any)
		props := schema["properties"].(map[string]any)
		one := props["one"].(map[string]any)
		many := props["many"].(map[string]any)
		if one["type"] != "string" || one["format"] != "binary" || one["description"] != "Payload" {
			ht.Fatalf("one %#v", one)
		}
		if many["type"] != "array" || many["items"].(map[string]any)["format"] != "binary" {
			ht.Fatalf("many %#v", many)
		}
		required, _ := schema["required"].([]any)
		if len(required) != 1 || required[0] != "one" {
			ht.Fatalf("required %#v", required)
		}
		if _, ok := content["application/x-www-form-urlencoded"]; ok {
			ht.Fatalf("file form stayed urlencoded %#v", content)
		}

		header := http.Header{}
		var body []byte
		switch mode {
		case 0:
			var buf bytes.Buffer
			writer := multipart.NewWriter(&buf)
			for _, title := range titles {
				if err := writer.WriteField("title", title); err != nil {
					ht.Fatal(err)
				}
			}
			for _, part := range ones {
				w, err := writer.CreateFormFile("one", part.name)
				if err != nil {
					ht.Fatal(err)
				}
				if _, err := w.Write(part.body); err != nil {
					ht.Fatal(err)
				}
			}
			for _, part := range manys {
				w, err := writer.CreateFormFile("many", part.name)
				if err != nil {
					ht.Fatal(err)
				}
				if _, err := w.Write(part.body); err != nil {
					ht.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				ht.Fatal(err)
			}
			header.Set("Content-Type", writer.FormDataContentType())
			body = buf.Bytes()
		case 1:
			header.Set("Content-Type", "application/x-www-form-urlencoded")
			v := url.Values{}
			if len(titles) > 0 {
				v["title"] = titles
			}
			body = []byte(v.Encode())
		case 2:
			header.Set("Content-Type", "application/json")
			body = []byte(`{"title":"a"}`)
		default:
			header.Set("Content-Type", "a/b/c")
			body = []byte("x")
		}
		res := app.Request(http.MethodPost, "/upload", body, header)
		switch mode {
		case 2:
			hpProblem(ht, res, http.StatusBadRequest, "expected form body")
			return
		case 3:
			hpProblem(ht, res, http.StatusBadRequest, "invalid content type")
			return
		}
		if !onePresent {
			hpProblem(ht, res, http.StatusUnprocessableEntity, "one is required")
			return
		}
		if mode == 1 {
			hpProblem(ht, res, http.StatusUnprocessableEntity, "one is required")
			return
		}
		if res.Status != http.StatusOK {
			ht.Fatalf("upload %d %s", res.Status, res.Body)
		}
		var got hpUploadOut
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		wantTitle := ""
		if len(titles) > 0 {
			wantTitle = titles[0]
		}
		wantMany := make([]string, len(manys))
		for i, part := range manys {
			wantMany[i] = part.name + ":" + base64.StdEncoding.EncodeToString(part.body)
		}
		wantOne := ones[0].name + ":" + base64.StdEncoding.EncodeToString(ones[0].body)
		if got.Title != wantTitle || got.One != wantOne || !sameStringList(got.Many, wantMany) {
			ht.Fatalf("got %+v want %s %s %q", got, wantTitle, wantOne, wantMany)
		}
	})
}

type hpUploadIn struct {
	Title string                 `form:"title"`
	One   *multipart.FileHeader  `file:"one" required:"true" doc:"Payload"`
	Many  []multipart.FileHeader `file:"many"`
}

type hpUploadOut struct {
	Title string   `json:"title"`
	One   string   `json:"one"`
	Many  []string `json:"many"`
}

func hpFilePart(h *multipart.FileHeader) string {
	f, err := h.Open()
	if err != nil {
		return h.Filename + ":err"
	}
	defer f.Close()
	body, _ := io.ReadAll(f)
	return h.Filename + ":" + base64.StdEncoding.EncodeToString(body)
}

type hpWho struct {
	Subject  string `json:"subject"`
	ClientID string `json:"clientId"`
	Route    string `json:"route"`
	Granted  string `json:"granted"`
}

var hpGrantCalls atomic.Int32

var hpGrantUser = gfast.Dep("GrantUser", func(ctx context.Context, cred gfast.Bearer) (hpWho, error) {
	hpGrantCalls.Add(1)
	return hpWho{
		Subject:  cred.Subject,
		ClientID: cred.ClientID,
		Route:    strings.Join(cred.Scopes, " "),
		Granted:  strings.Join(cred.TokenScopes, " "),
	}, nil
})

func TestPropOAuthGrants(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		secret := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		password := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		subject := hegel.Draw(ht, hegel.Text().Alphabet("abcYZ").MinSize(1).MaxSize(8))
		passwordOn := hegel.Draw(ht, hegel.Booleans())
		kind := hegel.Draw(ht, hegel.Integers(0, 6))
		scopeWords := hegel.Draw(ht, hegel.Lists(hegel.SampledFrom([]string{"read", "write", "nope"})).MaxSize(3))
		emptyPass := hegel.Draw(ht, hegel.Booleans())
		emptyUser := hegel.Draw(ht, hegel.Booleans())
		refuse := hegel.Draw(ht, hegel.Integers(0, 2))
		refreshMode := hegel.Draw(ht, hegel.Integers(0, 2))

		var passCalls atomic.Int32
		cfg := gfast.OAuthConfig{
			Clients: []gfast.OAuthClient{
				{ID: "app", RedirectURIs: []string{"http://localhost/cb"}, Scopes: []string{"read", "write"}},
				{ID: "svc", Secret: secret, Scopes: []string{"read"}},
			},
			Scopes: map[string]string{"read": "Read", "write": "Write"},
		}
		if passwordOn {
			cfg.Password = func(ctx context.Context, username, pass string) (string, error) {
				passCalls.Add(1)
				if username != "ada" || pass != password {
					return "", gfast.Unauthorized("nope")
				}
				switch refuse {
				case 1:
					return "", nil
				case 2:
					return "", errors.New("nope")
				default:
					return subject, nil
				}
			}
		}
		app := gfast.New(gfast.OAuthServer(cfg))
		app.Get("/me", func(ctx context.Context, in *struct {
			Who hpWho `gfast:"dep=GrantUser"`
		}) (*hpWho, error) {
			return &in.Who, nil
		}, gfast.Scopes("write"))

		scope := strings.Join(scopeWords, " ")
		basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc:"+secret))
		form := url.Values{}
		header := http.Header{}
		switch kind {
		case 0:
			form.Set("grant_type", "password")
			form.Set("client_id", "app")
			user := "ada"
			pass := password
			if emptyUser {
				user = ""
			}
			if emptyPass {
				pass = ""
			}
			form.Set("username", user)
			form.Set("password", pass)
			if scope != "" {
				form.Set("scope", scope)
			}
		case 1:
			form.Set("grant_type", "client_credentials")
			if scope != "" {
				form.Set("scope", scope)
			}
			header.Set("Authorization", basic)
		case 2:
			form.Set("grant_type", "client_credentials")
			form.Set("client_id", "svc")
			form.Set("client_secret", secret)
			if scope != "" {
				form.Set("scope", scope)
			}
		case 3:
			form.Set("grant_type", "client_credentials")
			form.Set("client_id", "app")
			if scope != "" {
				form.Set("scope", scope)
			}
		case 4:
			form.Set("grant_type", "client_credentials")
			header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("svc:"+secret+"x")))
		case 5:
			form.Set("grant_type", "client_credentials")
			form.Set("client_id", "app")
			header.Set("Authorization", basic)
		default:
			form.Set("grant_type", "password")
			header.Set("Content-Type", "application/json")
		}
		if kind != 6 {
			header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		before := passCalls.Load()
		res := app.Request(http.MethodPost, "/oauth/token", []byte(form.Encode()), header)

		switch kind {
		case 6:
			hpOAuthErr(ht, res, http.StatusBadRequest, "invalid_request", "content type must be application/x-www-form-urlencoded")
			return
		case 5:
			hpOAuthErr(ht, res, http.StatusBadRequest, "invalid_request", "client id does not match")
			if res.Header.Get("WWW-Authenticate") != "" {
				ht.Fatalf("challenge %q", res.Header.Get("WWW-Authenticate"))
			}
			return
		case 4:
			hpOAuthErr(ht, res, http.StatusUnauthorized, "invalid_client", "invalid client")
			if res.Header.Get("WWW-Authenticate") != `Basic realm="oauth"` {
				ht.Fatalf("challenge %q", res.Header.Get("WWW-Authenticate"))
			}
			return
		case 3:
			hpOAuthErr(ht, res, http.StatusBadRequest, "unauthorized_client", "client credentials requires a client secret")
			return
		case 0:
			if !passwordOn {
				hpOAuthErr(ht, res, http.StatusBadRequest, "unsupported_grant_type", "password grant is not enabled")
				if passCalls.Load() != before {
					ht.Fatalf("password called %d", passCalls.Load()-before)
				}
				return
			}
			if emptyUser || emptyPass {
				hpOAuthErr(ht, res, http.StatusBadRequest, "invalid_request", "username and password are required")
				if passCalls.Load() != before {
					ht.Fatalf("password called when blank")
				}
				return
			}
			if passCalls.Load() != before+1 {
				ht.Fatalf("password calls %d", passCalls.Load()-before)
			}
			if refuse != 0 {
				hpOAuthErr(ht, res, http.StatusBadRequest, "invalid_grant", "invalid username or password")
				return
			}
			scopes, ok := hpAllowed([]string{"read", "write"}, scope)
			if !ok {
				hpOAuthErr(ht, res, http.StatusBadRequest, "invalid_scope", "unknown scope")
				return
			}
			tok := hpOAuthOK(ht, res, true, scopes)
			hpUseBearer(ht, app, tok.Access, subject, "app", "write", strings.Join(scopes, " "))
			hpRefresh(ht, app, tok, "app", "", subject, scopes, refreshMode, secret)
			return
		}
		scopes, ok := hpAllowed([]string{"read"}, scope)
		if !ok {
			hpOAuthErr(ht, res, http.StatusBadRequest, "invalid_scope", "unknown scope")
			return
		}
		tok := hpOAuthOK(ht, res, false, scopes)
		hpUseBearer(ht, app, tok.Access, "svc", "svc", "write", strings.Join(scopes, " "))
		bogus := app.Request(http.MethodGet, "/me", nil, http.Header{"Authorization": []string{"Bearer nope"}})
		hpProblem(ht, bogus, http.StatusUnauthorized, "invalid bearer token")
		if hpGrantCalls.Load() == 0 {
			ht.Fatal("bearer was not checked")
		}
	})
}

func hpAllowed(pool []string, requested string) ([]string, bool) {
	var want []string
	seen := map[string]struct{}{}
	for _, part := range strings.Fields(requested) {
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		want = append(want, part)
	}
	if len(want) == 0 {
		return append([]string(nil), pool...), true
	}
	have := map[string]struct{}{}
	for _, name := range pool {
		have[name] = struct{}{}
	}
	for _, name := range want {
		if _, ok := have[name]; !ok {
			return nil, false
		}
	}
	return want, true
}

type hpIssued struct {
	Access  string
	Refresh string
	Scope   string
}

func hpOAuthErr(ht *hegel.T, res *gfast.Result, status int, code, desc string) {
	ht.Helper()
	if res.Status != status {
		ht.Fatalf("status %d want %d body %s", res.Status, status, res.Body)
	}
	if res.Header.Get("Content-Type") != "application/json" || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Pragma") != "no-cache" {
		ht.Fatalf("headers %#v", res.Header)
	}
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := res.JSON(&body); err != nil {
		ht.Fatal(err)
	}
	if body.Error != code || body.Description != desc {
		ht.Fatalf("oauth %+v want %s %s", body, code, desc)
	}
}

func hpOAuthOK(ht *hegel.T, res *gfast.Result, refresh bool, scopes []string) hpIssued {
	ht.Helper()
	if res.Status != http.StatusOK || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Pragma") != "no-cache" {
		ht.Fatalf("token %d %#v %s", res.Status, res.Header, res.Body)
	}
	var raw map[string]any
	if err := res.JSON(&raw); err != nil {
		ht.Fatal(err)
	}
	access, _ := raw["access_token"].(string)
	gotRefresh, hasRefresh := raw["refresh_token"].(string)
	if access == "" || raw["token_type"] != "Bearer" || raw["expires_in"] != float64(3600) {
		ht.Fatalf("token %#v", raw)
	}
	if parts := strings.Split(access, "."); len(parts) != 3 {
		ht.Fatalf("access %q", access)
	}
	if refresh {
		if !hasRefresh || gotRefresh == "" || gotRefresh == access {
			ht.Fatalf("refresh %#v", raw)
		}
	} else if _, ok := raw["refresh_token"]; ok {
		ht.Fatalf("unexpected refresh %#v", raw)
	}
	wantScope := strings.Join(scopes, " ")
	if raw["scope"] != wantScope {
		ht.Fatalf("scope %#v want %q", raw["scope"], wantScope)
	}
	return hpIssued{Access: access, Refresh: gotRefresh, Scope: wantScope}
}

func hpUseBearer(ht *hegel.T, app *gfast.App, access, subject, clientID, route, granted string) {
	ht.Helper()
	before := hpGrantCalls.Load()
	res := app.Request(http.MethodGet, "/me", nil, http.Header{"Authorization": []string{"Bearer " + access}})
	if res.Status != http.StatusOK {
		ht.Fatalf("me %d %s", res.Status, res.Body)
	}
	if hpGrantCalls.Load() != before+1 {
		ht.Fatalf("calls %d", hpGrantCalls.Load()-before)
	}
	var who hpWho
	if err := res.JSON(&who); err != nil {
		ht.Fatal(err)
	}
	if who.Subject != subject || who.ClientID != clientID || who.Route != route || who.Granted != granted {
		ht.Fatalf("who %+v want %s %s %s %s", who, subject, clientID, route, granted)
	}
}

func hpRefresh(ht *hegel.T, app *gfast.App, tok hpIssued, clientID, clientSecret, subject string, granted []string, mode int, svcSecret string) {
	ht.Helper()
	try := func(id, secret, token, scope string) *gfast.Result {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {token},
		}
		header := http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}}
		if secret != "" {
			header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(id+":"+secret)))
		} else {
			form.Set("client_id", id)
		}
		if scope != "" {
			form.Set("scope", scope)
		}
		return app.Request(http.MethodPost, "/oauth/token", []byte(form.Encode()), header)
	}
	switch mode {
	case 1:
		bad := try(clientID, clientSecret, tok.Refresh, "nope")
		hpOAuthErr(ht, bad, http.StatusBadRequest, "invalid_scope", "unknown scope")
		again := try(clientID, clientSecret, tok.Refresh, "")
		hpOAuthErr(ht, again, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		hpUseBearer(ht, app, tok.Access, subject, clientID, "write", tok.Scope)
	case 2:
		wrong := try("svc", svcSecret, tok.Refresh, "")
		hpOAuthErr(ht, wrong, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		ok := try(clientID, clientSecret, tok.Refresh, "")
		next := hpOAuthOK(ht, ok, true, granted)
		if next.Refresh == tok.Refresh || next.Access == tok.Access {
			ht.Fatalf("rotation did not change tokens %+v", next)
		}
		spent := try(clientID, clientSecret, tok.Refresh, "")
		hpOAuthErr(ht, spent, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		hpUseBearer(ht, app, tok.Access, subject, clientID, "write", tok.Scope)
		hpUseBearer(ht, app, next.Access, subject, clientID, "write", strings.Join(granted, " "))
	default:
		only := ""
		want := granted
		if len(granted) > 0 {
			only = granted[0]
			want = []string{granted[0]}
		}
		ok := try(clientID, clientSecret, tok.Refresh, only)
		next := hpOAuthOK(ht, ok, true, want)
		if next.Refresh == tok.Refresh {
			ht.Fatalf("refresh reused %q", next.Refresh)
		}
		spent := try(clientID, clientSecret, tok.Refresh, "")
		hpOAuthErr(ht, spent, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		hpUseBearer(ht, app, next.Access, subject, clientID, "write", strings.Join(want, " "))
	}
}
