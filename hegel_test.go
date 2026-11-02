// Hegel v0.9.28.
package gfast_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"hegel.dev/go/hegel"

	"github.com/pyrex41/gfast"
)

func prop(t *testing.T, fn func(*hegel.T)) {
	t.Helper()
	hegel.Test(t, fn, hegel.WithDatabase("hegel-db"))
}

func hpDo(app *gfast.App, method, target string, body []byte, header http.Header, forceCL bool, cl int) *gfast.Result {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if len(body) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if forceCL {
		req.ContentLength = int64(cl)
	}
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	payload, _ := io.ReadAll(res.Body)
	return &gfast.Result{Status: res.StatusCode, Header: res.Header.Clone(), Body: payload}
}

func hpProblem(ht *hegel.T, res *gfast.Result, status int, detail string) {
	ht.Helper()
	if res.Status != status {
		ht.Fatalf("status %d want %d body %s", res.Status, status, res.Body)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/problem+json" {
		ht.Fatalf("content type %q body %s", ct, res.Body)
	}
	var body struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := res.JSON(&body); err != nil {
		ht.Fatal(err)
	}
	if body.Status != status || body.Title != http.StatusText(status) || body.Detail != detail {
		ht.Fatalf("problem %+v want status %d detail %q", body, status, detail)
	}
}

func hpStatus(ht *hegel.T, res *gfast.Result, status int) {
	ht.Helper()
	if res.Status != status {
		ht.Fatalf("status %d want %d body %s", res.Status, status, res.Body)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/problem+json" {
		ht.Fatalf("content type %q body %s", ct, res.Body)
	}
	var body struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := res.JSON(&body); err != nil {
		ht.Fatal(err)
	}
	if body.Status != status || body.Title != http.StatusText(status) || body.Detail == "" {
		ht.Fatalf("problem %+v", body)
	}
}

func hpChallenge(ht *hegel.T, res *gfast.Result, want string) {
	ht.Helper()
	if got := res.Header.Get("WWW-Authenticate"); got != want {
		ht.Fatalf("challenge %q want %q body %s", got, want, res.Body)
	}
}

// hpJoin is the path join used by Group and route registration.
func hpJoin(prefix, path string) string {
	if prefix == "" {
		return path
	}
	if path == "" {
		return prefix
	}
	return strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(path, "/")
}

// hpOpID is the OpenAPI operationId derived from the method and path.
func hpOpID(method, path string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(method))
	for _, r := range path {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	if s == "" {
		s = strings.ToLower(method)
	}
	return s
}

// hpSanitize is the API-key scheme-name encoding.
func hpSanitize(name string) string {
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// hpHTML is the /docs title escaping.
func hpHTML(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// hpBearer is the Authorization parse used for bearer credentials.
func hpBearer(present bool, value string) (string, bool) {
	if !present {
		return "", false
	}
	const prefix = "bearer "
	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(value[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

func hpFlip(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			b.WriteRune(unicode.ToLower(r))
		case unicode.IsLower(r):
			b.WriteRune(unicode.ToUpper(r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

type hpPrincipal struct {
	ID     string   `json:"id"`
	Scopes []string `json:"scopes,omitempty"`
}

type hpCell struct {
	Name string `json:"name" minLength:"2" maxLength:"5"`
}

type hpBody struct {
	Title string   `json:"title" minLength:"2" maxLength:"5"`
	Cells []hpCell `json:"cells"`
}

type hpTitle struct {
	Title string `json:"title" minLength:"2" maxLength:"5"`
}

type hpBox struct{ Name string }

func (b *hpBox) Close() error {
	hpEvents = append(hpEvents, "close-"+b.Name)
	return errors.New("close " + b.Name)
}

var (
	hpUserCalls atomic.Int32
	hpViewCalls atomic.Int32
	hpBothCalls atomic.Int32
	hpBoxACalls atomic.Int32
	hpBoxBCalls atomic.Int32
	hpSeenToken string
	hpSeenScope []string
	hpEvents    []string
	hpKeySeq    atomic.Int64
)

var hpUser = gfast.Dep("hpUser", func(ctx context.Context, cred gfast.Bearer) (hpPrincipal, error) {
	hpUserCalls.Add(1)
	hpSeenToken = cred.Token
	hpSeenScope = append([]string(nil), cred.Scopes...)
	return hpPrincipal{ID: cred.Token, Scopes: append([]string(nil), cred.Scopes...)}, nil
})

type hpView struct {
	Token  string
	Scopes []string
}

var hpViewer = gfast.Dep("hpViewer", func(ctx context.Context, cred gfast.Bearer) (hpView, error) {
	hpViewCalls.Add(1)
	return hpView{Token: cred.Token, Scopes: cred.Scopes}, nil
})

var hpBoth = gfast.Dep("hpBoth", func(ctx context.Context, cred gfast.Bearer, basic gfast.Basic) (hpPrincipal, error) {
	hpBothCalls.Add(1)
	return hpPrincipal{ID: cred.Token + ":" + basic.Username}, nil
})

var hpBoxA = gfast.Dep("hpBoxA", func(ctx context.Context) (*hpBox, error) {
	hpBoxACalls.Add(1)
	return &hpBox{Name: "A"}, nil
})

var hpBoxB = gfast.Dep("hpBoxB", func(ctx context.Context) (*hpBox, error) {
	hpBoxBCalls.Add(1)
	return &hpBox{Name: "B"}, nil
})

func hpReset() {
	hpUserCalls.Store(0)
	hpViewCalls.Store(0)
	hpBothCalls.Store(0)
	hpBoxACalls.Store(0)
	hpBoxBCalls.Store(0)
	hpSeenToken = ""
	hpSeenScope = nil
	hpEvents = nil
}

type hpScalarIn struct {
	ID     int16   `path:"id"`
	N      int64   `query:"n"`
	U      uint8   `query:"u"`
	Flag   *bool   `query:"flag"`
	On     bool    `query:"on"`
	F      float64 `query:"f"`
	Q      string  `query:"q"`
	Label  *string `query:"label"`
	Req    string  `header:"X-Request-Id"`
	Trace  *string `header:"X-Trace"`
	Cookie string  `cookie:"session"`
	Extra  *string `cookie:"extra"`
}

type hpScalarOut struct {
	ID     int16   `json:"id"`
	N      int64   `json:"n"`
	U      uint8   `json:"u"`
	Flag   *bool   `json:"flag"`
	On     bool    `json:"on"`
	F      string  `json:"f"`
	Q      string  `json:"q"`
	Label  *string `json:"label"`
	Req    string  `json:"req"`
	Trace  *string `json:"trace"`
	Cookie string  `json:"cookie"`
	Extra  *string `json:"extra"`
}

func TestPropJSONBodyValidation(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		hpReset()
		text := hegel.Text().Alphabet("ab👍\u0301").MaxSize(8)
		title := hegel.Draw(ht, text)
		cells := hegel.Draw(ht, hegel.Lists(hegel.Map(text, func(s string) hpCell { return hpCell{Name: s} })).MaxSize(3))
		defect := hegel.Draw(ht, hegel.Integers(0, 5))
		chunked := hegel.Draw(ht, hegel.Booleans())
		ignored := hegel.Draw(ht, hegel.Binary(0, 24))
		extra := hegel.Draw(ht, hegel.Text().Alphabet("xyz").MinSize(1).MaxSize(4))

		if defect == 5 && len(cells) == 0 {
			cells = []hpCell{{Name: "abcd"}}
		}

		var hits int
		app := gfast.New()
		app.Post("/items", func(ctx context.Context, in *struct {
			Body hpBody
			User hpPrincipal `gfast:"dep=hpUser"`
			Also hpPrincipal `gfast:"dep=hpUser"`
		}) (*hpBody, error) {
			hits++
			return &in.Body, nil
		})

		var body []byte
		switch defect {
		case 1:
			body = []byte("{\"title\":\"\xff\"}")
		case 2:
			quoted, _ := json.Marshal(title)
			body = []byte(`{"title":` + string(quoted) + `,"title":` + string(quoted) + `,"cells":[]}`)
		case 3:
			body = []byte(`{"title":1,"cells":[]}`)
		case 4:
			payload := map[string]any{"title": title, "cells": cells, extra: 1}
			body, _ = json.Marshal(payload)
		case 5:
			rawCells := make([]any, len(cells))
			for i, cell := range cells {
				rawCells[i] = map[string]any{"name": cell.Name, extra: true}
			}
			body, _ = json.Marshal(map[string]any{"title": title, "cells": rawCells})
		default:
			body, _ = json.Marshal(hpBody{Title: title, Cells: cells})
		}

		header := http.Header{"Authorization": []string{"Bearer tok"}}
		res := hpDo(app, http.MethodPost, "/items", body, header, chunked, -1)
		if defect != 0 {
			hpStatus(ht, res, http.StatusBadRequest)
			if strings.Contains(string(res.Body), "must be at least") || strings.Contains(string(res.Body), "must be at most") {
				ht.Fatalf("validation ran on a rejected document: %s", res.Body)
			}
			if hits != 0 || hpUserCalls.Load() != 0 {
				ht.Fatalf("handler %d provider %d on defect %d", hits, hpUserCalls.Load(), defect)
			}
		} else if issues := hpBodyIssues(title, cells); len(issues) > 0 {
			hpIssues(ht, res, http.StatusUnprocessableEntity, issues)
			if hits != 0 || hpUserCalls.Load() != 0 {
				ht.Fatalf("handler %d provider %d", hits, hpUserCalls.Load())
			}
		} else {
			if res.Status != http.StatusOK {
				ht.Fatalf("status %d body %s", res.Status, res.Body)
			}
			if ct := res.Header.Get("Content-Type"); ct != "application/json" {
				ht.Fatalf("content type %s", ct)
			}
			var got hpBody
			if err := res.JSON(&got); err != nil {
				ht.Fatal(err)
			}
			if got.Title != title || !reflect.DeepEqual(normCells(got.Cells), normCells(cells)) {
				ht.Fatalf("got %+v want title %q cells %+v", got, title, cells)
			}
			if hits != 1 || hpUserCalls.Load() != 1 {
				ht.Fatalf("handler %d provider %d", hits, hpUserCalls.Load())
			}
		}

		beforeHits, beforeCalls := hits, hpUserCalls.Load()
		zero := hpDo(app, http.MethodPost, "/items", ignored, header, true, 0)
		hpIssues(ht, zero, http.StatusUnprocessableEntity, hpBodyIssues("", nil))
		if hits != beforeHits || hpUserCalls.Load() != beforeCalls {
			ht.Fatalf("ContentLength 0 read the body: handler %d provider %d", hits, hpUserCalls.Load())
		}
	})
}

type hpIssue struct {
	Loc  []string
	Type string
	Msg  string
}

func hpBodyIssues(title string, cells []hpCell) []hpIssue {
	var issues []hpIssue
	issues = append(issues, hpStringIssues(title, "title", []string{"body", "title"}, 2, 5)...)
	for i, cell := range cells {
		loc := []string{"body", "cells", strconv.Itoa(i), "name"}
		issues = append(issues, hpStringIssues(cell.Name, "name", loc, 2, 5)...)
	}
	return issues
}

func hpStringIssues(value, name string, loc []string, min, max int) []hpIssue {
	var issues []hpIssue
	n := utf8.RuneCountInString(value)
	if n < min {
		issues = append(issues, hpIssue{loc, "string_too_short", name + " must be at least " + strconv.Itoa(min) + " characters"})
	}
	if n > max {
		issues = append(issues, hpIssue{loc, "string_too_long", name + " must be at most " + strconv.Itoa(max) + " characters"})
	}
	return issues
}

func hpIssues(ht *hegel.T, res *gfast.Result, status int, issues []hpIssue) {
	ht.Helper()
	msgs := make([]string, len(issues))
	for i, issue := range issues {
		msgs[i] = issue.Msg
	}
	hpProblem(ht, res, status, strings.Join(msgs, "; "))
	var body struct {
		Errors []struct {
			Loc  []string `json:"loc"`
			Type string   `json:"type"`
			Msg  string   `json:"msg"`
		} `json:"errors"`
	}
	if err := res.JSON(&body); err != nil {
		ht.Fatal(err)
	}
	if len(body.Errors) != len(issues) {
		ht.Fatalf("errors %#v want %d", body.Errors, len(issues))
	}
	for i, issue := range issues {
		got := body.Errors[i]
		if got.Type != issue.Type || got.Msg != issue.Msg || !reflect.DeepEqual(got.Loc, issue.Loc) {
			ht.Fatalf("error %d %#v want %+v", i, got, issue)
		}
	}
}

func normCells(cells []hpCell) []hpCell {
	if cells == nil {
		return []hpCell{}
	}
	return cells
}

func TestPropScalarBinding(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		num := hegel.Text().Alphabet("0123456789-+x").MinSize(1).MaxSize(8)
		idRaw := hegel.Draw(ht, num)
		nRaws := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("0123456789-+").MinSize(1).MaxSize(20)).MinSize(1).MaxSize(3))
		uRaw := hegel.Draw(ht, hegel.Text().Alphabet("0123456789-+").MinSize(1).MaxSize(4))
		boolText := hegel.OneOf(
			hegel.SampledFrom([]string{"1", "t", "T", "true", "TRUE", "True", "0", "f", "F", "false", "FALSE", "False"}),
			hegel.Text().Alphabet("truefalsTRUE01x ").MinSize(1).MaxSize(6),
		)
		flagRaws := hegel.Draw(ht, hegel.Lists(boolText).MaxSize(3))
		onRaws := hegel.Draw(ht, hegel.Lists(boolText).MaxSize(3))
		fRaw := hegel.Draw(ht, hegel.OneOf(
			hegel.SampledFrom([]string{"NaN", "Inf", "+Inf", "-Inf", "1e309", "0", "1.5"}),
			hegel.Text().Alphabet("0123456789.+-eE").MinSize(1).MaxSize(12),
		))
		wide := hegel.Text().Alphabet("ab👍\u0301XYZ019._-~").MaxSize(8)
		qRaws := hegel.Draw(ht, hegel.Lists(wide).MaxSize(3))
		labelRaws := hegel.Draw(ht, hegel.Lists(wide).MaxSize(3))
		headerText := hegel.Text().Alphabet("abcXYZ019 _.-~!#$%&'*+=?@^_|~").MaxSize(8)
		reqRaws := hegel.Draw(ht, hegel.Lists(headerText).MaxSize(3))
		traceRaws := hegel.Draw(ht, hegel.Lists(headerText).MaxSize(3))
		cookieText := hegel.Text().Alphabet("abcXYZ019_-.~!#$%&'*+=?@^_|~").MaxSize(8)
		sessionRaws := hegel.Draw(ht, hegel.Lists(cookieText).MaxSize(3))
		extraRaws := hegel.Draw(ht, hegel.Lists(cookieText).MaxSize(3))
		lowerHeader := hegel.Draw(ht, hegel.Booleans())

		app := gfast.New()
		app.Get("/s/{id}", func(ctx context.Context, in *hpScalarIn) (*hpScalarOut, error) {
			return &hpScalarOut{
				ID: in.ID, N: in.N, U: in.U, Flag: in.Flag, On: in.On,
				F: strconv.FormatFloat(in.F, 'g', -1, 64),
				Q: in.Q, Label: in.Label, Req: in.Req, Trace: in.Trace,
				Cookie: in.Cookie, Extra: in.Extra,
			}, nil
		})

		q := url.Values{}
		q["n"] = nRaws
		q.Set("u", uRaw)
		q.Set("f", fRaw)
		if len(flagRaws) > 0 {
			q["flag"] = flagRaws
		}
		if len(onRaws) > 0 {
			q["on"] = onRaws
		}
		if len(qRaws) > 0 {
			q["q"] = qRaws
		}
		if len(labelRaws) > 0 {
			q["label"] = labelRaws
		}
		target := "/s/" + url.PathEscape(idRaw) + "?" + q.Encode()
		header := http.Header{}
		reqName, traceName := "X-Request-Id", "X-Trace"
		if lowerHeader {
			reqName, traceName = strings.ToLower(reqName), strings.ToLower(traceName)
		}
		for _, value := range reqRaws {
			header.Add(reqName, value)
		}
		for _, value := range traceRaws {
			header.Add(traceName, value)
		}
		if cookie := hpCookie(sessionRaws, extraRaws); cookie != "" {
			header.Set("Cookie", cookie)
		}

		res := app.Request(http.MethodGet, target, nil, header)
		want, detail, ok := hpScalarOracle(idRaw, nRaws, uRaw, flagRaws, onRaws, fRaw, qRaws, labelRaws, reqRaws, traceRaws, sessionRaws, extraRaws)
		if !ok {
			hpProblem(ht, res, http.StatusBadRequest, detail)
			return
		}
		if res.Status != http.StatusOK {
			ht.Fatalf("status %d body %s", res.Status, res.Body)
		}
		if ct := res.Header.Get("Content-Type"); ct != "application/json" {
			ht.Fatalf("content type %s", ct)
		}
		var got hpScalarOut
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			ht.Fatalf("got %+v want %+v", got, want)
		}
	})
}

func hpCookie(session, extra []string) string {
	var pairs []string
	for _, value := range session {
		pairs = append(pairs, "session="+value)
	}
	for _, value := range extra {
		pairs = append(pairs, "extra="+value)
	}
	return strings.Join(pairs, "; ")
}

func hpScalarOracle(idRaw string, nRaws []string, uRaw string, flagRaws, onRaws []string, fRaw string, qRaws, labelRaws, reqRaws, traceRaws, sessionRaws, extraRaws []string) (hpScalarOut, string, bool) {
	var out hpScalarOut
	id, err := strconv.ParseInt(idRaw, 10, 16)
	if err != nil {
		return out, "id: " + err.Error(), false
	}
	out.ID = int16(id)
	n, err := strconv.ParseInt(nRaws[0], 10, 64)
	if err != nil {
		return out, "n: " + err.Error(), false
	}
	out.N = n
	u, err := strconv.ParseUint(uRaw, 10, 8)
	if err != nil {
		return out, "u: " + err.Error(), false
	}
	out.U = uint8(u)
	if len(flagRaws) > 0 {
		flag, err := strconv.ParseBool(flagRaws[0])
		if err != nil {
			return out, "flag: " + err.Error(), false
		}
		out.Flag = &flag
	}
	if len(onRaws) > 0 {
		on, err := strconv.ParseBool(onRaws[0])
		if err != nil {
			return out, "on: " + err.Error(), false
		}
		out.On = on
	}
	f, err := strconv.ParseFloat(fRaw, 64)
	if err != nil {
		return out, "f: " + err.Error(), false
	}
	out.F = strconv.FormatFloat(f, 'g', -1, 64)
	if len(qRaws) > 0 {
		out.Q = qRaws[0]
	}
	if len(labelRaws) > 0 {
		label := labelRaws[0]
		out.Label = &label
	}
	if len(reqRaws) > 0 {
		out.Req = reqRaws[0]
	}
	if len(traceRaws) > 0 {
		trace := traceRaws[0]
		out.Trace = &trace
	}
	if len(sessionRaws) > 0 {
		out.Cookie = sessionRaws[0]
	}
	if len(extraRaws) > 0 {
		extra := extraRaws[0]
		out.Extra = &extra
	}
	return out, "", true
}

func TestPropBearerScopesAndOverride(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		hpReset()
		scopes := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abc:").MinSize(1).MaxSize(6)).MinSize(1).MaxSize(4))
		mode := hegel.Draw(ht, hegel.Integers(0, 1))
		token := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019._-~").MinSize(1).MaxSize(12))
		var present bool
		var headerValue string
		if mode == 0 {
			present = hegel.Draw(ht, hegel.Booleans())
			if present {
				kind := hegel.Draw(ht, hegel.Integers(0, 3))
				switch kind {
				case 0:
					scheme := hegel.Draw(ht, hegel.SampledFrom([]string{"Bearer", "bearer", "BEARER", "BeArEr"}))
					left := hegel.Draw(ht, hegel.Integers(0, 3))
					right := hegel.Draw(ht, hegel.Integers(0, 3))
					headerValue = scheme + " " + strings.Repeat(" ", left) + token + strings.Repeat(" ", right)
				case 1:
					headerValue = "Bearer"
				case 2:
					headerValue = "Token " + token
				default:
					headerValue = "bearer" + token
				}
			}
		} else {
			present = true
			headerValue = hegel.Draw(ht, hegel.Text().Alphabet("Bearer abcXYZ019").MaxSize(18))
		}
		overrideID := hegel.Draw(ht, hegel.Text().Alphabet("xyz019").MinSize(1).MaxSize(8))
		tok, ok := hpBearer(present, headerValue)

		var viewHits int
		app := gfast.New()
		gfast.Get(app, "/view", func(ctx context.Context, in *struct {
			A hpView `gfast:"dep=hpViewer"`
			B hpView `gfast:"dep=hpViewer"`
		}) (*struct {
			Token string   `json:"token"`
			A     []string `json:"a"`
			B     []string `json:"b"`
		}, error) {
			viewHits++
			out := &struct {
				Token string   `json:"token"`
				A     []string `json:"a"`
				B     []string `json:"b"`
			}{
				Token: in.A.Token,
				A:     append([]string(nil), in.A.Scopes...),
				B:     append([]string(nil), in.B.Scopes...),
			}
			in.A.Scopes[0] = "mutated"
			return out, nil
		}, gfast.Scopes(scopes...))
		var groupHits int
		group := app.Group("/v1", gfast.Require(hpUser), gfast.Scopes("group:read"))
		gfast.Get(group, "/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
			groupHits++
			return &struct{ OK bool }{OK: true}, nil
		})

		header := http.Header{}
		if present {
			header.Set("Authorization", headerValue)
		}
		view := app.Request(http.MethodGet, "/view", nil, header)
		if !ok {
			hpProblem(ht, view, http.StatusUnauthorized, "missing bearer token")
			hpChallenge(ht, view, "Bearer")
			if viewHits != 0 || hpViewCalls.Load() != 0 {
				ht.Fatalf("view ran without a token: hits %d calls %d", viewHits, hpViewCalls.Load())
			}
		} else {
			if view.Status != http.StatusOK {
				ht.Fatalf("view %d %s", view.Status, view.Body)
			}
			var got struct {
				Token string   `json:"token"`
				A     []string `json:"a"`
				B     []string `json:"b"`
			}
			if err := view.JSON(&got); err != nil {
				ht.Fatal(err)
			}
			if got.Token != tok || !reflect.DeepEqual(got.A, scopes) || !reflect.DeepEqual(got.B, scopes) {
				ht.Fatalf("view %+v token %q scopes %v", got, tok, scopes)
			}
			if hpViewCalls.Load() != 1 || viewHits != 1 {
				ht.Fatalf("memo calls %d hits %d", hpViewCalls.Load(), viewHits)
			}
			again := app.Request(http.MethodGet, "/view", nil, header)
			if again.Status != http.StatusOK {
				ht.Fatalf("second view %d %s", again.Status, again.Body)
			}
			var got2 struct {
				A []string `json:"a"`
			}
			if err := again.JSON(&got2); err != nil {
				ht.Fatal(err)
			}
			if !reflect.DeepEqual(got2.A, scopes) {
				ht.Fatalf("mutation leaked into the next request: %v", got2.A)
			}
			if hpViewCalls.Load() != 2 {
				ht.Fatalf("second request calls %d", hpViewCalls.Load())
			}
		}

		groupRes := app.Request(http.MethodGet, "/v1/ping", nil, header)
		if !ok {
			hpProblem(ht, groupRes, http.StatusUnauthorized, "missing bearer token")
			hpChallenge(ht, groupRes, "Bearer")
			if groupHits != 0 || hpUserCalls.Load() != 0 {
				ht.Fatalf("group ran without a token: hits %d calls %d", groupHits, hpUserCalls.Load())
			}
		} else {
			if groupRes.Status != http.StatusOK || groupHits != 1 || hpUserCalls.Load() != 1 {
				ht.Fatalf("group status %d hits %d calls %d body %s", groupRes.Status, groupHits, hpUserCalls.Load(), groupRes.Body)
			}
			if hpSeenToken != tok || !reflect.DeepEqual(hpSeenScope, []string{"group:read"}) {
				ht.Fatalf("group saw token %q scopes %v", hpSeenToken, hpSeenScope)
			}
		}

		spec := hpSpec(ht, app)
		if !reflect.DeepEqual(spec.security("/view", "get"), []map[string][]string{{"bearerAuth": scopes}}) {
			ht.Fatalf("view security %v", spec.security("/view", "get"))
		}
		if !reflect.DeepEqual(spec.security("/v1/ping", "get"), []map[string][]string{{"bearerAuth": {"group:read"}}}) {
			ht.Fatalf("group security %v", spec.security("/v1/ping", "get"))
		}

		var overrides atomic.Int32
		other := gfast.New()
		gfast.Get(other, "/view", func(ctx context.Context, in *struct {
			A hpPrincipal `gfast:"dep=hpUser"`
			B hpPrincipal `gfast:"dep=hpUser"`
		}) (*hpPrincipal, error) {
			if in.A.ID != in.B.ID {
				ht.Fatalf("override fields differ")
			}
			return &in.A, nil
		})
		untouched := gfast.New()
		gfast.Get(untouched, "/view", func(ctx context.Context, in *struct {
			A hpPrincipal `gfast:"dep=hpUser"`
		}) (*hpPrincipal, error) {
			return &in.A, nil
		})
		before := hpUserCalls.Load()
		other.Override(hpUser, func(ctx context.Context) (hpPrincipal, error) {
			overrides.Add(1)
			return hpPrincipal{ID: overrideID}, nil
		})
		over := other.Request(http.MethodGet, "/view", nil)
		if over.Status != http.StatusOK {
			ht.Fatalf("override %d %s", over.Status, over.Body)
		}
		var got hpPrincipal
		if err := over.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.ID != overrideID || overrides.Load() != 1 || hpUserCalls.Load() != before {
			ht.Fatalf("override id %q calls %d provider %d", got.ID, overrides.Load(), hpUserCalls.Load())
		}
		denied := untouched.Request(http.MethodGet, "/view", nil)
		hpProblem(ht, denied, http.StatusUnauthorized, "missing bearer token")
		if hpUserCalls.Load() != before {
			ht.Fatalf("override leaked and called the provider")
		}
	})
}

func TestPropBasicAuth(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		mode := hegel.Draw(ht, hegel.Integers(0, 2))
		user := hegel.Draw(ht, hegel.Text().Alphabet("abYZ09._~-").MaxSize(8))
		pass := hegel.Draw(ht, hegel.Text().Alphabet("ab:YZ09 _~-").MaxSize(12))
		var present bool
		var value string
		switch mode {
		case 0:
			present = true
			scheme := hegel.Draw(ht, hegel.SampledFrom([]string{"Basic", "basic", "BASIC"}))
			value = scheme + " " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
		case 1:
			present = true
			value = hegel.Draw(ht, hegel.Text().Alphabet("Basic abcXYZ019+/= ").MaxSize(24))
		default:
			present = false
		}

		app := gfast.New()
		app.Get("/b", func(ctx context.Context, in *struct {
			Cred gfast.Basic `gfast:"dep=basicAuth"`
		}) (*struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		}, error) {
			return &struct {
				User string `json:"user"`
				Pass string `json:"pass"`
			}{User: in.Cred.Username, Pass: in.Cred.Password}, nil
		})

		oracle := httptest.NewRequest(http.MethodGet, "/b", nil)
		header := http.Header{}
		if present {
			oracle.Header.Set("Authorization", value)
			header.Set("Authorization", value)
		}
		u, p, ok := oracle.BasicAuth()
		res := app.Request(http.MethodGet, "/b", nil, header)
		if !ok {
			hpProblem(ht, res, http.StatusUnauthorized, "missing basic credentials")
			hpChallenge(ht, res, `Basic realm="api"`)
			return
		}
		if res.Status != http.StatusOK {
			ht.Fatalf("status %d body %s", res.Status, res.Body)
		}
		var got struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		}
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.User != u || got.Pass != p {
			ht.Fatalf("got %#v want user %q pass %q", got, u, p)
		}
	})
}

func TestPropBearerPreemptsBasic(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		hpReset()
		kind := hegel.Draw(ht, hegel.Integers(0, 2))
		token := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		user := hegel.Draw(ht, hegel.Text().Alphabet("abYZ09").MaxSize(6))
		pass := hegel.Draw(ht, hegel.Text().Alphabet("abYZ09").MaxSize(6))
		header := http.Header{}
		switch kind {
		case 0:
		case 1:
			header.Set("Authorization", "Bearer "+token)
		default:
			header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
		}
		app := gfast.New()
		app.Get("/both", func(ctx context.Context, in *struct {
			User hpPrincipal `gfast:"dep=hpBoth"`
		}) (*hpPrincipal, error) {
			return &in.User, nil
		}, gfast.Scopes("both:write"))
		res := app.Request(http.MethodGet, "/both", nil, header)
		if hpBothCalls.Load() != 0 {
			ht.Fatalf("provider ran: %d body %s", hpBothCalls.Load(), res.Body)
		}
		hpProblem(ht, res, http.StatusUnauthorized, map[bool]string{true: "missing basic credentials", false: "missing bearer token"}[kind == 1])
		if kind == 1 {
			hpChallenge(ht, res, `Basic realm="api"`)
		} else {
			hpChallenge(ht, res, "Bearer")
		}
	})
}

func TestPropAPIKeyValues(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		valueText := hegel.Text().Alphabet("abcXYZ019 ._-~").MinSize(1).MaxSize(8)
		hMode := hegel.Draw(ht, hegel.Integers(0, 2))
		qMode := hegel.Draw(ht, hegel.Integers(0, 2))
		hVals := hegel.Draw(ht, hegel.Lists(valueText).MinSize(1).MaxSize(3))
		qVals := hegel.Draw(ht, hegel.Lists(valueText).MinSize(1).MaxSize(3))
		lower := hegel.Draw(ht, hegel.Booleans())

		app := gfast.New()
		app.Get("/k", func(ctx context.Context, in *struct {
			Key gfast.APIKey `gfast:"dep=apiKey_header_X_API_Key"`
		}) (*struct {
			Value string `json:"value"`
			Name  string `json:"name"`
			In    string `json:"in"`
		}, error) {
			return &struct {
				Value string `json:"value"`
				Name  string `json:"name"`
				In    string `json:"in"`
			}{Value: in.Key.Value, Name: in.Key.Name, In: in.Key.In}, nil
		})
		app.Get("/q", func(ctx context.Context, in *struct {
			Key gfast.APIKey `gfast:"dep=apiKey_query_api_key"`
		}) (*struct {
			Value string `json:"value"`
			Name  string `json:"name"`
			In    string `json:"in"`
		}, error) {
			return &struct {
				Value string `json:"value"`
				Name  string `json:"name"`
				In    string `json:"in"`
			}{Value: in.Key.Value, Name: in.Key.Name, In: in.Key.In}, nil
		})

		hName := "X-API-Key"
		if lower {
			hName = strings.ToLower(hName)
		}
		header := http.Header{}
		switch hMode {
		case 1:
			header.Add(hName, "")
		case 2:
			for _, value := range hVals {
				header.Add(hName, value)
			}
		}
		res := app.Request(http.MethodGet, "/k", nil, header)
		if hMode != 2 {
			hpProblem(ht, res, http.StatusUnauthorized, "missing api key")
			hpChallenge(ht, res, "X-API-Key")
		} else {
			hpKeyEqual(ht, res, hVals[0], "X-API-Key", "header")
		}

		q := url.Values{}
		switch qMode {
		case 1:
			q.Set("api_key", "")
		case 2:
			q["api_key"] = qVals
		}
		target := "/q"
		if encoded := q.Encode(); encoded != "" {
			target += "?" + encoded
		}
		qres := app.Request(http.MethodGet, target, nil)
		if qMode != 2 {
			hpProblem(ht, qres, http.StatusUnauthorized, "missing api key")
			hpChallenge(ht, qres, "apiKey")
		} else {
			hpKeyEqual(ht, qres, qVals[0], "api_key", "query")
		}
		if qMode == 2 && hpFlip("api_key") != "api_key" {
			flipped := app.Request(http.MethodGet, "/q?"+url.Values{hpFlip("api_key"): {qVals[0]}}.Encode(), nil)
			hpProblem(ht, flipped, http.StatusUnauthorized, "missing api key")
			hpChallenge(ht, flipped, "apiKey")
		}
	})
}

func hpKeyEqual(ht *hegel.T, res *gfast.Result, value, name, loc string) {
	ht.Helper()
	if res.Status != http.StatusOK {
		ht.Fatalf("status %d body %s", res.Status, res.Body)
	}
	var got struct {
		Value string `json:"value"`
		Name  string `json:"name"`
		In    string `json:"in"`
	}
	if err := res.JSON(&got); err != nil {
		ht.Fatal(err)
	}
	if got.Value != value || got.Name != name || got.In != loc {
		ht.Fatalf("got %+v want value %q name %q in %q", got, value, name, loc)
	}
}

func TestPropAPIKeySchemes(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		core := hegel.Text().Alphabet("ABab12-_").MinSize(1).MaxSize(8)
		hName := hegel.Draw(ht, core) + "N" + strconv.FormatInt(hpKeySeq.Add(1), 10)
		qName := hegel.Draw(ht, core) + "N" + strconv.FormatInt(hpKeySeq.Add(1), 10)
		hPresent := hegel.Draw(ht, hegel.Booleans())
		hEmpty := hegel.Draw(ht, hegel.Booleans())
		qPresent := hegel.Draw(ht, hegel.Booleans())
		qEmpty := hegel.Draw(ht, hegel.Booleans())
		hValue := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019 ").MinSize(1).MaxSize(6))
		qValue := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019 ").MinSize(1).MaxSize(6))

		hDep := gfast.APIKeyHeader(hName)
		qDep := gfast.APIKeyQuery(qName)
		var hits int
		app := gfast.New()
		app.Get("/k", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
			hits++
			return &struct{ OK bool }{OK: true}, nil
		}, gfast.Require(hDep, qDep))

		hScheme := "apiKey_header_" + hpSanitize(hName)
		qScheme := "apiKey_query_" + hpSanitize(qName)
		spec := hpSpec(ht, app)
		got := spec.security("/k", "get")
		if len(got) != 1 || !sameStringList(got[0][hScheme], nil) || !sameStringList(got[0][qScheme], nil) || len(got[0]) != 2 {
			ht.Fatalf("security %v", got)
		}
		schemes := spec.raw["components"].(map[string]any)["securitySchemes"].(map[string]any)
		hpSchemeEqual(ht, schemes[hScheme], "header", hName)
		hpSchemeEqual(ht, schemes[qScheme], "query", qName)

		header := http.Header{}
		if hPresent {
			value := hValue
			if hEmpty {
				value = ""
			}
			header.Set(hName, value)
		}
		q := url.Values{}
		if qPresent {
			value := qValue
			if qEmpty {
				value = ""
			}
			q.Set(qName, value)
		}
		target := "/k"
		if encoded := q.Encode(); encoded != "" {
			target += "?" + encoded
		}
		res := app.Request(http.MethodGet, target, nil, header)
		switch {
		case !hPresent || hEmpty:
			hpProblem(ht, res, http.StatusUnauthorized, "missing api key")
			hpChallenge(ht, res, hName)
			if hits != 0 {
				ht.Fatal("handler ran")
			}
		case !qPresent || qEmpty:
			hpProblem(ht, res, http.StatusUnauthorized, "missing api key")
			hpChallenge(ht, res, "apiKey")
			if hits != 0 {
				ht.Fatal("handler ran")
			}
		default:
			if res.Status != http.StatusOK || hits != 1 {
				ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
			}
		}
		if flipped := hpFlip(qName); flipped != qName && hPresent && !hEmpty {
			badQ := url.Values{}
			badQ.Set(flipped, qValue)
			bad := app.Request(http.MethodGet, "/k?"+badQ.Encode(), nil, http.Header{hName: []string{hValue}})
			hpProblem(ht, bad, http.StatusUnauthorized, "missing api key")
			hpChallenge(ht, bad, "apiKey")
		}
	})
}

func hpSchemeEqual(ht *hegel.T, raw any, loc, name string) {
	ht.Helper()
	scheme := raw.(map[string]any)
	if scheme["type"] != "apiKey" || scheme["in"] != loc || scheme["name"] != name || scheme["description"] != "API key." {
		ht.Fatalf("scheme %#v", scheme)
	}
}

func TestPropCORS(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		mode := hegel.Draw(ht, hegel.Integers(0, 3))
		drawn := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abcdefghijklmnopqrstuvwxyz0123456789.-:").MinSize(1).MaxSize(16)).MaxSize(4))
		choice := hegel.Draw(ht, hegel.Integers(0, 2))
		method := hegel.Draw(ht, hegel.SampledFrom([]string{http.MethodGet, http.MethodPost, http.MethodOptions, http.MethodDelete}))
		known := hegel.Draw(ht, hegel.Booleans())

		var origins []string
		switch mode {
		case 1:
			origins = drawn
		case 2:
			origins = append(append([]string{}, drawn...), "*")
		case 3:
			origins = nil
		}
		origin := ""
		switch choice {
		case 1:
			origin = "https://stranger.test"
		case 2:
			if len(drawn) == 0 {
				origin = "https://stranger.test"
			} else {
				origin = drawn[hegel.Draw(ht, hegel.Integers(0, len(drawn)-1))]
			}
		}

		var opts []gfast.Option
		if mode != 0 {
			opts = append(opts, gfast.CORS(origins...))
		}
		var hits int
		app := gfast.New(opts...)
		app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
			hits++
			return &struct{ OK bool }{OK: true}, nil
		})

		path := "/missing"
		if known {
			path = "/ping"
		}
		header := http.Header{}
		if origin != "" {
			header.Set("Origin", origin)
		}
		res := app.Request(method, path, nil, header)

		allowed := map[string]struct{}{}
		star := false
		corsOn := mode != 0
		if corsOn {
			star = len(origins) == 0
			for _, item := range origins {
				if item == "*" {
					star = true
				}
				allowed[item] = struct{}{}
			}
		}
		_, listed := allowed[origin]
		match := corsOn && origin != "" && (star || listed)
		var want int
		wantHits := 0
		switch {
		case corsOn && method == http.MethodOptions:
			want = http.StatusNoContent
		case known && method == http.MethodGet:
			want = http.StatusOK
			wantHits = 1
		case known:
			want = http.StatusMethodNotAllowed
		default:
			want = http.StatusNotFound
		}
		if res.Status != want || hits != wantHits {
			ht.Fatalf("status %d hits %d want %d/%d body %s", res.Status, hits, want, wantHits, res.Body)
		}
		if match {
			if res.Header.Get("Access-Control-Allow-Origin") != origin || res.Header.Get("Vary") != "Origin" {
				ht.Fatalf("origin %q vary %q", res.Header.Get("Access-Control-Allow-Origin"), res.Header.Get("Vary"))
			}
			if res.Header.Get("Access-Control-Allow-Methods") != "GET, POST, PUT, PATCH, DELETE, OPTIONS" {
				ht.Fatalf("methods %q", res.Header.Get("Access-Control-Allow-Methods"))
			}
			if res.Header.Get("Access-Control-Allow-Headers") != "Authorization, Content-Type, Accept" {
				ht.Fatalf("headers %q", res.Header.Get("Access-Control-Allow-Headers"))
			}
		} else if res.Header.Get("Access-Control-Allow-Origin") != "" || res.Header.Get("Vary") != "" {
			ht.Fatalf("cors leaked origin %q vary %q", res.Header.Get("Access-Control-Allow-Origin"), res.Header.Get("Vary"))
		}
		if want == http.StatusNoContent && len(bytes.TrimSpace(res.Body)) != 0 {
			ht.Fatalf("options body %s", res.Body)
		}
		if want == http.StatusOK {
			var got struct{ OK bool }
			if err := res.JSON(&got); err != nil || !got.OK {
				ht.Fatalf("ping %#v err %v", got, err)
			}
		}
	})
}

type hpHTTPError struct {
	status int
	detail string
	header http.Header
}

func (e *hpHTTPError) Error() string        { return e.detail }
func (e *hpHTTPError) GetStatus() int       { return e.status }
func (e *hpHTTPError) Headers() http.Header { return e.header }

func TestPropStatusAndErrors(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		mode := hegel.Draw(ht, hegel.Integers(0, 4))
		useStatus := hegel.Draw(ht, hegel.Booleans())
		success := hegel.Draw(ht, hegel.Integers(200, 599))
		errCode := hegel.Draw(ht, hegel.Integers(200, 599))
		n := hegel.Draw(ht, hegel.Integers(-20, 20))
		ok := hegel.Draw(ht, hegel.Booleans())
		detail := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ ").MaxSize(12))
		mark := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		secret := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		name := "X-" + hegel.Draw(ht, hegel.Text().Alphabet("Abcdefgh").MinSize(1).MaxSize(6))
		values := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abcXYZ019 ").MinSize(1).MaxSize(6)).MinSize(1).MaxSize(3))
		setType := hegel.Draw(ht, hegel.Booleans())

		hdr := http.Header{}
		for _, value := range values {
			hdr.Add(name, value)
		}
		if setType {
			hdr.Set("Content-Type", "text/plain")
		}
		inner := &hpHTTPError{status: errCode, detail: detail, header: hdr}
		wrapped := fmt.Errorf("zz-mark:%s: %w", mark, inner)

		var opts []gfast.Option
		documented := 200
		if useStatus {
			opts = append(opts, gfast.Status(success))
			documented = success
		}
		app := gfast.New()
		app.Get("/s", func(ctx context.Context, in *struct{}) (*struct {
			N  int  `json:"n"`
			OK bool `json:"ok"`
		}, error) {
			switch mode {
			case 0:
				return nil, nil
			case 1:
				return &struct {
					N  int  `json:"n"`
					OK bool `json:"ok"`
				}{N: n, OK: ok}, nil
			case 2:
				return nil, inner
			case 3:
				return nil, wrapped
			default:
				return nil, errors.New("zz-secret:" + secret)
			}
		}, opts...)

		res := app.Request(http.MethodGet, "/s", nil)
		switch mode {
		case 0:
			if res.Status != http.StatusNoContent || len(res.Body) != 0 || res.Header.Get("Content-Type") != "" {
				ht.Fatalf("nil result status %d type %q body %s", res.Status, res.Header.Get("Content-Type"), res.Body)
			}
		case 1:
			if res.Status != documented || res.Header.Get("Content-Type") != "application/json" {
				ht.Fatalf("success status %d type %q body %s", res.Status, res.Header.Get("Content-Type"), res.Body)
			}
			var got struct {
				N  int  `json:"n"`
				OK bool `json:"ok"`
			}
			if err := res.JSON(&got); err != nil {
				ht.Fatal(err)
			}
			if got.N != n || got.OK != ok {
				ht.Fatalf("got %+v", got)
			}
		case 2, 3:
			wantDetail := detail
			if mode == 3 {
				wantDetail = wrapped.Error()
			}
			hpProblem(ht, res, errCode, wantDetail)
			got := res.Header.Values(http.CanonicalHeaderKey(name))
			if !reflect.DeepEqual(got, values) {
				ht.Fatalf("header %v want %v", got, values)
			}
			if ct := res.Header.Get("Content-Type"); ct != "application/problem+json" {
				ht.Fatalf("content type %s", ct)
			}
		default:
			hpProblem(ht, res, http.StatusInternalServerError, "unexpected error occurred")
			if strings.Contains(string(res.Body), "zz-secret:") {
				ht.Fatalf("secret leaked: %s", res.Body)
			}
		}

		spec := hpSpec(ht, app)
		op := spec.op("/s", "get")
		if _, ok := op.Responses[strconv.Itoa(documented)]; !ok {
			ht.Fatalf("responses %#v want %d", op.Responses, documented)
		}
		schema := op.Responses[strconv.Itoa(documented)].Content["application/json"].Schema
		if schema.Type != "object" || schema.Properties["n"].Type != "integer" || schema.Properties["ok"].Type != "boolean" {
			ht.Fatalf("schema %#v", schema)
		}
		if !reflect.DeepEqual(schema.Required, []string{"n", "ok"}) {
			ht.Fatalf("required %v", schema.Required)
		}
	})
}

type hpSchema struct {
	Title string `json:"title" minLength:"2" maxLength:"5"`
	N     int    `json:"n"`
	OK    bool   `json:"ok"`
	Xs    []int  `json:"xs"`
	Skip  string `json:"-"`
}

func TestPropOpenAPIRoutingAndDocs(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		segText := hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(6)
		segG := hegel.Draw(ht, segText)
		segP := hegel.Draw(ht, segText)
		gSlash := hegel.Draw(ht, hegel.Booleans())
		pSlash := hegel.Draw(ht, hegel.Booleans())
		methodIndex := hegel.Draw(ht, hegel.Integers(0, 4))
		methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
		method := methods[methodIndex]
		other := methods[(methodIndex+1)%len(methods)]
		id := hegel.Draw(ht, hegel.Integers(0, 999))
		q := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301XYZ019").MaxSize(8))
		summary := hegel.Draw(ht, hegel.Text().Alphabet("abc ").MaxSize(12))
		description := hegel.Draw(ht, hegel.Text().Alphabet("abc ").MaxSize(12))

		tagText := hegel.Text().Alphabet("abc").MinSize(1).MaxSize(3)
		tagList := hegel.Lists(tagText).MaxSize(3)
		parentSet := hegel.Draw(ht, hegel.Booleans())
		childSet := hegel.Draw(ht, hegel.Booleans())
		routeSet := hegel.Draw(ht, hegel.Booleans())
		parentTags := hegel.Draw(ht, tagList)
		childTags := hegel.Draw(ht, tagList)
		routeTags := hegel.Draw(ht, tagList)
		scopeText := hegel.Text().Alphabet("abc:").MinSize(1).MaxSize(6)
		scopeList := hegel.Lists(scopeText).MaxSize(3)
		parentScopeSet := hegel.Draw(ht, hegel.Booleans())
		childScopeSet := hegel.Draw(ht, hegel.Booleans())
		routeScopeSet := hegel.Draw(ht, hegel.Booleans())
		parentScopes := hegel.Draw(ht, scopeList)
		childScopes := hegel.Draw(ht, scopeList)
		routeScopes := hegel.Draw(ht, scopeList)

		useInfo := hegel.Draw(ht, hegel.Booleans())
		infoText := hegel.Text().Alphabet("ab&<>\"' ").MaxSize(12)
		title1 := hegel.Draw(ht, infoText)
		title2 := hegel.Draw(ht, infoText)
		version1 := hegel.Draw(ht, infoText)
		version2 := hegel.Draw(ht, infoText)
		outTitle := hegel.Draw(ht, hegel.Text().Alphabet("ab👍").MaxSize(8))
		outN := hegel.Draw(ht, hegel.Integers(-5, 5))
		outOK := hegel.Draw(ht, hegel.Booleans())
		outXs := hegel.Draw(ht, hegel.Lists(hegel.Integers(-3, 3)).MaxSize(3))

		var info []gfast.Option
		wantTitle, wantVersion := "API", "0.0.0"
		if useInfo {
			info = []gfast.Option{gfast.Title(title1), gfast.Version(version1), gfast.Title(title2), gfast.Version(version2)}
			wantTitle, wantVersion = title2, version2
		}
		app := gfast.New(info...)

		prefix := "/g" + segG
		if gSlash {
			prefix += "/"
		}
		routePath := segP + "/{id}"
		if pSlash {
			routePath = "/" + routePath
		}
		full := hpJoin(prefix, routePath)
		var hits int
		group := app.Group(prefix)
		hpMount(group, method, routePath, func(ctx context.Context, in *struct {
			ID int    `path:"id"`
			Q  string `query:"q"`
			H  string `header:"X-Hegel"`
			C  string `cookie:"sid"`
		}) (*struct {
			ID int    `json:"id"`
			Q  string `json:"q"`
		}, error) {
			hits++
			return &struct {
				ID int    `json:"id"`
				Q  string `json:"q"`
			}{ID: in.ID, Q: in.Q}, nil
		}, gfast.Summary(summary), gfast.Description(description))

		tags := pickStrings(nil, parentSet, parentTags)
		tags = pickStrings(tags, childSet, childTags)
		tags = pickStrings(tags, routeSet, routeTags)
		var parentOpts []gfast.Option
		if parentSet {
			parentOpts = append(parentOpts, gfast.Tags(parentTags...))
		}
		parent := app.Group("/p", parentOpts...)
		var childOpts []gfast.Option
		if childSet {
			childOpts = append(childOpts, gfast.Tags(childTags...))
		}
		child := parent.Group("/c", childOpts...)
		var routeOpts []gfast.Option
		if routeSet {
			routeOpts = append(routeOpts, gfast.Tags(routeTags...))
		}
		gfast.Get(child, "/r", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
			return &struct{ OK bool }{OK: true}, nil
		}, routeOpts...)

		scopes := pickStrings(nil, parentScopeSet, parentScopes)
		scopes = pickStrings(scopes, childScopeSet, childScopes)
		scopes = pickStrings(scopes, routeScopeSet, routeScopes)
		var direct []gfast.Option
		if parentScopeSet {
			direct = append(direct, gfast.Scopes(parentScopes...))
		}
		if childScopeSet {
			direct = append(direct, gfast.Scopes(childScopes...))
		}
		if routeScopeSet {
			direct = append(direct, gfast.Scopes(routeScopes...))
		}
		app.Get("/auth/{id}", func(ctx context.Context, in *struct {
			ID   string      `path:"id"`
			User hpPrincipal `gfast:"dep=hpUser"`
			Body hpTitle
		}) (*hpTitle, error) {
			return &in.Body, nil
		}, direct...)

		app.Get("/schema", func(ctx context.Context, in *struct{}) (*hpSchema, error) {
			return &hpSchema{Title: outTitle, N: outN, OK: outOK, Xs: outXs, Skip: "zz-hidden"}, nil
		})

		concrete := strings.Replace(full, "{id}", strconv.Itoa(id), 1)
		query := url.Values{"q": {q}}.Encode()
		okRes := app.Request(method, concrete+"?"+query, nil)
		if okRes.Status != http.StatusOK || hits != 1 {
			ht.Fatalf("mounted %s %d hits %d body %s", concrete, okRes.Status, hits, okRes.Body)
		}
		var echoed struct {
			ID int    `json:"id"`
			Q  string `json:"q"`
		}
		if err := okRes.JSON(&echoed); err != nil {
			ht.Fatal(err)
		}
		if echoed.ID != id || echoed.Q != q {
			ht.Fatalf("echo %+v id %d q %q", echoed, id, q)
		}
		badPath := "/g" + segG + "//" + segP + "/" + strconv.Itoa(id) + "?" + query
		bad := app.Request(method, badPath, nil)
		if bad.Status != http.StatusTemporaryRedirect || hits != 1 {
			ht.Fatalf("double slash status %d hits %d location %q", bad.Status, hits, bad.Header.Get("Location"))
		}
		loc, err := url.Parse(bad.Header.Get("Location"))
		if err != nil {
			ht.Fatal(err)
		}
		if loc.Path != concrete || loc.RawQuery != query {
			ht.Fatalf("location %q want %s?%s", bad.Header.Get("Location"), concrete, query)
		}
		wrong := app.Request(other, concrete, nil)
		if wrong.Status != http.StatusMethodNotAllowed || hits != 1 || !strings.Contains(wrong.Header.Get("Allow"), method) {
			ht.Fatalf("method %d allow %q", wrong.Status, wrong.Header.Get("Allow"))
		}

		tagsRes := app.Request(http.MethodGet, "/p/c/r", nil)
		if tagsRes.Status != http.StatusOK {
			ht.Fatalf("tags route %d", tagsRes.Status)
		}
		schemaRes := app.Request(http.MethodGet, "/schema", nil)
		if schemaRes.Status != http.StatusOK || strings.Contains(string(schemaRes.Body), "zz-hidden") {
			ht.Fatalf("schema status %d body %s", schemaRes.Status, schemaRes.Body)
		}
		var gotSchema hpSchema
		if err := schemaRes.JSON(&gotSchema); err != nil {
			ht.Fatal(err)
		}
		if gotSchema.Title != outTitle || gotSchema.N != outN || gotSchema.OK != outOK || !sameInts(gotSchema.Xs, outXs) || gotSchema.Skip != "" {
			ht.Fatalf("schema body %+v", gotSchema)
		}

		spec := hpSpec(ht, app)
		if spec.doc.OpenAPI != "3.1.0" || spec.doc.Info.Title != wantTitle || spec.doc.Info.Version != wantVersion {
			ht.Fatalf("info %+v", spec.doc.Info)
		}
		op := spec.op(full, strings.ToLower(method))
		if op.OperationID != hpOpID(method, full) || op.Summary != summary || op.Description != description {
			ht.Fatalf("op id %q summary %q description %q", op.OperationID, op.Summary, op.Description)
		}
		if len(op.Parameters) != 4 {
			ht.Fatalf("parameters %#v", op.Parameters)
		}
		for i, want := range []struct {
			name, in, typ string
			required      bool
		}{
			{"id", "path", "integer", true},
			{"q", "query", "string", false},
			{"X-Hegel", "header", "string", false},
			{"sid", "cookie", "string", false},
		} {
			p := op.Parameters[i]
			if p.Name != want.name || p.In != want.in || p.Required != want.required || p.Schema.Type != want.typ {
				ht.Fatalf("param %#v", p)
			}
		}
		resp := op.Responses["200"]
		if resp.Description != "Success" || resp.Content["application/json"].Schema.Properties["id"].Type != "integer" || resp.Content["application/json"].Schema.Properties["q"].Type != "string" {
			ht.Fatalf("response %#v", resp)
		}

		tagOp := spec.op("/p/c/r", "get")
		if tagOp.OperationID != "get-p-c-r" || !sameStringList(tagOp.Tags, tags) || tagOp.Security != nil {
			ht.Fatalf("tags op %#v want %v", tagOp, tags)
		}

		auth := spec.op("/auth/{id}", "get")
		if auth.Security == nil || !sameStringList((*auth.Security)[0]["bearerAuth"], scopes) {
			ht.Fatalf("auth security %v want %v", auth.Security, scopes)
		}
		if len(auth.Parameters) != 1 || auth.Parameters[0].Name != "id" {
			ht.Fatalf("auth params %#v", auth.Parameters)
		}
		bodySchema := spec.expand(auth.RequestBody.Content["application/json"].Schema)
		if !auth.RequestBody.Required || bodySchema.Properties["title"].Type != "string" || !intPtrIs(bodySchema.Properties["title"].MinLength, 2) || !intPtrIs(bodySchema.Properties["title"].MaxLength, 5) {
			ht.Fatalf("body schema %#v", bodySchema)
		}
		if _, ok := bodySchema.Properties["User"]; ok {
			ht.Fatal("dep field documented on the body")
		}
		outSchema := spec.expand(auth.Responses["200"].Content["application/json"].Schema)
		if !intPtrIs(outSchema.Properties["title"].MinLength, 2) {
			ht.Fatalf("response schema %#v", outSchema)
		}
		bearer := spec.doc.Components.SecuritySchemes["bearerAuth"]
		if bearer.Type != "http" || bearer.Scheme != "bearer" || bearer.Description != "Bearer token in the Authorization header." {
			ht.Fatalf("bearer %#v", bearer)
		}

		schemaOp := spec.op("/schema", "get")
		sch := spec.expand(schemaOp.Responses["200"].Content["application/json"].Schema)
		if sch.Properties["title"].Type != "string" || sch.Properties["n"].Type != "integer" || sch.Properties["ok"].Type != "boolean" || sch.Properties["xs"].Type != "array" || sch.Properties["xs"].Items.Type != "integer" {
			ht.Fatalf("schema %#v", sch)
		}
		if _, ok := sch.Properties["Skip"]; ok || !intPtrIs(sch.Properties["title"].MinLength, 2) || !intPtrIs(sch.Properties["title"].MaxLength, 5) {
			ht.Fatalf("schema bounds %#v", sch)
		}
		if !reflect.DeepEqual(sch.Required, []string{"title", "n", "ok", "xs"}) {
			ht.Fatalf("required %v", sch.Required)
		}

		docs := app.Request(http.MethodGet, "/docs", nil)
		if docs.Status != http.StatusOK || !strings.Contains(docs.Header.Get("Content-Type"), "text/html") {
			ht.Fatalf("docs %d %s", docs.Status, docs.Header.Get("Content-Type"))
		}
		wantTag := "<title>" + hpHTML(wantTitle) + "</title>"
		if !strings.Contains(string(docs.Body), wantTag) {
			ht.Fatalf("docs title missing %q", wantTag)
		}
	})
}

func TestPropBackgroundAndClosers(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		hpReset()
		tasks := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abc").MinSize(1).MaxSize(4)).MaxSize(5))
		mode := hegel.Draw(ht, hegel.Integers(0, 2))
		secret := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(4))

		app := gfast.New()
		app.Post("/work", func(ctx context.Context, in *struct {
			B *hpBox `gfast:"dep=hpBoxB"`
		}) (*struct{ OK bool }, error) {
			if in.B == nil || in.B.Name != "B" {
				ht.Fatalf("box %#v", in.B)
			}
			gfast.Background(ctx, nil)
			for _, task := range tasks {
				task := task
				gfast.Background(ctx, func() { hpEvents = append(hpEvents, task) })
			}
			switch mode {
			case 1:
				return nil, nil
			case 2:
				return nil, errors.New("zz-secret:" + secret)
			default:
				return &struct{ OK bool }{OK: true}, nil
			}
		}, gfast.Require(hpBoxA))

		var want []string
		want = append(want, tasks...)
		want = append(want, "close-B", "close-A")
		for i := 0; i < 2; i++ {
			before := len(hpEvents)
			res := app.Request(http.MethodPost, "/work", nil)
			switch mode {
			case 1:
				if res.Status != http.StatusNoContent || len(res.Body) != 0 {
					ht.Fatalf("nil %d %s", res.Status, res.Body)
				}
			case 2:
				hpProblem(ht, res, http.StatusInternalServerError, "unexpected error occurred")
				if strings.Contains(string(res.Body), "zz-secret:") || strings.Contains(string(res.Body), "close ") {
					ht.Fatalf("body leaked %s", res.Body)
				}
			default:
				if res.Status != http.StatusOK {
					ht.Fatalf("status %d %s", res.Status, res.Body)
				}
			}
			if !reflect.DeepEqual(hpEvents[before:], want) {
				ht.Fatalf("events %v want %v", hpEvents[before:], want)
			}
		}
		if hpBoxACalls.Load() != 2 || hpBoxBCalls.Load() != 2 {
			ht.Fatalf("calls A %d B %d", hpBoxACalls.Load(), hpBoxBCalls.Load())
		}
	})
}

func TestPropStartStopHooks(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		nStart := hegel.Draw(ht, hegel.Integers(0, 4))
		failAt := -1
		if nStart > 0 {
			failAt = hegel.Draw(ht, hegel.Integers(-1, nStart-1))
		}
		nStop := hegel.Draw(ht, hegel.Integers(0, 4))
		stopFail := hegel.Draw(ht, hegel.Lists(hegel.Booleans()).MinSize(nStop).MaxSize(nStop))

		var ran []string
		var opts []gfast.Option
		for i := 0; i < nStart; i++ {
			i := i
			opts = append(opts, gfast.OnStart(func(ctx context.Context) error {
				ran = append(ran, fmt.Sprintf("start-%d", i))
				if i == failAt {
					return errors.New(fmt.Sprintf("start-fail-%d", i))
				}
				return nil
			}))
		}
		for i := 0; i < nStop; i++ {
			i := i
			opts = append(opts, gfast.OnStop(func(ctx context.Context) error {
				ran = append(ran, fmt.Sprintf("stop-%d", i))
				if stopFail[i] {
					return errors.New(fmt.Sprintf("stop-fail-%d", i))
				}
				return nil
			}))
		}
		app := gfast.New(opts...)
		err := hpServeClosed(ht, app)
		if failAt >= 0 {
			var want []string
			for i := 0; i <= failAt; i++ {
				want = append(want, fmt.Sprintf("start-%d", i))
			}
			if !reflect.DeepEqual(ran, want) || err == nil || !strings.Contains(err.Error(), fmt.Sprintf("start-fail-%d", failAt)) {
				ht.Fatalf("ran %v err %v", ran, err)
			}
		} else {
			var want []string
			for i := 0; i < nStart; i++ {
				want = append(want, fmt.Sprintf("start-%d", i))
			}
			for i := 0; i < nStop; i++ {
				want = append(want, fmt.Sprintf("stop-%d", i))
			}
			if !reflect.DeepEqual(ran, want) {
				ht.Fatalf("ran %v want %v err %v", ran, want, err)
			}
			if err != nil && strings.Contains(err.Error(), "stop-fail") {
				ht.Fatalf("Serve returned stop error %v", err)
			}
		}
		after := append([]string(nil), ran...)
		err = hpServeClosed(ht, app)
		if err == nil || !strings.Contains(err.Error(), "already started") || !reflect.DeepEqual(ran, after) {
			ht.Fatalf("second err %v ran %v", err, ran)
		}
	})
}

func hpServeClosed(ht *hegel.T, app *gfast.App) error {
	ht.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ht.Fatal(err)
	}
	ln.Close()
	done := make(chan error, 1)
	go func() { done <- app.Serve(ln) }()
	select {
	case err = <-done:
		return err
	case <-time.After(2 * time.Second):
		ht.Fatal("Serve blocked")
		return nil
	}
}

func hpMount[I, O any](r gfast.Router, method, path string, handler func(context.Context, *I) (*O, error), opts ...gfast.Option) {
	switch method {
	case http.MethodGet:
		gfast.Get(r, path, handler, opts...)
	case http.MethodPost:
		gfast.Post(r, path, handler, opts...)
	case http.MethodPut:
		gfast.Put(r, path, handler, opts...)
	case http.MethodPatch:
		gfast.Patch(r, path, handler, opts...)
	case http.MethodDelete:
		gfast.Delete(r, path, handler, opts...)
	default:
		panic(method)
	}
}

func pickStrings(base []string, set bool, next []string) []string {
	if set {
		return next
	}
	return base
}

func sameStringList(got, want []string) bool {
	if len(got) == 0 && len(want) == 0 {
		return true
	}
	return reflect.DeepEqual(got, want)
}

func sameInts(got, want []int) bool {
	if len(got) == 0 && len(want) == 0 {
		return true
	}
	return reflect.DeepEqual(got, want)
}

func intPtrIs(p *int, n int) bool {
	return p != nil && *p == n
}

type hpSpecDoc struct {
	OpenAPI string `json:"openapi"`
	Info    struct {
		Title   string `json:"title"`
		Version string `json:"version"`
	} `json:"info"`
	Paths      map[string]map[string]hpSpecOp `json:"paths"`
	Components *struct {
		SecuritySchemes map[string]struct {
			Type        string `json:"type"`
			Scheme      string `json:"scheme"`
			In          string `json:"in"`
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"securitySchemes"`
	} `json:"components"`
}

type hpSpecOp struct {
	OperationID string                 `json:"operationId"`
	Summary     string                 `json:"summary"`
	Description string                 `json:"description"`
	Tags        []string               `json:"tags"`
	Parameters  []hpSpecParam          `json:"parameters"`
	RequestBody *hpSpecBody            `json:"requestBody"`
	Responses   map[string]hpSpecResp  `json:"responses"`
	Security    *[]map[string][]string `json:"security"`
}

type hpSpecParam struct {
	Name     string `json:"name"`
	In       string `json:"in"`
	Required bool   `json:"required"`
	Schema   struct {
		Type string `json:"type"`
	} `json:"schema"`
}

type hpSpecBody struct {
	Required bool                   `json:"required"`
	Content  map[string]hpSpecMedia `json:"content"`
}

type hpSpecMedia struct {
	Schema hpDocSchema `json:"schema"`
}

type hpSpecResp struct {
	Description string                 `json:"description"`
	Content     map[string]hpSpecMedia `json:"content"`
}

type hpDocSchema struct {
	Ref        string                  `json:"$ref"`
	Type       string                  `json:"type"`
	Properties map[string]*hpDocSchema `json:"properties"`
	Required   []string                `json:"required"`
	Items      *hpDocSchema            `json:"items"`
	MinLength  *int                    `json:"minLength"`
	MaxLength  *int                    `json:"maxLength"`
}

type hpParsed struct {
	doc hpSpecDoc
	raw map[string]any
}

func (p hpParsed) op(path, method string) hpSpecOp {
	return p.doc.Paths[path][method]
}

func (p hpParsed) security(path, method string) []map[string][]string {
	op := p.op(path, method)
	if op.Security == nil {
		return nil
	}
	return *op.Security
}

func (p hpParsed) expand(s hpDocSchema) hpDocSchema {
	name, ok := strings.CutPrefix(s.Ref, "#/components/schemas/")
	if !ok || name == "" || strings.Contains(name, "/") {
		return s
	}
	comps, _ := p.raw["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	raw, _ := schemas[name].(map[string]any)
	if raw == nil {
		return s
	}
	buf, err := json.Marshal(raw)
	if err != nil {
		return s
	}
	var out hpDocSchema
	if err := json.Unmarshal(buf, &out); err != nil {
		return s
	}
	return out
}

func hpSpec(ht *hegel.T, app *gfast.App) hpParsed {
	ht.Helper()
	res := app.Request(http.MethodGet, "/openapi.json", nil)
	if res.Status != http.StatusOK {
		ht.Fatalf("openapi %d %s", res.Status, res.Body)
	}
	var doc hpSpecDoc
	if err := json.Unmarshal(res.Body, &doc); err != nil {
		ht.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(res.Body, &raw); err != nil {
		ht.Fatal(err)
	}
	return hpParsed{doc: doc, raw: raw}
}
