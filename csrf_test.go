package gfast_test

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/pyrex41/gfast"
)

func TestCSRFFetchOriginAndSkip(t *testing.T) {
	app := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}))
	var hits int
	app.Post("/do", func(ctx context.Context, in *struct{}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		hits++
		gfast.SessionFrom(ctx)["user"] = "ada"
		return &struct {
			OK bool `json:"ok"`
		}{OK: true}, nil
	})
	app.Put("/do", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		hits++
		return &struct{}{}, nil
	})
	app.Patch("/do", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		hits++
		return &struct{}{}, nil
	})
	app.Delete("/do", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		hits++
		return &struct{}{}, nil
	})
	app.Get("/do", func(ctx context.Context, in *struct{}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		hits++
		return &struct {
			OK bool `json:"ok"`
		}{OK: true}, nil
	})
	app.Post("/open", func(ctx context.Context, in *struct{}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		hits++
		return &struct {
			OK bool `json:"ok"`
		}{OK: true}, nil
	}, gfast.SkipCSRF())
	open := app.Group("/group", gfast.SkipCSRF())
	open.Post("/open", func(ctx context.Context, in *struct{}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		hits++
		return &struct {
			OK bool `json:"ok"`
		}{OK: true}, nil
	})

	primed := app.Request(http.MethodPost, "/do", nil)
	if primed.Status != http.StatusOK {
		t.Fatalf("prime %d %s", primed.Status, primed.Body)
	}
	cookie := sessionCookie(t, primed)
	hits = 0

	cross := headerCookie(cookie)
	cross.Set("Sec-Fetch-Site", "cross-site")
	denied := app.Request(http.MethodPost, "/do", nil, cross)
	assertCSRF(t, denied)
	if hits != 0 {
		t.Fatalf("cross-site handler ran")
	}
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		res := app.Request(method, "/do", nil, cross)
		assertCSRF(t, res)
	}

	same := headerCookie(cookie)
	same.Set("Origin", "https://example.com")
	same.Set("Referer", "https://evil.test/from")
	if res := app.Request(http.MethodPost, "/do", nil, same); res.Status != http.StatusOK {
		t.Fatalf("same-origin %d %s", res.Status, res.Body)
	}
	referer := headerCookie(cookie)
	referer.Set("Referer", "https://example.com/page?q=1")
	if res := app.Request(http.MethodPost, "/do", nil, referer); res.Status != http.StatusOK {
		t.Fatalf("referer %d %s", res.Status, res.Body)
	}
	badOrigin := headerCookie(cookie)
	badOrigin.Set("Origin", "https://evil.test")
	assertCSRF(t, app.Request(http.MethodPost, "/do", nil, badOrigin))
	badRef := headerCookie(cookie)
	badRef.Set("Referer", "https://evil.test/x")
	assertCSRF(t, app.Request(http.MethodPost, "/do", nil, badRef))

	if res := app.Request(http.MethodPost, "/do", nil, headerCookie(cookie)); res.Status != http.StatusOK {
		t.Fatalf("curl %d %s", res.Status, res.Body)
	}
	fetchSame := headerCookie(cookie)
	fetchSame.Set("Sec-Fetch-Site", "same-origin")
	fetchSame.Set("Origin", "https://evil.test")
	if res := app.Request(http.MethodPost, "/do", nil, fetchSame); res.Status != http.StatusOK {
		t.Fatalf("fetch same-origin %d %s", res.Status, res.Body)
	}
	sameSite := headerCookie(cookie)
	sameSite.Set("Sec-Fetch-Site", "same-site")
	if res := app.Request(http.MethodPost, "/do", nil, sameSite); res.Status != http.StatusOK {
		t.Fatalf("same-site %d %s", res.Status, res.Body)
	}
	if res := app.Request(http.MethodGet, "/do", nil, cross); res.Status != http.StatusOK {
		t.Fatalf("get %d %s", res.Status, res.Body)
	}

	if res := app.Request(http.MethodPost, "/open", nil, cross); res.Status != http.StatusOK {
		t.Fatalf("skip %d %s", res.Status, res.Body)
	}
	if res := app.Request(http.MethodPost, "/group/open", nil, cross); res.Status != http.StatusOK {
		t.Fatalf("group skip %d %s", res.Status, res.Body)
	}

	bearer := http.Header{"Authorization": []string{"Bearer token"}, "Sec-Fetch-Site": []string{"cross-site"}}
	if res := app.Request(http.MethodPost, "/do", nil, bearer); res.Status != http.StatusOK {
		t.Fatalf("bearer %d %s", res.Status, res.Body)
	}
	bearer.Set("Cookie", "session="+cookie)
	assertCSRF(t, app.Request(http.MethodPost, "/do", nil, bearer))

	off := gfast.New()
	off.Post("/do", func(ctx context.Context, in *struct{}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		return &struct {
			OK bool `json:"ok"`
		}{OK: true}, nil
	})
	if res := off.Request(http.MethodPost, "/do", nil, cross); res.Status != http.StatusOK {
		t.Fatalf("sessions off %d %s", res.Status, res.Body)
	}

	none := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}), gfast.NoCSRF())
	none.Post("/do", func(ctx context.Context, in *struct{}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		return &struct {
			OK bool `json:"ok"`
		}{OK: true}, nil
	})
	if res := none.Request(http.MethodPost, "/do", nil, cross); res.Status != http.StatusOK {
		t.Fatalf("no csrf %d %s", res.Status, res.Body)
	}

	listed := gfast.New(
		gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}),
		gfast.CSRFOrigins("https://Files.Example"),
	)
	listed.Post("/do", func(ctx context.Context, in *struct{}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		return &struct {
			OK bool `json:"ok"`
		}{OK: true}, nil
	})
	allowed := headerCookie(cookie)
	allowed.Set("Origin", "https://files.example")
	if res := listed.Request(http.MethodPost, "/do", nil, allowed); res.Status != http.StatusOK {
		t.Fatalf("listed origin %d %s", res.Status, res.Body)
	}
	other := headerCookie(cookie)
	other.Set("Origin", "https://other.example")
	assertCSRF(t, listed.Request(http.MethodPost, "/do", nil, other))
}

func TestCSRFStrict(t *testing.T) {
	app := gfast.New(
		gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}),
		gfast.CSRFStrict(),
	)
	app.Post("/do", func(ctx context.Context, in *struct{}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		gfast.SessionFrom(ctx)["user"] = "ada"
		return &struct {
			OK bool `json:"ok"`
		}{OK: true}, nil
	})
	primed := app.Request(http.MethodPost, "/do", nil)
	cookie := sessionCookie(t, primed)

	sameSite := headerCookie(cookie)
	sameSite.Set("Sec-Fetch-Site", "same-site")
	assertCSRF(t, app.Request(http.MethodPost, "/do", nil, sameSite))

	cross := headerCookie(cookie)
	cross.Set("Sec-Fetch-Site", "cross-site")
	assertCSRF(t, app.Request(http.MethodPost, "/do", nil, cross))

	same := headerCookie(cookie)
	same.Set("Sec-Fetch-Site", "same-origin")
	if res := app.Request(http.MethodPost, "/do", nil, same); res.Status != http.StatusOK {
		t.Fatalf("same-origin %d %s", res.Status, res.Body)
	}
	if res := app.Request(http.MethodPost, "/do", nil, headerCookie(cookie)); res.Status != http.StatusOK {
		t.Fatalf("curl %d %s", res.Status, res.Body)
	}
}

func TestCSRFToken(t *testing.T) {
	app := gfast.New(
		gfast.Sessions(gfast.SessionConfig{Secret: "test-secret", Secure: true}),
		gfast.CSRFToken(),
		gfast.CSRFStrict(),
	)
	app.Get("/token", func(ctx context.Context, in *struct{}) (*struct {
		Token string `json:"token"`
	}, error) {
		return &struct {
			Token string `json:"token"`
		}{Token: gfast.CSRFTokenFrom(ctx)}, nil
	})
	app.Post("/do", func(ctx context.Context, in *struct{}) (*struct {
		Token string `json:"token"`
	}, error) {
		return &struct {
			Token string `json:"token"`
		}{Token: gfast.CSRFTokenFrom(ctx)}, nil
	})
	app.Post("/open", func(ctx context.Context, in *struct{}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		return &struct {
			OK bool `json:"ok"`
		}{OK: true}, nil
	}, gfast.SkipCSRF())
	app.Post("/clear", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		sess := gfast.SessionFrom(ctx)
		for key := range sess {
			delete(sess, key)
		}
		return nil, nil
	})

	first := app.Request(http.MethodGet, "/token", nil)
	if first.Status != http.StatusOK {
		t.Fatalf("token status %d %s", first.Status, first.Body)
	}
	var body struct {
		Token string `json:"token"`
	}
	if first.JSON(&body) != nil || body.Token == "" {
		t.Fatalf("token body %s", first.Body)
	}
	session, csrf := splitSessionCookies(t, first)
	if csrf.Value != body.Token || csrf.HttpOnly || !csrf.Secure || csrf.Path != "/" || csrf.Name != "csrf_token" {
		t.Fatalf("csrf cookie %+v", csrf)
	}
	if session.Name != "session" || !session.HttpOnly || session.Value == "" {
		t.Fatalf("session cookie %+v", session)
	}
	again := app.Request(http.MethodGet, "/token", nil, http.Header{
		"Cookie": []string{"session=" + session.Value + "; csrf_token=" + csrf.Value},
	})
	body = struct {
		Token string `json:"token"`
	}{}
	if again.Status != http.StatusOK || again.JSON(&body) != nil || body.Token != csrf.Value {
		t.Fatalf("again %d %s", again.Status, again.Body)
	}
	if again.Header.Get("Set-Cookie") != "" {
		t.Fatalf("unchanged set-cookie %q", again.Header.Get("Set-Cookie"))
	}

	cookie := "session=" + session.Value
	missing := http.Header{"Cookie": []string{cookie}, "Origin": []string{"https://example.com"}}
	assertCSRF(t, app.Request(http.MethodPost, "/do", nil, missing))
	wrong := missing.Clone()
	wrong.Set("X-CSRF-Token", "not-the-token")
	assertCSRF(t, app.Request(http.MethodPost, "/do", nil, wrong))

	okHeader := missing.Clone()
	okHeader.Set("X-CSRF-Token", body.Token)
	accepted := app.Request(http.MethodPost, "/do", nil, okHeader)
	body = struct {
		Token string `json:"token"`
	}{}
	if accepted.Status != http.StatusOK || accepted.JSON(&body) != nil || body.Token != csrf.Value {
		t.Fatalf("accepted %d %s", accepted.Status, accepted.Body)
	}

	form := url.Values{"csrf_token": {csrf.Value}}
	formHeader := http.Header{
		"Cookie":       []string{cookie},
		"Content-Type": []string{"application/x-www-form-urlencoded"},
	}
	posted := app.Request(http.MethodPost, "/do", []byte(form.Encode()), formHeader)
	if posted.Status != http.StatusOK {
		t.Fatalf("form %d %s", posted.Status, posted.Body)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("csrf_token", csrf.Value); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	multi := http.Header{
		"Cookie":       []string{cookie},
		"Content-Type": []string{mw.FormDataContentType()},
	}
	if res := app.Request(http.MethodPost, "/do", buf.Bytes(), multi); res.Status != http.StatusOK {
		t.Fatalf("multipart %d %s", res.Status, res.Body)
	}

	cross := http.Header{
		"Cookie":         []string{cookie},
		"Sec-Fetch-Site": []string{"cross-site"},
		"X-CSRF-Token":   []string{csrf.Value},
	}
	assertCSRF(t, app.Request(http.MethodPost, "/do", nil, cross))
	sameSite := http.Header{
		"Cookie":         []string{cookie},
		"Sec-Fetch-Site": []string{"same-site"},
		"X-CSRF-Token":   []string{csrf.Value},
	}
	assertCSRF(t, app.Request(http.MethodPost, "/do", nil, sameSite))
	if res := app.Request(http.MethodPost, "/open", nil, cross); res.Status != http.StatusOK {
		t.Fatalf("skip token %d %s", res.Status, res.Body)
	}

	cleared := app.Request(http.MethodPost, "/clear", nil, okHeader)
	if cleared.Status != http.StatusNoContent {
		t.Fatalf("clear %d %s", cleared.Status, cleared.Body)
	}
	gone := map[string]*http.Cookie{}
	for _, c := range (&http.Response{Header: cleared.Header}).Cookies() {
		gone[c.Name] = c
	}
	if gone["session"] == nil || gone["session"].MaxAge >= 0 || gone["csrf_token"] == nil || gone["csrf_token"].MaxAge >= 0 {
		t.Fatalf("clear cookies %+v", gone)
	}
}

func TestCSRFOptionRejects(t *testing.T) {
	mustPanic(t, "origin", func() {
		gfast.New(gfast.CSRFOrigins())
	})
	mustPanic(t, "origin", func() {
		gfast.New(gfast.CSRFOrigins("http://"))
	})
}

func headerCookie(session string) http.Header {
	return http.Header{"Cookie": []string{"session=" + session}}
}

func sessionCookie(t *testing.T, res *gfast.Result) string {
	t.Helper()
	for _, c := range (&http.Response{Header: res.Header}).Cookies() {
		if c.Name == "session" && c.Value != "" {
			return c.Value
		}
	}
	t.Fatalf("session cookie %v", res.Header)
	return ""
}

func splitSessionCookies(t *testing.T, res *gfast.Result) (session, csrf *http.Cookie) {
	t.Helper()
	for _, c := range (&http.Response{Header: res.Header}).Cookies() {
		switch c.Name {
		case "session":
			session = c
		case "csrf_token":
			csrf = c
		}
	}
	if session == nil || csrf == nil {
		t.Fatalf("cookies %v", res.Header)
	}
	return session, csrf
}

func assertCSRF(t *testing.T, res *gfast.Result) {
	t.Helper()
	if res.Status != http.StatusForbidden || res.Header.Get("Content-Type") != "application/problem+json" || !strings.Contains(string(res.Body), "csrf check failed") {
		t.Fatalf("csrf %d type %q body %s", res.Status, res.Header.Get("Content-Type"), res.Body)
	}
}
