package gfast_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/pyrex41/gfast"
)

func TestSessionRoundTripAndTamper(t *testing.T) {
	app := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}))
	app.Post("/set", func(ctx context.Context, in *struct {
		V string `query:"v"`
	}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		gfast.SessionFrom(ctx)["user"] = in.V
		return &struct {
			OK bool `json:"ok"`
		}{OK: true}, nil
	})
	app.Get("/get", func(ctx context.Context, in *struct{}) (*struct {
		User string `json:"user"`
	}, error) {
		user, _ := gfast.SessionFrom(ctx)["user"].(string)
		return &struct {
			User string `json:"user"`
		}{User: user}, nil
	})

	set := app.Request(http.MethodPost, "/set?v=ada", nil)
	if set.Status != http.StatusOK {
		t.Fatalf("set status %d body %s", set.Status, set.Body)
	}
	cookies := (&http.Response{Header: set.Header}).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies %#v header %v", cookies, set.Header)
	}
	c := cookies[0]
	if c.Name != "session" || c.Value == "" || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Secure || c.MaxAge != 0 {
		t.Fatalf("cookie %+v", c)
	}

	header := http.Header{"Cookie": []string{"session=" + c.Value}}
	got := app.Request(http.MethodGet, "/get", nil, header)
	var body struct {
		User string `json:"user"`
	}
	if got.Status != http.StatusOK || got.JSON(&body) != nil || body.User != "ada" {
		t.Fatalf("get %d %s", got.Status, got.Body)
	}
	if got.Header.Get("Set-Cookie") != "" {
		t.Fatalf("unchanged session set cookie %q", got.Header.Get("Set-Cookie"))
	}

	last := c.Value[len(c.Value)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	tampered := c.Value[:len(c.Value)-1] + string(repl)
	for _, raw := range []string{tampered, "nope", "%%%", "abc.def"} {
		bad := app.Request(http.MethodGet, "/get", nil, http.Header{"Cookie": []string{"session=" + raw}})
		body = struct {
			User string `json:"user"`
		}{}
		if bad.Status != http.StatusOK || bad.JSON(&body) != nil || body.User != "" {
			t.Fatalf("cookie %q status %d body %s", raw, bad.Status, bad.Body)
		}
		if bad.Header.Get("Set-Cookie") != "" {
			t.Fatalf("cookie %q set %q", raw, bad.Header.Get("Set-Cookie"))
		}
	}

	other := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "other-secret"}))
	other.Get("/get", func(ctx context.Context, in *struct{}) (*struct {
		User string `json:"user"`
	}, error) {
		user, _ := gfast.SessionFrom(ctx)["user"].(string)
		return &struct {
			User string `json:"user"`
		}{User: user}, nil
	})
	wrong := other.Request(http.MethodGet, "/get", nil, header)
	body = struct {
		User string `json:"user"`
	}{}
	if wrong.Status != http.StatusOK || wrong.JSON(&body) != nil || body.User != "" {
		t.Fatalf("other secret %d %s", wrong.Status, wrong.Body)
	}
}

func TestSessionCookieOptions(t *testing.T) {
	app := gfast.New(gfast.Sessions(gfast.SessionConfig{
		Secret:   "s",
		Secure:   true,
		MaxAge:   120,
		SameSite: http.SameSiteStrictMode,
	}))
	app.Post("/set", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		gfast.SessionFrom(ctx)["user"] = "ada"
		return nil, nil
	})
	res := app.Request(http.MethodPost, "/set", nil)
	if res.Status != http.StatusNoContent {
		t.Fatalf("status %d body %s", res.Status, res.Body)
	}
	cookies := (&http.Response{Header: res.Header}).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies %#v", cookies)
	}
	c := cookies[0]
	if !c.HttpOnly || !c.Secure || c.MaxAge != 120 || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
		t.Fatalf("cookie %+v", c)
	}

	none := gfast.New(gfast.Sessions(gfast.SessionConfig{
		Secret:   "s",
		Secure:   true,
		SameSite: http.SameSiteNoneMode,
	}))
	none.Post("/set", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		gfast.SessionFrom(ctx)["user"] = "ada"
		return nil, nil
	})
	res = none.Request(http.MethodPost, "/set", nil)
	cookies = (&http.Response{Header: res.Header}).Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteNoneMode {
		t.Fatalf("none cookie %+v", cookies)
	}
}

func TestSessionClearAndError(t *testing.T) {
	app := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "s"}))
	app.Post("/set", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		gfast.SessionFrom(ctx)["user"] = "ada"
		return nil, nil
	})
	app.Post("/clear", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		sess := gfast.SessionFrom(ctx)
		for key := range sess {
			delete(sess, key)
		}
		return nil, nil
	})
	app.Get("/bad", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		gfast.SessionFrom(ctx)["user"] = "ada"
		return nil, gfast.BadRequest("nope")
	})

	set := app.Request(http.MethodPost, "/set", nil)
	cookies := (&http.Response{Header: set.Header}).Cookies()
	if len(cookies) != 1 || cookies[0].Value == "" {
		t.Fatalf("set cookie %+v", cookies)
	}
	cleared := app.Request(http.MethodPost, "/clear", nil, http.Header{"Cookie": []string{"session=" + cookies[0].Value}})
	gone := (&http.Response{Header: cleared.Header}).Cookies()
	if cleared.Status != http.StatusNoContent || len(gone) != 1 || gone[0].MaxAge >= 0 || gone[0].Value != "" {
		t.Fatalf("clear status %d cookies %+v", cleared.Status, gone)
	}

	bad := app.Request(http.MethodGet, "/bad", nil)
	if bad.Status != http.StatusBadRequest {
		t.Fatalf("bad status %d body %s", bad.Status, bad.Body)
	}
	saved := (&http.Response{Header: bad.Header}).Cookies()
	if len(saved) != 1 || saved[0].Value == "" {
		t.Fatalf("error cookie %+v", saved)
	}
}

func TestSessionsOff(t *testing.T) {
	app := gfast.New()
	app.Get("/x", func(ctx context.Context, in *struct{}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		return &struct {
			OK bool `json:"ok"`
		}{OK: true}, nil
	})
	res := app.Request(http.MethodGet, "/x", nil)
	if res.Status != http.StatusOK || res.Header.Get("Set-Cookie") != "" {
		t.Fatalf("off %d cookie %q", res.Status, res.Header.Get("Set-Cookie"))
	}
	mustPanic(t, "sessions", func() {
		app.Get("/y", func(ctx context.Context, in *struct{}) (*struct{}, error) {
			_ = gfast.SessionFrom(ctx)
			return &struct{}{}, nil
		})
		app.Request(http.MethodGet, "/y", nil)
	})
}

func TestSessionConfigRejects(t *testing.T) {
	mustPanic(t, "secret", func() {
		gfast.New(gfast.Sessions(gfast.SessionConfig{}))
	})
	mustPanic(t, "secure", func() {
		gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "s", SameSite: http.SameSiteNoneMode}))
	})
	mustPanic(t, "maxage", func() {
		gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "s", MaxAge: -1}))
	})
	mustPanic(t, "samesite", func() {
		gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "s", SameSite: 99}))
	})
}
