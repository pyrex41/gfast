package gfast_test

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pyrex41/gfast"
)

func TestClientCookiesRedirectsAndState(t *testing.T) {
	var starts, stops atomic.Int32
	app := gfast.New(
		gfast.OnStart(func(ctx context.Context) error {
			if gfast.StateFrom(ctx) == nil {
				return errors.New("missing state")
			}
			gfast.StateFrom(ctx)["ready"] = true
			starts.Add(1)
			return nil
		}),
		gfast.OnStop(func(ctx context.Context) error {
			if ready, _ := gfast.StateFrom(ctx)["ready"].(bool); !ready {
				return errors.New("state dropped")
			}
			stops.Add(1)
			return nil
		}),
		gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}),
	)
	app.State()["n"] = 1
	app.Post("/login", func(ctx context.Context, in *struct {
		Name string `json:"name"`
	}) (*struct{}, error) {
		if req := gfast.RequestFrom(ctx); req.Method != http.MethodPost || req.URL.Path != "/login" {
			return nil, errors.New("request")
		}
		gfast.SessionFrom(ctx)["user"] = in.Name
		gfast.ResponseFrom(ctx).SetCookie(&http.Cookie{Name: "sid", Value: in.Name, Path: "/"})
		return &struct{}{}, nil
	})
	app.Get("/me", func(ctx context.Context, in *struct{}) (*struct {
		User string `json:"user"`
		Sid  string `json:"sid"`
		N    int    `json:"n"`
	}, error) {
		user, _ := gfast.SessionFrom(ctx)["user"].(string)
		sid := ""
		if c, err := gfast.RequestFrom(ctx).Cookie("sid"); err == nil {
			sid = c.Value
		}
		n, _ := gfast.StateFrom(ctx)["n"].(int)
		n++
		gfast.StateFrom(ctx)["n"] = n
		ready, _ := gfast.StateFrom(ctx)["ready"].(bool)
		if !ready {
			return nil, errors.New("not ready")
		}
		return &struct {
			User string `json:"user"`
			Sid  string `json:"sid"`
			N    int    `json:"n"`
		}{User: user, Sid: sid, N: n}, nil
	})
	app.Get("/a", func(ctx context.Context, in *struct{}) (*gfast.Redirect, error) {
		return gfast.RedirectTo("/b", http.StatusFound), nil
	})
	app.Post("/see", func(ctx context.Context, in *struct {
		Name string `json:"name"`
	}) (*gfast.Redirect, error) {
		gfast.ResponseFrom(ctx).SetCookie(&http.Cookie{Name: "seen", Value: in.Name, Path: "/"})
		return gfast.RedirectTo("/land", http.StatusSeeOther), nil
	})
	app.Post("/keep", func(ctx context.Context, in *struct {
		Name string `json:"name"`
	}) (*gfast.Redirect, error) {
		return gfast.RedirectTo("/land", http.StatusTemporaryRedirect), nil
	})
	app.Get("/b", func(ctx context.Context, in *struct{}) (*struct {
		OK bool `json:"ok"`
	}, error) {
		return &struct {
			OK bool `json:"ok"`
		}{true}, nil
	})
	var landed atomic.Value
	app.Get("/land", func(ctx context.Context, in *struct{}) (*struct {
		Method string `json:"method"`
		Seen   string `json:"seen"`
	}, error) {
		seen := ""
		if c, err := gfast.RequestFrom(ctx).Cookie("seen"); err == nil {
			seen = c.Value
		}
		out := &struct {
			Method string `json:"method"`
			Seen   string `json:"seen"`
		}{Method: gfast.RequestFrom(ctx).Method, Seen: seen}
		landed.Store(out.Method)
		return out, nil
	})
	app.Post("/land", func(ctx context.Context, in *struct {
		Name string `json:"name"`
	}) (*struct {
		Method string `json:"method"`
		Name   string `json:"name"`
	}, error) {
		return &struct {
			Method string `json:"method"`
			Name   string `json:"name"`
		}{Method: http.MethodPost, Name: in.Name}, nil
	})
	app.Get("/away", func(ctx context.Context, in *struct{}) (*gfast.Redirect, error) {
		return gfast.RedirectTo("https://elsewhere.example/no", http.StatusFound), nil
	})
	var hops atomic.Int32
	app.Get("/loop/{n}", func(ctx context.Context, in *struct {
		N int `path:"n"`
	}) (*gfast.Redirect, error) {
		hops.Add(1)
		return gfast.RedirectTo("/loop/"+strconv.Itoa(in.N+1), http.StatusFound), nil
	})

	before := app.Request(http.MethodGet, "/b", nil)
	if before.Status != http.StatusOK || starts.Load() != 0 {
		t.Fatalf("before %d %s starts %d", before.Status, before.Body, starts.Load())
	}

	client := app.Client()
	login := client.Request(http.MethodPost, "/login", []byte(`{"name":"ada"}`))
	if login.Status != http.StatusOK || starts.Load() != 1 {
		t.Fatalf("login %d %s starts %d", login.Status, login.Body, starts.Load())
	}
	me := client.Request(http.MethodGet, "/me", nil)
	var got struct {
		User string `json:"user"`
		Sid  string `json:"sid"`
		N    int    `json:"n"`
	}
	if err := me.JSON(&got); err != nil {
		t.Fatal(err)
	}
	if me.Status != http.StatusOK || got.User != "ada" || got.Sid != "ada" || got.N != 2 || starts.Load() != 1 {
		t.Fatalf("me %d %+v starts %d", me.Status, got, starts.Load())
	}
	again := app.Request(http.MethodGet, "/me", nil)
	got = struct {
		User string `json:"user"`
		Sid  string `json:"sid"`
		N    int    `json:"n"`
	}{}
	if err := again.JSON(&got); err != nil {
		t.Fatal(err)
	}
	if got.User != "" || got.Sid != "" || got.N != 3 {
		t.Fatalf("single shot kept state %+v", got)
	}

	follow := client.Request(http.MethodGet, "/a", nil)
	if follow.Status != http.StatusOK || !strings.Contains(string(follow.Body), `"ok":true`) {
		t.Fatalf("follow %d %s", follow.Status, follow.Body)
	}
	see := client.Request(http.MethodPost, "/see", []byte(`{"name":"bee"}`))
	var land struct {
		Method string `json:"method"`
		Seen   string `json:"seen"`
	}
	if err := see.JSON(&land); err != nil {
		t.Fatal(err)
	}
	if see.Status != http.StatusOK || land.Method != http.MethodGet || land.Seen != "bee" {
		t.Fatalf("see %d %+v", see.Status, land)
	}
	keep := client.Request(http.MethodPost, "/keep", []byte(`{"name":"cy"}`))
	var kept struct {
		Method string `json:"method"`
		Name   string `json:"name"`
	}
	if err := keep.JSON(&kept); err != nil {
		t.Fatal(err)
	}
	if keep.Status != http.StatusOK || kept.Method != http.MethodPost || kept.Name != "cy" {
		t.Fatalf("keep %d %+v", keep.Status, kept)
	}
	away := client.Request(http.MethodGet, "/away", nil)
	if away.Status != http.StatusFound || away.Header.Get("Location") != "https://elsewhere.example/no" {
		t.Fatalf("away %d %s", away.Status, away.Header.Get("Location"))
	}
	loop := client.Request(http.MethodGet, "/loop/0", nil)
	if loop.Status != http.StatusFound || hops.Load() != int32(gfast.ClientRedirectLimit+1) {
		t.Fatalf("loop %d hops %d loc %s", loop.Status, hops.Load(), loop.Header.Get("Location"))
	}
	if !strings.HasSuffix(loop.Header.Get("Location"), "/loop/"+strconv.Itoa(gfast.ClientRedirectLimit+1)) {
		t.Fatalf("loop location %s", loop.Header.Get("Location"))
	}

	client.FollowRedirects = false
	stay := client.Request(http.MethodGet, "/a", nil)
	if stay.Status != http.StatusFound || stay.Header.Get("Location") != "/b" {
		t.Fatalf("stay %d %s", stay.Status, stay.Header.Get("Location"))
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if stops.Load() != 1 {
		t.Fatalf("stops %d", stops.Load())
	}
	if err := client.Close(); err != nil || stops.Load() != 1 {
		t.Fatalf("second close %v stops %d", err, stops.Load())
	}

	bad := gfast.New(gfast.OnStart(func(ctx context.Context) error {
		return errors.New("nope")
	}), gfast.OnStop(func(ctx context.Context) error {
		stops.Add(1)
		return nil
	}))
	failed := bad.Client()
	if err := failed.Start(); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("start %v", err)
	}
	if err := failed.Close(); err != nil || stops.Load() != 1 {
		t.Fatalf("failed close %v stops %d", err, stops.Load())
	}
}
