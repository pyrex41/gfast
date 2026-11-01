package gfast_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"github.com/pyrex41/gfast"
)

func TestPropUnmatchedAndMethodProblem(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		seg := hegel.Draw(ht, hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(8))
		known := hegel.Draw(ht, hegel.Booleans())
		get := hegel.Draw(ht, hegel.Booleans())
		post := hegel.Draw(ht, hegel.Booleans())
		put := hegel.Draw(ht, hegel.Booleans())
		patch := hegel.Draw(ht, hegel.Booleans())
		del := hegel.Draw(ht, hegel.Booleans())
		reqMethods := []string{
			http.MethodGet,
			http.MethodHead,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		}
		method := reqMethods[hegel.Draw(ht, hegel.Integers(0, len(reqMethods)-1))]

		registered := map[string]bool{
			http.MethodGet:    get,
			http.MethodPost:   post,
			http.MethodPut:    put,
			http.MethodPatch:  patch,
			http.MethodDelete: del,
		}
		var hits int
		app := gfast.New()
		handle := func(ctx context.Context, in *struct{}) (*struct {
			OK bool `json:"ok"`
		}, error) {
			hits++
			return &struct {
				OK bool `json:"ok"`
			}{OK: true}, nil
		}
		path := "/yes/" + seg
		if get {
			app.Get(path, handle)
		}
		if post {
			app.Post(path, handle)
		}
		if put {
			app.Put(path, handle)
		}
		if patch {
			app.Patch(path, handle)
		}
		if del {
			app.Delete(path, handle)
		}

		target := "/no/" + seg
		if known {
			target = path
		}
		res := app.Request(method, target, nil)
		matched := known && (registered[method] || (method == http.MethodHead && get))
		if matched {
			if res.Status != http.StatusOK || hits != 1 || res.Header.Get("Allow") != "" {
				ht.Fatalf("hit status %d hits %d allow %q body %s", res.Status, hits, res.Header.Get("Allow"), res.Body)
			}
			if method == http.MethodHead {
				if len(res.Body) != 0 || res.Header.Get("Content-Type") != "application/json" {
					ht.Fatalf("head %q type %q", res.Body, res.Header.Get("Content-Type"))
				}
				return
			}
			var got struct {
				OK bool `json:"ok"`
			}
			if err := res.JSON(&got); err != nil || !got.OK {
				ht.Fatalf("body %s err %v", res.Body, err)
			}
			return
		}
		if hits != 0 {
			ht.Fatalf("handler ran")
		}
		want := http.StatusNotFound
		detail := "Not Found"
		allow := ""
		// GET registration also serves HEAD, and ServeMux lists that HEAD in Allow.
		if known && fuAnyMethod(registered) {
			want = http.StatusMethodNotAllowed
			detail = "Method Not Allowed"
			allow = fuAllow(registered)
		}
		if res.Header.Get("Allow") != allow {
			ht.Fatalf("allow %q want %q status %d body %s", res.Header.Get("Allow"), allow, res.Status, res.Body)
		}
		if method == http.MethodHead {
			if res.Status != want || len(res.Body) != 0 || res.Header.Get("Content-Type") != "application/problem+json" {
				ht.Fatalf("head status %d type %q body %q", res.Status, res.Header.Get("Content-Type"), res.Body)
			}
			return
		}
		hpProblem(ht, res, want, detail)
	})
}

func TestPropMountStaticGenerated(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		grouped := hegel.Draw(ht, hegel.Booleans())
		nested := hegel.Draw(ht, hegel.Booleans())
		seg := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		name := hegel.Draw(ht, hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(8)) + ".txt"
		body := hegel.Draw(ht, hegel.Binary(1, 32))
		missing := hegel.Draw(ht, hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(8)) + ".bin"
		if missing == name {
			missing = "x" + missing
		}

		dir, err := os.MkdirTemp("", "gfast-fu-")
		if err != nil {
			ht.Fatal(err)
		}
		defer os.RemoveAll(dir)
		rel := name
		if nested {
			if err := os.Mkdir(filepath.Join(dir, seg), 0o755); err != nil {
				ht.Fatal(err)
			}
			rel = seg + "/" + name
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), body, 0o644); err != nil {
			ht.Fatal(err)
		}

		app := gfast.New()
		var root gfast.Router = app
		prefix := ""
		if grouped {
			root = app.Group("/v1")
			prefix = "/v1"
		}
		gfast.Static(root, "/assets", dir)
		gfast.Mount(root, "/extra", http.FileServer(http.Dir(dir)))

		for _, base := range []string{prefix + "/assets/", prefix + "/extra/"} {
			got := app.Request(http.MethodGet, base+rel, nil)
			if got.Status != http.StatusOK || !bytes.Equal(got.Body, body) {
				ht.Fatalf("get %s %d body %q want %q", base, got.Status, got.Body, body)
			}
			head := app.Request(http.MethodHead, base+rel, nil)
			if head.Status != http.StatusOK || len(head.Body) != 0 || head.Header.Get("Content-Type") != got.Header.Get("Content-Type") {
				ht.Fatalf("head %s %d type %q/%q body %q", base, head.Status, head.Header.Get("Content-Type"), got.Header.Get("Content-Type"), head.Body)
			}
			miss := app.Request(http.MethodGet, base+missing, nil)
			hpProblem(ht, miss, http.StatusNotFound, "Not Found")
		}
		// Static registers GET only. Mount delegates every method to the handler.
		post := app.Request(http.MethodPost, prefix+"/assets/"+rel, nil)
		hpProblem(ht, post, http.StatusMethodNotAllowed, "Method Not Allowed")
		if post.Header.Get("Allow") != "GET, HEAD" {
			ht.Fatalf("static post allow %q body %s", post.Header.Get("Allow"), post.Body)
		}
		mounted := app.Request(http.MethodPost, prefix+"/extra/"+rel, nil)
		if mounted.Status != http.StatusOK || !bytes.Equal(mounted.Body, body) {
			ht.Fatalf("mount post %d body %q", mounted.Status, mounted.Body)
		}
	})
}

func TestPropSameSiteNoneRequiresSecure(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		secret := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		value := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MaxSize(12))
		secure := hegel.Draw(ht, hegel.Booleans())
		none := hegel.Draw(ht, hegel.Booleans())
		maxAge := []int{0, 1, 30, 120}[hegel.Draw(ht, hegel.Integers(0, 3))]
		same := http.SameSiteLaxMode
		if none {
			same = http.SameSiteNoneMode
		}
		cfg := gfast.SessionConfig{Secret: secret, Secure: secure, MaxAge: maxAge, SameSite: same}
		var app *gfast.App
		rec := hpCatch(func() {
			app = gfast.New(gfast.Sessions(cfg))
		})
		if none && !secure {
			if rec == nil || !strings.Contains(fmt.Sprint(rec), "SameSite=None requires Secure") {
				ht.Fatalf("panic %#v", rec)
			}
			return
		}
		if rec != nil {
			ht.Fatalf("panic %#v", rec)
		}
		app.Post("/set", func(ctx context.Context, in *struct {
			V string `json:"v"`
		}) (*struct{}, error) {
			gfast.SessionFrom(ctx)["user"] = in.V
			return &struct{}{}, nil
		})
		res := app.Request(http.MethodPost, "/set", []byte(`{"v":"`+value+`"}`))
		if res.Status != http.StatusOK {
			ht.Fatalf("set %d %s", res.Status, res.Body)
		}
		cookie := pendCookie(ht, res, "session")
		wantSame := http.SameSiteLaxMode
		if none {
			wantSame = http.SameSiteNoneMode
		}
		if !cookie.HttpOnly || cookie.Path != "/" || cookie.Secure != secure || cookie.SameSite != wantSame || cookie.MaxAge != maxAge || cookie.Value == "" {
			ht.Fatalf("cookie %+v secure %v same %v age %d", cookie, secure, wantSame, maxAge)
		}
		app.Get("/get", func(ctx context.Context, in *struct{}) (*struct {
			User string `json:"user"`
		}, error) {
			user, _ := gfast.SessionFrom(ctx)["user"].(string)
			return &struct {
				User string `json:"user"`
			}{User: user}, nil
		})
		got := app.Request(http.MethodGet, "/get", nil, http.Header{"Cookie": []string{"session=" + cookie.Value}})
		var body struct {
			User string `json:"user"`
		}
		if got.Status != http.StatusOK || got.JSON(&body) != nil || body.User != value {
			ht.Fatalf("get %d %+v body %s", got.Status, body, got.Body)
		}
	})
}

func TestPropWebSocketUpgradeHTTPError(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		methods := []string{http.MethodGet, http.MethodHead, http.MethodPost}
		method := methods[hegel.Draw(ht, hegel.Integers(0, len(methods)-1))]
		withUpgrade := hegel.Draw(ht, hegel.Booleans())
		version := []string{"13", "12", "8", ""}[hegel.Draw(ht, hegel.Integers(0, 3))]
		extensions := hegel.Draw(ht, hegel.Booleans())
		validKey := hegel.Draw(ht, hegel.Booleans())
		badKey := hegel.Draw(ht, hegel.Text().Alphabet("abcABC012+/=").MaxSize(12))

		var ran bool
		app := gfast.New()
		app.WebSocket("/ws", func(ctx context.Context, in *struct{}) error {
			ran = true
			return nil
		})
		header := http.Header{}
		if withUpgrade {
			key := "dGhlIHNhbXBsZSBub25jZQ=="
			if !validKey {
				key = badKey
			}
			header = upgradeHeaders(key)
			if version == "" {
				header.Del("Sec-WebSocket-Version")
			} else {
				header.Set("Sec-WebSocket-Version", version)
			}
			if extensions {
				header.Set("Sec-WebSocket-Extensions", "permessage-deflate")
			}
		}
		res := app.Request(method, "/ws", nil, header)
		if ran || res.Status == http.StatusSwitchingProtocols {
			ht.Fatalf("ran %v status %d body %s", ran, res.Status, res.Body)
		}
		// POST never reaches the GET pattern. HEAD matches GET, then the
		// handshake rejects every method other than GET before upgrading.
		switch method {
		case http.MethodPost:
			hpProblem(ht, res, http.StatusMethodNotAllowed, "Method Not Allowed")
			if res.Header.Get("Allow") != "GET, HEAD" {
				ht.Fatalf("allow %q", res.Header.Get("Allow"))
			}
			return
		case http.MethodHead:
			if res.Status != http.StatusMethodNotAllowed || len(res.Body) != 0 || res.Header.Get("Content-Type") != "application/problem+json" || res.Header.Get("Allow") != "" {
				ht.Fatalf("head %d type %q allow %q body %q", res.Status, res.Header.Get("Content-Type"), res.Header.Get("Allow"), res.Body)
			}
			return
		}
		status, detail := fuUpgradeFailure(withUpgrade, version, extensions, validKey)
		hpProblem(ht, res, status, detail)
		if status == http.StatusInternalServerError && bytes.Contains(res.Body, []byte("Hijacker")) {
			ht.Fatalf("hijack detail leaked %s", res.Body)
		}
	})
}

func fuAnyMethod(registered map[string]bool) bool {
	for _, on := range registered {
		if on {
			return true
		}
	}
	return false
}

func fuAllow(registered map[string]bool) string {
	set := map[string]struct{}{}
	for method, on := range registered {
		if on {
			set[method] = struct{}{}
		}
	}
	if _, ok := set[http.MethodGet]; ok {
		set[http.MethodHead] = struct{}{}
	}
	list := make([]string, 0, len(set))
	for method := range set {
		list = append(list, method)
	}
	sort.Strings(list)
	return strings.Join(list, ", ")
}

func fuUpgradeFailure(withUpgrade bool, version string, extensions, validKey bool) (int, string) {
	if !withUpgrade {
		return http.StatusBadRequest, "websocket handshake missing upgrade"
	}
	if version != "13" {
		return http.StatusBadRequest, "unsupported Sec-WebSocket-Version"
	}
	if extensions {
		return http.StatusBadRequest, "websocket extensions are not supported"
	}
	if !validKey {
		return http.StatusBadRequest, "invalid Sec-WebSocket-Key"
	}
	return http.StatusInternalServerError, "unexpected error occurred"
}
