package gfast_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"github.com/pyrex41/gfast"
)

// reviewAuth is the inherited dependency the route-policy property counts.
// It accepts only the credential "Bearer ok" and rejects every other request.
var reviewHits atomic.Int32

type reviewMark struct{}

var reviewAuth = gfast.Dep("reviewAuth", func(ctx context.Context) (reviewMark, error) {
	reviewHits.Add(1)
	if gfast.RequestFrom(ctx).Header.Get("Authorization") != "Bearer ok" {
		return reviewMark{}, gfast.Unauthorized("rejected")
	}
	return reviewMark{}, nil
})

// TestIssue1MountStaticPolicy is the unauthenticated mount and the cross-site
// cookie mutation reported in GitHub issue 1.
func TestIssue1MountStaticPolicy(t *testing.T) {
	var hits int
	app := gfast.New()
	app.Group("/private", gfast.Require(gfast.BearerAuth())).Mount("/raw", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("private data"))
	}))
	got := app.Request(http.MethodGet, "/private/raw/", nil)
	if got.Status != http.StatusUnauthorized || hits != 0 || strings.Contains(string(got.Body), "private data") {
		t.Fatalf("mount status %d hits %d body %s", got.Status, hits, got.Body)
	}
	if got.Header.Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("challenge %q", got.Header.Get("WWW-Authenticate"))
	}
	redir := app.Request(http.MethodGet, "/private/raw", nil)
	if redir.Status != http.StatusTemporaryRedirect || redir.Header.Get("Location") != "/private/raw/" || hits != 0 {
		t.Fatalf("redirect %d location %q hits %d", redir.Status, redir.Header.Get("Location"), hits)
	}

	sess := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}))
	var mutated int
	sess.Group("/private").Mount("/raw", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutated++
		_, _ = w.Write([]byte("mutated"))
	}))
	cross := http.Header{
		"Cookie":         []string{"session=abc"},
		"Sec-Fetch-Site": []string{"cross-site"},
	}
	blocked := sess.Request(http.MethodPost, "/private/raw/", nil, cross)
	assertProblem(t, blocked, http.StatusForbidden, "csrf check failed")
	if mutated != 0 || strings.Contains(string(blocked.Body), "mutated") {
		t.Fatalf("mutated %d body %s", mutated, blocked.Body)
	}
	same := sess.Request(http.MethodPost, "/private/raw/", nil, http.Header{
		"Cookie":         []string{"session=abc"},
		"Sec-Fetch-Site": []string{"same-origin"},
	})
	if same.Status != http.StatusOK || mutated != 1 || string(same.Body) != "mutated" {
		t.Fatalf("same-origin %d mutated %d body %s", same.Status, mutated, same.Body)
	}

	skipped := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}))
	var skippedHits int
	outer := skipped.Group("/outer", gfast.SkipCSRF())
	outer.Group("/inner").Mount("/raw", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		skippedHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	opened := skipped.Request(http.MethodPost, "/outer/inner/raw/", nil, cross)
	if opened.Status != http.StatusNoContent || skippedHits != 1 {
		t.Fatalf("skip %d hits %d body %s", opened.Status, skippedHits, opened.Body)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	files := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}))
	files.Group("/private", gfast.Require(gfast.BearerAuth())).Static("/assets", dir)
	hidden := files.Request(http.MethodGet, "/private/assets/hello.txt", nil)
	assertProblem(t, hidden, http.StatusUnauthorized, "missing bearer token")
	if strings.Contains(string(hidden.Body), "hi") {
		t.Fatalf("static body %s", hidden.Body)
	}
	missing := files.Request(http.MethodGet, "/private/assets/missing.txt", nil, http.Header{"Authorization": []string{"Bearer ok"}})
	assertProblem(t, missing, http.StatusNotFound, "Not Found")
	shown := files.Request(http.MethodGet, "/private/assets/hello.txt", nil, http.Header{"Authorization": []string{"Bearer ok"}})
	if shown.Status != http.StatusOK || string(shown.Body) != "hi" {
		t.Fatalf("static ok %d %s", shown.Status, shown.Body)
	}
	posted := files.Request(http.MethodPost, "/private/assets/hello.txt", nil, cross)
	assertProblem(t, posted, http.StatusMethodNotAllowed, "Method Not Allowed")
	if posted.Header.Get("Allow") != "GET, HEAD" || strings.Contains(string(posted.Body), "hi") {
		t.Fatalf("static post %d allow %q body %s", posted.Status, posted.Header.Get("Allow"), posted.Body)
	}

	built := gfast.New(
		gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"}),
		gfast.Require(gfast.BearerAuth()),
		gfast.OAuthServer(gfast.OAuthConfig{Clients: []gfast.OAuthClient{{ID: "docs"}}}),
	)
	var builtHits int
	built.Get("/open", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
		builtHits++
		return &struct{ OK bool }{OK: true}, nil
	})
	built.Group("/other", gfast.Require(gfast.BearerAuth()))
	docs := built.Request(http.MethodGet, "/docs", nil)
	if docs.Status != http.StatusOK || !strings.Contains(string(docs.Body), "swagger-ui") || docs.Header.Get("WWW-Authenticate") != "" {
		t.Fatalf("docs %d challenge %q body %s", docs.Status, docs.Header.Get("WWW-Authenticate"), docs.Body)
	}
	spec := built.Request(http.MethodGet, "/openapi.json", nil)
	if spec.Status != http.StatusOK || !strings.Contains(string(spec.Body), `"openapi"`) {
		t.Fatalf("spec %d %s", spec.Status, spec.Body)
	}
	token := built.Request(http.MethodPost, "/oauth/token", nil)
	if token.Status != http.StatusBadRequest || strings.Contains(string(token.Body), "missing bearer token") || token.Header.Get("WWW-Authenticate") == "Bearer" {
		t.Fatalf("token %d challenge %q body %s", token.Status, token.Header.Get("WWW-Authenticate"), token.Body)
	}
	locked := built.Request(http.MethodGet, "/open", nil)
	if locked.Status != http.StatusUnauthorized || builtHits != 0 {
		t.Fatalf("app require %d hits %d body %s", locked.Status, builtHits, locked.Body)
	}

	hpReset()
	scoped := gfast.New()
	var scopeHits int
	scoped.Group("/private", gfast.Require(hpUser), gfast.Scopes("alpha", "beta")).Mount("/raw", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scopeHits++
		w.WriteHeader(http.StatusNoContent)
	}))
	scopeRes := scoped.Request(http.MethodGet, "/private/raw/", nil, http.Header{"Authorization": []string{"Bearer ok"}})
	if scopeRes.Status != http.StatusNoContent || scopeHits != 1 || hpUserCalls.Load() != 1 || !reflect.DeepEqual(hpSeenScope, []string{"alpha", "beta"}) {
		t.Fatalf("scopes status %d hits %d calls %d saw %v", scopeRes.Status, scopeHits, hpUserCalls.Load(), hpSeenScope)
	}

	reviewCloser(t, false, true, []string{"close-B", "close-A"})
	reviewCloser(t, true, true, []string{"close-B", "close-A"})
	reviewCloser(t, false, false, []string{"handler", "close-B", "close-A"})
	reviewCloser(t, true, false, []string{"handler", "close-B", "close-A"})
}

// reviewCloser checks that a mounted handler and a typed handler under the
// same Require list acquire hpBoxA then hpBoxB once and close them in reverse.
// failDep rejects the request after both boxes are acquired.
func reviewCloser(t *testing.T, mount, failDep bool, want []string) {
	t.Helper()
	hpReset()
	opts := []gfast.Option{gfast.Require(hpBoxA, hpBoxB)}
	if failDep {
		opts = append(opts, gfast.Require(hpUser))
	}
	app := gfast.New()
	g := app.Group("/g", opts...)
	if mount {
		g.Mount("/h", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hpEvents = append(hpEvents, "handler")
			w.WriteHeader(http.StatusNoContent)
		}))
	} else {
		g.Get("/h", func(ctx context.Context, in *struct{}) (*struct{}, error) {
			hpEvents = append(hpEvents, "handler")
			return nil, nil
		})
	}
	path := "/g/h"
	if mount {
		path = "/g/h/"
	}
	res := app.Request(http.MethodGet, path, nil)
	if failDep {
		assertProblem(t, res, http.StatusUnauthorized, "missing bearer token")
	} else if res.Status != http.StatusNoContent || len(res.Body) != 0 {
		t.Fatalf("status %d body %s", res.Status, res.Body)
	}
	if !reflect.DeepEqual(hpEvents, want) || hpBoxACalls.Load() != 1 || hpBoxBCalls.Load() != 1 {
		t.Fatalf("mount %v fail %v events %v calls %d %d", mount, failDep, hpEvents, hpBoxACalls.Load(), hpBoxBCalls.Load())
	}
}

func TestPropInheritedRoutePolicy(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		kind := hegel.Draw(ht, hegel.Integers(0, 2)) // 0 typed, 1 mount, 2 static
		depth := hegel.Draw(ht, hegel.Integers(0, 2))
		rawPlace := hegel.Draw(ht, hegel.Integers(0, 4)) // 0 none, 1 app, 2 outer, 3 inner, 4 route
		cred := hegel.Draw(ht, hegel.Integers(0, 2))     // 0 absent, 1 malformed, 2 Bearer ok
		cookieMode := hegel.Draw(ht, hegel.Integers(0, 2))
		method := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}[hegel.Draw(ht, hegel.Integers(0, 5))]
		site := []string{"", "cross-site", "CROSS-SITE", "same-origin", "same-site", "none"}[hegel.Draw(ht, hegel.Integers(0, 5))]
		skip := hegel.Draw(ht, hegel.Booleans())
		dup := hegel.Draw(ht, hegel.Booleans())
		secret := "REVIEWSECRET" + hegel.Draw(ht, hegel.Text().Alphabet("abcxyz012").MinSize(1).MaxSize(8))
		place := reviewPlace(kind, depth, rawPlace)

		reviewHits.Store(0)
		var ran atomic.Int32
		appOpts := []gfast.Option{gfast.Sessions(gfast.SessionConfig{Secret: "test-secret"})}
		if depth == 0 && skip {
			appOpts = append(appOpts, gfast.SkipCSRF())
		}
		if place == 1 {
			appOpts = append(appOpts, gfast.Require(reviewAuth))
			if dup {
				appOpts = append(appOpts, gfast.Require(reviewAuth))
			}
		}
		app := gfast.New(appOpts...)
		var leaf gfast.Router = app
		if depth >= 1 {
			var outer []gfast.Option
			if skip {
				outer = append(outer, gfast.SkipCSRF())
			}
			if place == 2 {
				outer = append(outer, gfast.Require(reviewAuth))
				if dup {
					outer = append(outer, gfast.Require(reviewAuth))
				}
			}
			g := app.Group("/p", outer...)
			leaf = g
			if depth >= 2 {
				var inner []gfast.Option
				if place == 3 {
					inner = append(inner, gfast.Require(reviewAuth))
					if dup {
						inner = append(inner, gfast.Require(reviewAuth))
					}
				}
				leaf = g.Group("/c", inner...)
			}
		}
		var routeOpts []gfast.Option
		if place == 4 {
			routeOpts = append(routeOpts, gfast.Require(reviewAuth))
			if dup {
				routeOpts = append(routeOpts, gfast.Require(reviewAuth))
			}
		}
		handle := func(ctx context.Context, in *struct{}) (*struct {
			OK string `json:"ok"`
		}, error) {
			ran.Add(1)
			return &struct {
				OK string `json:"ok"`
			}{OK: secret}, nil
		}
		switch kind {
		case 0:
			gfast.Get(leaf, "/leaf", handle, routeOpts...)
			gfast.Post(leaf, "/leaf", handle, routeOpts...)
			gfast.Put(leaf, "/leaf", handle, routeOpts...)
			gfast.Patch(leaf, "/leaf", handle, routeOpts...)
			gfast.Delete(leaf, "/leaf", handle, routeOpts...)
		case 1:
			gfast.Mount(leaf, "/leaf", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ran.Add(1)
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = w.Write([]byte(secret))
			}))
		default:
			dir, err := os.MkdirTemp("", "gfast-review-")
			if err != nil {
				ht.Fatal(err)
			}
			defer os.RemoveAll(dir)
			if err := os.WriteFile(filepath.Join(dir, "item.txt"), []byte(secret), 0o644); err != nil {
				ht.Fatal(err)
			}
			gfast.Static(leaf, "/leaf", dir)
		}

		prefix := ""
		if depth >= 1 {
			prefix = "/p"
		}
		if depth >= 2 {
			prefix += "/c"
		}
		target := prefix + "/leaf"
		if kind != 0 {
			target += "/item.txt"
		}
		header := http.Header{}
		cookie := ""
		switch cookieMode {
		case 1:
			header.Set("Cookie", "session=")
		case 2:
			cookie = "abc"
			header.Set("Cookie", "session=abc")
		}
		if site != "" {
			header.Set("Sec-Fetch-Site", site)
		}
		switch cred {
		case 1:
			header.Set("Authorization", "Bearer")
		case 2:
			header.Set("Authorization", "Bearer ok")
		}
		res := app.Request(method, target, nil, header)

		required := place != 0
		staticMiss := kind == 2 && method != http.MethodGet && method != http.MethodHead
		csrfReject := reviewCSRFReject(skip, method, cookie, site)
		label := func() string {
			return strings.Join([]string{
				"kind", strconv.Itoa(kind),
				"depth", strconv.Itoa(depth),
				"place", strconv.Itoa(place),
				"cred", strconv.Itoa(cred),
				"cookie", strconv.Itoa(cookieMode),
				"method", method,
				"site", site,
				"skip", strconv.FormatBool(skip),
				"dup", strconv.FormatBool(dup),
			}, " ")
		}
		if strings.Contains(string(res.Body), secret) && (staticMiss || csrfReject || (required && cred != 2)) {
			ht.Fatalf("secret leaked %s body %s", label(), res.Body)
		}
		if staticMiss {
			hpProblem(ht, res, http.StatusMethodNotAllowed, "Method Not Allowed")
			if res.Header.Get("Allow") != "GET, HEAD" || ran.Load() != 0 || reviewHits.Load() != 0 {
				ht.Fatalf("static method %s allow %q ran %d deps %d", label(), res.Header.Get("Allow"), ran.Load(), reviewHits.Load())
			}
			return
		}
		if csrfReject {
			if method == http.MethodHead {
				if res.Status != http.StatusForbidden || len(res.Body) != 0 || res.Header.Get("Content-Type") != "application/problem+json" {
					ht.Fatalf("head csrf %s status %d type %s body %q", label(), res.Status, res.Header.Get("Content-Type"), res.Body)
				}
			} else {
				hpProblem(ht, res, http.StatusForbidden, "csrf check failed")
			}
			if ran.Load() != 0 || reviewHits.Load() != 0 {
				ht.Fatalf("csrf ran %s ran %d deps %d", label(), ran.Load(), reviewHits.Load())
			}
			return
		}
		if required && cred != 2 {
			if method == http.MethodHead {
				if res.Status != http.StatusUnauthorized || len(res.Body) != 0 || res.Header.Get("Content-Type") != "application/problem+json" {
					ht.Fatalf("head auth %s status %d type %s body %q", label(), res.Status, res.Header.Get("Content-Type"), res.Body)
				}
			} else {
				hpProblem(ht, res, http.StatusUnauthorized, "rejected")
			}
			// The first rejection aborts Require, so a repeated dependency runs once.
			if ran.Load() != 0 || reviewHits.Load() != 1 {
				ht.Fatalf("rejected %s ran %d deps %d", label(), ran.Load(), reviewHits.Load())
			}
			return
		}
		wantDeps := int32(0)
		if required {
			wantDeps = 1
		}
		wantRan := int32(1)
		if kind == 2 {
			wantRan = 0
		}
		if ran.Load() != wantRan || reviewHits.Load() != wantDeps {
			ht.Fatalf("allowed %s ran %d deps %d want ran %d deps %d status %d body %s", label(), ran.Load(), reviewHits.Load(), wantRan, wantDeps, res.Status, res.Body)
		}
		if method == http.MethodHead {
			if res.Status != http.StatusOK || len(res.Body) != 0 {
				ht.Fatalf("head %s status %d body %q", label(), res.Status, res.Body)
			}
			if kind == 2 && res.Header.Get("Content-Length") != strconv.Itoa(len(secret)) {
				ht.Fatalf("static head %s length %q", label(), res.Header.Get("Content-Length"))
			}
			return
		}
		if kind == 0 {
			var got struct {
				OK string `json:"ok"`
			}
			if res.Status != http.StatusOK || res.JSON(&got) != nil || got.OK != secret {
				ht.Fatalf("typed %s status %d body %s", label(), res.Status, res.Body)
			}
			return
		}
		if res.Status != http.StatusOK || string(res.Body) != secret {
			ht.Fatalf("body %s status %d body %q", label(), res.Status, res.Body)
		}
	})
}

// reviewPlace maps a drawn placement onto a router that exists for this kind
// and depth. Group and route placements collapse onto the app when that
// router is absent, so a drawn requirement is not discarded.
func reviewPlace(kind, depth, place int) int {
	switch place {
	case 2:
		if depth < 1 {
			return 1
		}
	case 3:
		if depth >= 2 {
			return 3
		}
		if depth == 1 {
			return 2
		}
		return 1
	case 4:
		if kind != 0 {
			return 1
		}
	}
	return place
}

// reviewCSRFReject is the documented CSRF rule for the inputs this property
// draws: sessions on, token mode off, no Origin or Referer. A nonempty session
// cookie on an unsafe method from a cross-site fetch is rejected unless the
// registering group, or the app when there is no group, set SkipCSRF.
// Node is the minimal recursive input from issue 10.
type Node struct {
	Name string `json:"name"`
	Next *Node  `json:"next"`
}

type reviewNode struct {
	Name string      `json:"name"`
	Next *reviewNode `json:"next"`
}

type reviewA struct {
	Name string   `json:"name"`
	B    *reviewB `json:"b"`
}

type reviewB struct {
	Name string   `json:"name"`
	A    *reviewA `json:"a"`
}

type reviewBody struct {
	Body reviewNode
}

type reviewLeaf struct {
	Name string `json:"name"`
}

type reviewShare struct {
	A reviewLeaf `json:"a"`
	B reviewLeaf `json:"b"`
}

type reviewSeen struct {
	Title string `json:"title"`
	Slot  string `json:"slot"`
}

type reviewToken struct {
	Value string
}

const reviewDepValue = "dep-value"

var reviewTokenDep = gfast.Dep("reviewToken", func(ctx context.Context) (reviewToken, error) {
	return reviewToken{Value: reviewDepValue}, nil
})

type reviewPath struct {
	ID    string `path:"id"`
	Title string `json:"title"`
}

type reviewPathAllow struct {
	reviewPath
	_ struct{} `extra:"allow"`
}

type reviewPathAlias struct {
	ID    string `path:"id" json:"user_id"`
	Title string `json:"title"`
}

type reviewPathAliasAllow struct {
	reviewPathAlias
	_ struct{} `extra:"allow"`
}

type reviewQuery struct {
	Q     string `query:"q" default:"fallback"`
	Title string `json:"title"`
}

type reviewQueryAllow struct {
	reviewQuery
	_ struct{} `extra:"allow"`
}

type reviewHeader struct {
	Flag  string `header:"X-Review" default:"fallback"`
	Title string `json:"title"`
}

type reviewHeaderAllow struct {
	reviewHeader
	_ struct{} `extra:"allow"`
}

type reviewCookie struct {
	Sid   string `cookie:"sid" default:"fallback"`
	Title string `json:"title"`
}

type reviewCookieAllow struct {
	reviewCookie
	_ struct{} `extra:"allow"`
}

type reviewEmbedInner struct {
	ID    string `path:"id"`
	Title string `json:"title"`
}

type reviewEmbedIn struct {
	reviewEmbedInner
}

type reviewEmbedAllow struct {
	reviewEmbedIn
	_ struct{} `extra:"allow"`
}

type reviewEmbedAliasInner struct {
	ID    string `path:"id" json:"user_id"`
	Title string `json:"title"`
}

type reviewEmbedAliasIn struct {
	reviewEmbedAliasInner
}

type reviewEmbedAliasAllow struct {
	reviewEmbedAliasIn
	_ struct{} `extra:"allow"`
}

type reviewPtrIn struct {
	*reviewPath
}

type reviewPtrAllow struct {
	reviewPtrIn
	_ struct{} `extra:"allow"`
}

type reviewDepIn struct {
	Title string      `json:"title"`
	User  reviewToken `gfast:"dep=reviewToken"`
}

type reviewDepAllow struct {
	reviewDepIn
	_ struct{} `extra:"allow"`
}

type reviewDepAliasIn struct {
	Title string      `json:"title" `
	User  reviewToken `json:"user" gfast:"dep=reviewToken"`
}

type reviewDepAliasAllow struct {
	reviewDepAliasIn
	_ struct{} `extra:"allow"`
}

// reviewFix is the independent ownership table for one handler input.
// reserved is the JSON object name of the non-JSON field.
type reviewFix struct {
	reserved string
	source   string
	param    string
	route    string
}

var reviewFixes = []reviewFix{
	{"ID", "path", "id", "/own/{id}"},
	{"user_id", "path", "id", "/own/{id}"},
	{"Q", "query", "q", "/own"},
	{"Flag", "header", "X-Review", "/own"},
	{"Sid", "cookie", "sid", "/own"},
	{"ID", "path", "id", "/own/{id}"},
	{"user_id", "path", "id", "/own/{id}"},
	{"ID", "path", "id", "/own/{id}"},
	{"User", "dependency", "", "/own"},
	{"user", "dependency", "", "/own"},
}

// TestIssue2FlatJSONDoesNotReplacePath is the flat-JSON counterexample from issue 2.
func TestIssue2FlatJSONDoesNotReplacePath(t *testing.T) {
	type Input struct {
		ID   string `path:"id"`
		Name string `json:"name"`
	}
	var hits int
	var gotID, gotName string
	app := gfast.New()
	app.Post("/items/{id}", func(ctx context.Context, in *Input) (*struct {
		ID   string `json:"ID"`
		Name string `json:"name"`
	}, error) {
		hits++
		gotID, gotName = in.ID, in.Name
		return &struct {
			ID   string `json:"ID"`
			Name string `json:"name"`
		}{ID: in.ID, Name: in.Name}, nil
	})
	ok := app.Request(http.MethodPost, "/items/url-id", []byte(`{"name":"n"}`))
	if ok.Status != http.StatusOK || hits != 1 || gotID != "url-id" || gotName != "n" || !strings.Contains(string(ok.Body), `"url-id"`) {
		t.Fatalf("clean status %d hits %d id %q name %q body %s", ok.Status, hits, gotID, gotName, ok.Body)
	}
	bad := app.Request(http.MethodPost, "/items/url-id", []byte(`{"name":"n","ID":"body-id"}`))
	if bad.Status != http.StatusUnprocessableEntity || hits != 1 || strings.Contains(string(bad.Body), "body-id") {
		t.Fatalf("conflict status %d hits %d body %s", bad.Status, hits, bad.Body)
	}
}

// TestIssue10RecursiveInputPanics is the Node counterexample from issue 10.
// The child must panic with the documented message and must not keep running.
func TestIssue10RecursiveInputPanics(t *testing.T) {
	if os.Getenv("GFAST_REVIEW_REGISTER") == "issue10" {
		gfast.Post(gfast.New(), "/n", func(ctx context.Context, in *Node) (*Node, error) {
			return in, nil
		})
		fmtReview("registered")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestIssue10RecursiveInputPanics$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "GFAST_REVIEW_REGISTER=issue10")
	raw, err := cmd.CombinedOutput()
	out := string(raw)
	if strings.Contains(out, "GFAST_RESULT registered") || strings.Contains(strings.ToLower(out), "stack overflow") {
		t.Fatalf("registration did not stop: %v %s", err, out)
	}
	if err == nil || !strings.Contains(out, "gfast: recursive type") || !strings.Contains(out, "Node") {
		t.Fatalf("panic err %v output %s", err, out)
	}
}

func TestPropRecursiveInputs(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		kind := hegel.Draw(ht, hegel.Integers(0, 3)) // 0 self, 1 mutual, 2 body, 3 shared acyclic
		depth := hegel.Draw(ht, hegel.Integers(0, 2))
		a := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(4))
		b := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(4))
		switch kind {
		case 0:
			reviewMustPanic(ht, "self", "reviewNode")
		case 1:
			reviewMustPanic(ht, "mutual", "reviewA")
		case 2:
			var hits int
			app := gfast.New()
			app.Post("/n", func(ctx context.Context, in *reviewBody) (*reviewNode, error) {
				hits++
				return &in.Body, nil
			})
			want, raw := reviewChain(depth, a)
			res := app.Request(http.MethodPost, "/n", raw)
			if res.Status != http.StatusOK || hits != 1 {
				ht.Fatalf("body status %d hits %d body %s", res.Status, hits, res.Body)
			}
			var got reviewNode
			if err := res.JSON(&got); err != nil {
				ht.Fatal(err)
			}
			if !reflect.DeepEqual(got, *want) {
				ht.Fatalf("got %#v want %#v", got, *want)
			}
		default:
			var hits int
			app := gfast.New()
			app.Post("/n", func(ctx context.Context, in *reviewShare) (*reviewShare, error) {
				hits++
				return in, nil
			})
			raw, err := json.Marshal(reviewShare{A: reviewLeaf{Name: a}, B: reviewLeaf{Name: b}})
			if err != nil {
				ht.Fatal(err)
			}
			res := app.Request(http.MethodPost, "/n", raw)
			if res.Status != http.StatusOK || hits != 1 {
				ht.Fatalf("share status %d hits %d body %s", res.Status, hits, res.Body)
			}
			var got reviewShare
			if err := res.JSON(&got); err != nil {
				ht.Fatal(err)
			}
			if got.A.Name != a || got.B.Name != b {
				ht.Fatalf("got %#v want %q %q", got, a, b)
			}
		}
	})
}

func TestPropSingleFieldSource(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		base := hegel.Draw(ht, hegel.Integers(0, len(reviewFixes)-1))
		allow := hegel.Draw(ht, hegel.Booleans())
		present := hegel.Draw(ht, hegel.Booleans())
		conflict := hegel.Draw(ht, hegel.Booleans())
		unknown := hegel.Draw(ht, hegel.Booleans())
		same := hegel.Draw(ht, hegel.Booleans())
		trans := "T" + hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(6))
		title := "B" + hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(6))
		other := "C" + hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(6))
		fix := reviewFixes[base]
		conflictVal := other
		if same {
			conflictVal = trans
		}
		var hits int
		app := gfast.New()
		reviewMount(app, base, allow, &hits)
		spec := hpSpec(ht, app)
		op := spec.op(fix.route, "post")
		schema := spec.expand(op.RequestBody.Content["application/json"].Schema)
		if len(schema.Properties) != 1 || schema.Properties["title"] == nil || schema.Properties[fix.reserved] != nil {
			ht.Fatalf("schema %#v reserved %s", schema.Properties, fix.reserved)
		}
		if fix.param == "" {
			if len(op.Parameters) != 0 {
				ht.Fatalf("params %#v", op.Parameters)
			}
		} else {
			found := false
			for _, p := range op.Parameters {
				if p.Name == fix.param && p.In == fix.source {
					found = true
				}
			}
			if !found {
				ht.Fatalf("params %#v want %s %s", op.Parameters, fix.source, fix.param)
			}
		}

		body := map[string]any{"title": title}
		if conflict {
			body[fix.reserved] = conflictVal
		}
		unknownName := "zz" + other
		if unknown {
			body[unknownName] = 1
		}
		payload, err := json.Marshal(body)
		if err != nil {
			ht.Fatal(err)
		}
		target := fix.route
		header := http.Header{}
		switch fix.source {
		case "path":
			target = "/own/" + url.PathEscape(trans)
		case "query":
			if present {
				target = "/own?q=" + url.QueryEscape(trans)
			}
		case "header":
			if present {
				header.Set("X-Review", trans)
			}
		case "cookie":
			if present {
				header.Set("Cookie", "sid="+trans)
			}
		}
		res := app.Request(http.MethodPost, target, payload, header)
		if conflict {
			if res.Status != http.StatusUnprocessableEntity || hits != 0 || strings.Contains(string(res.Body), conflictVal) {
				ht.Fatalf("conflict allow %v status %d hits %d body %s", allow, res.Status, hits, res.Body)
			}
			return
		}
		if unknown && !allow {
			var problem struct {
				Detail string `json:"detail"`
			}
			if err := res.JSON(&problem); err != nil {
				ht.Fatal(err)
			}
			if res.Status != http.StatusBadRequest || hits != 0 || !strings.Contains(problem.Detail, "unknown object member name "+strconv.Quote(unknownName)) {
				ht.Fatalf("unknown status %d hits %d detail %q", res.Status, hits, problem.Detail)
			}
			return
		}
		want := trans
		switch fix.source {
		case "dependency":
			want = reviewDepValue
		case "query", "header", "cookie":
			if !present {
				want = "fallback"
			}
		}
		if res.Status != http.StatusOK || hits != 1 {
			ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
		}
		var got reviewSeen
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.Title != title || got.Slot != want {
			ht.Fatalf("got %#v title %q slot %q", got, title, want)
		}
	})
}

func reviewMount(app *gfast.App, base int, allow bool, hits *int) {
	switch base {
	case 0:
		if allow {
			app.Post("/own/{id}", reviewHandle(hits, func(in *reviewPathAllow) (string, string) { return in.Title, in.ID }))
		} else {
			app.Post("/own/{id}", reviewHandle(hits, func(in *reviewPath) (string, string) { return in.Title, in.ID }))
		}
	case 1:
		if allow {
			app.Post("/own/{id}", reviewHandle(hits, func(in *reviewPathAliasAllow) (string, string) { return in.Title, in.ID }))
		} else {
			app.Post("/own/{id}", reviewHandle(hits, func(in *reviewPathAlias) (string, string) { return in.Title, in.ID }))
		}
	case 2:
		if allow {
			app.Post("/own", reviewHandle(hits, func(in *reviewQueryAllow) (string, string) { return in.Title, in.Q }))
		} else {
			app.Post("/own", reviewHandle(hits, func(in *reviewQuery) (string, string) { return in.Title, in.Q }))
		}
	case 3:
		if allow {
			app.Post("/own", reviewHandle(hits, func(in *reviewHeaderAllow) (string, string) { return in.Title, in.Flag }))
		} else {
			app.Post("/own", reviewHandle(hits, func(in *reviewHeader) (string, string) { return in.Title, in.Flag }))
		}
	case 4:
		if allow {
			app.Post("/own", reviewHandle(hits, func(in *reviewCookieAllow) (string, string) { return in.Title, in.Sid }))
		} else {
			app.Post("/own", reviewHandle(hits, func(in *reviewCookie) (string, string) { return in.Title, in.Sid }))
		}
	case 5:
		if allow {
			app.Post("/own/{id}", reviewHandle(hits, func(in *reviewEmbedAllow) (string, string) { return in.Title, in.ID }))
		} else {
			app.Post("/own/{id}", reviewHandle(hits, func(in *reviewEmbedIn) (string, string) { return in.Title, in.ID }))
		}
	case 6:
		if allow {
			app.Post("/own/{id}", reviewHandle(hits, func(in *reviewEmbedAliasAllow) (string, string) { return in.Title, in.ID }))
		} else {
			app.Post("/own/{id}", reviewHandle(hits, func(in *reviewEmbedAliasIn) (string, string) { return in.Title, in.ID }))
		}
	case 7:
		if allow {
			app.Post("/own/{id}", reviewHandle(hits, func(in *reviewPtrAllow) (string, string) { return in.Title, in.ID }))
		} else {
			app.Post("/own/{id}", reviewHandle(hits, func(in *reviewPtrIn) (string, string) { return in.Title, in.ID }))
		}
	case 8:
		if allow {
			app.Post("/own", reviewHandle(hits, func(in *reviewDepAllow) (string, string) { return in.Title, in.User.Value }))
		} else {
			app.Post("/own", reviewHandle(hits, func(in *reviewDepIn) (string, string) { return in.Title, in.User.Value }))
		}
	default:
		if allow {
			app.Post("/own", reviewHandle(hits, func(in *reviewDepAliasAllow) (string, string) { return in.Title, in.User.Value }))
		} else {
			app.Post("/own", reviewHandle(hits, func(in *reviewDepAliasIn) (string, string) { return in.Title, in.User.Value }))
		}
	}
}

func reviewHandle[I any](hits *int, read func(*I) (string, string)) func(context.Context, *I) (*reviewSeen, error) {
	return func(ctx context.Context, in *I) (*reviewSeen, error) {
		*hits++
		title, slot := read(in)
		return &reviewSeen{Title: title, Slot: slot}, nil
	}
}

func reviewChain(depth int, base string) (*reviewNode, []byte) {
	var head, tail *reviewNode
	for i := 0; i <= depth; i++ {
		n := &reviewNode{Name: base + strconv.Itoa(i)}
		if head == nil {
			head = n
		} else {
			tail.Next = n
		}
		tail = n
	}
	raw, err := json.Marshal(head)
	if err != nil {
		panic(err)
	}
	return head, raw
}

func reviewMustPanic(ht *hegel.T, kind, typeName string) {
	ht.Helper()
	out, err := reviewCached(kind)
	if strings.Contains(out, "GFAST_RESULT registered") || strings.Contains(strings.ToLower(out), "stack overflow") {
		ht.Fatalf("%s did not stop: %v %s", kind, err, out)
	}
	if err == nil || !strings.Contains(out, "gfast: recursive type") || !strings.Contains(out, typeName) {
		ht.Fatalf("%s panic err %v output %s", kind, err, out)
	}
}

type reviewChildResult struct {
	out string
	err error
}

var reviewChildCache sync.Map

func reviewCached(kind string) (string, error) {
	if v, ok := reviewChildCache.Load(kind); ok {
		got := v.(reviewChildResult)
		return got.out, got.err
	}
	out, err := reviewChild(kind)
	reviewChildCache.Store(kind, reviewChildResult{out: out, err: err})
	return out, err
}

func reviewChild(kind string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReviewRegisterChild$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "GFAST_REVIEW_REGISTER="+kind)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestReviewRegisterChild(t *testing.T) {
	kind := os.Getenv("GFAST_REVIEW_REGISTER")
	if kind == "" {
		t.Skip()
		return
	}
	app := gfast.New()
	switch kind {
	case "self":
		app.Post("/n", func(ctx context.Context, in *reviewNode) (*reviewNode, error) { return in, nil })
	case "mutual":
		app.Post("/n", func(ctx context.Context, in *reviewA) (*struct{}, error) { return &struct{}{}, nil })
	default:
		t.Fatalf("kind %s", kind)
	}
	fmtReview("registered")
}

func fmtReview(s string) {
	_, _ = os.Stdout.WriteString("GFAST_RESULT " + s + "\n")
}

// reviewWSCloser is closed once when a WebSocket upgrade finishes, including
// a rejected Origin. The handler must not run in that case.
type reviewWSCloser struct{}

func (reviewWSCloser) Close() error {
	reviewWSCloses.Add(1)
	return nil
}

var reviewWSCloses atomic.Int32

var reviewWSRes = gfast.Dep("reviewWSRes", func(ctx context.Context) (reviewWSCloser, error) {
	return reviewWSCloser{}, nil
})

type reviewWSIn struct {
	Res reviewWSCloser `gfast:"dep=reviewWSRes"`
}

// TestIssue3ForeignWebSocketOrigin is the minimal counterexample from issue 3:
// a real TCP handshake with Origin https://evil.example must not get 101.
// A signed session cookie, CORS allowing that origin, and a trusted request
// host do not authorize it. SameSite is not what the raw handshake checks.
func TestIssue3ForeignWebSocketOrigin(t *testing.T) {
	mustPanic(t, "requires a host", func() { gfast.New(gfast.WebSocketOrigins()) })
	mustPanic(t, "empty", func() { gfast.New(gfast.WebSocketOrigins("  ")) })
	mustPanic(t, "bad", func() { gfast.New(gfast.WebSocketOrigins("null")) })
	mustPanic(t, "bad", func() { gfast.New(gfast.WebSocketOrigins("https://evil.example/x")) })
	mustPanic(t, "bad", func() { gfast.New(gfast.WebSocketOrigins("ftp://evil.example")) })
	mustPanic(t, "bad", func() { gfast.New(gfast.WebSocketOrigins("example.com:99999")) })

	var hits atomic.Int32
	base, stop := reviewWSServer(t, &hits, true, []gfast.Option{
		gfast.CORS("https://evil.example"),
		gfast.AllowCredentials(true),
		gfast.TrustedHost("app.example", "::1"),
	})
	defer stop()
	cookie := reviewLogin(t, base, "app.example")
	meStatus, _, meBody := reviewHTTP(t, http.MethodGet, base, "app.example", "/me", cookie, nil)
	if meStatus != http.StatusOK || !strings.Contains(string(meBody), `"ada"`) {
		t.Fatalf("session probe %d %s", meStatus, meBody)
	}

	// Issue 3 probe: foreign Origin on a valid upgrade. CORS echoes it.
	reviewOneWS(t, &hits, base, "app.example", []string{"https://evil.example"}, cookie, http.StatusForbidden, false, true)

	cases := []struct {
		name   string
		host   string
		origin []string
		cookie bool
		want   int
		echo   bool
		cors   bool
	}{
		{name: "absent", host: "app.example", cookie: true, want: http.StatusSwitchingProtocols, echo: true},
		{name: "default port", host: "App.Example", origin: []string{"https://app.example:443"}, want: http.StatusSwitchingProtocols, echo: true},
		{name: "either default port", host: "app.example:443", origin: []string{"http://app.example:80"}, want: http.StatusSwitchingProtocols, echo: true},
		{name: "leading zero", host: "app.example:080", origin: []string{"https://APP.example"}, want: http.StatusSwitchingProtocols, echo: true},
		{name: "nondefault port", host: "app.example", origin: []string{"http://app.example:8080"}, want: http.StatusForbidden},
		{name: "null", host: "app.example", origin: []string{"null"}, cookie: true, want: http.StatusForbidden},
		{name: "NULL", host: "app.example", origin: []string{"NULL"}, want: http.StatusForbidden},
		{name: "path", host: "app.example", origin: []string{"https://app.example/x"}, want: http.StatusForbidden},
		{name: "userinfo", host: "app.example", origin: []string{"https://user@app.example"}, want: http.StatusForbidden},
		{name: "ftp", host: "app.example", origin: []string{"ftp://app.example"}, want: http.StatusForbidden},
		{name: "ws scheme", host: "app.example", origin: []string{"ws://app.example"}, want: http.StatusForbidden},
		{name: "ipv6 default", host: "[::1]:443", origin: []string{"http://[::1]:80"}, want: http.StatusSwitchingProtocols, echo: true},
		{name: "ipv6 port", host: "[::1]:8080", origin: []string{"https://[::1]"}, want: http.StatusForbidden},
		{name: "duplicate origin", host: "app.example", origin: []string{"https://app.example", "https://app.example"}, want: http.StatusForbidden},
		{name: "subdomain", host: "app.example", origin: []string{"https://a.app.example"}, cookie: true, want: http.StatusForbidden},
		{name: "untrusted host", host: "evil.example", origin: []string{"https://evil.example"}, want: http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ck := ""
			if tc.cookie {
				ck = cookie
			}
			reviewOneWS(t, &hits, base, tc.host, tc.origin, ck, tc.want, tc.echo, tc.cors)
		})
	}

	allowed, stopAllowed := reviewWSServer(t, &hits, true, []gfast.Option{
		gfast.CORS("https://evil.example"),
		gfast.AllowCredentials(true),
		gfast.TrustedHost("app.example", "::1"),
		gfast.WebSocketOrigins("https://evil.example", "app.example:8443"),
	})
	defer stopAllowed()
	reviewOneWS(t, &hits, allowed, "app.example:8080", []string{"https://EVIL.example:443"}, cookie, http.StatusSwitchingProtocols, true, false)
	reviewOneWS(t, &hits, allowed, "app.example", []string{"https://a.evil.example"}, "", http.StatusForbidden, false, false)
	reviewOneWS(t, &hits, allowed, "app.example", []string{"https://app.example:8443"}, "", http.StatusSwitchingProtocols, true, false)
	reviewOneWS(t, &hits, allowed, "app.example:8443", []string{"https://app.example"}, "", http.StatusForbidden, false, false)

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()
	reviewWSCloses.Store(0)
	hits.Store(0)
	for i := 0; i < 30; i++ {
		reviewOneWS(t, &hits, base, "app.example", []string{"https://evil.example"}, cookie, http.StatusForbidden, false, true)
	}
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+8 {
		t.Fatalf("goroutines %d to %d", before, after)
	}
}

func TestPropWebSocketOrigin(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		reqLabel := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(3))
		originLabel := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(3))
		allowLabel := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(3))
		reqKind := hegel.Draw(ht, hegel.Integers(0, 4))
		originKind := hegel.Draw(ht, hegel.Integers(0, 4))
		allowKind := hegel.Draw(ht, hegel.Integers(0, 4))
		reqPort := []string{"", "80", "443", "8080", "8443", "080"}[hegel.Draw(ht, hegel.Integers(0, 5))]
		originPort := []string{"", "80", "443", "8080", "8443", "080", "08080", "99999", "abc"}[hegel.Draw(ht, hegel.Integers(0, 8))]
		allowPort := []string{"", "443", "8443", "8080", "080"}[hegel.Draw(ht, hegel.Integers(0, 4))]
		scheme := []string{"http", "https", "HTTP", "ws", "ftp"}[hegel.Draw(ht, hegel.Integers(0, 4))]
		reqFold := hegel.Draw(ht, hegel.Booleans())
		originFold := hegel.Draw(ht, hegel.Booleans())
		reqDot := hegel.Draw(ht, hegel.Booleans())
		originDot := hegel.Draw(ht, hegel.Booleans())
		absent := hegel.Draw(ht, hegel.Booleans())
		nullOrigin := hegel.Draw(ht, hegel.Booleans())
		nullWord := []string{"null", "NULL"}[hegel.Draw(ht, hegel.Integers(0, 1))]
		junk := hegel.Draw(ht, hegel.Integers(0, 4)) // 0 none, 1 path, 2 userinfo, 3 fragment, 4 query
		multi := hegel.Draw(ht, hegel.Booleans())
		nAllow := hegel.Draw(ht, hegel.Integers(0, 2))
		form0 := hegel.Draw(ht, hegel.Integers(0, 5))
		form1 := hegel.Draw(ht, hegel.Integers(0, 5))
		sessionOn := hegel.Draw(ht, hegel.Booleans())
		corsMode := hegel.Draw(ht, hegel.Integers(0, 3))
		trustedMode := hegel.Draw(ht, hegel.Integers(0, 2))
		payload := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))

		reqName := reviewWSName(reqLabel, reqKind, reqFold, reqDot)
		originName := reviewWSName(originLabel, originKind, originFold, originDot)
		allowName := reviewWSName(allowLabel, allowKind, false, false)
		hostHeader := reviewJoinHost(reqName, reqPort)
		built := reviewBuildOrigin(scheme, originName, originPort, junk)
		var origins []string
		if !absent {
			raw := built
			if nullOrigin {
				raw = nullWord
			}
			origins = append(origins, raw)
			if multi {
				origins = append(origins, raw)
			}
		}
		allowA := reviewAllowRaw(allowName, allowPort, form0)
		allowB := reviewAllowRaw(allowName, allowPort, form1)
		allows := []string{allowA, allowB}[:nAllow]
		for _, raw := range allows {
			if reviewConfigHost(raw) == "" {
				ht.Fatalf("allow %q does not canonicalize", raw)
			}
		}
		originValue := ""
		if len(origins) == 1 {
			originValue = origins[0]
		}
		hostOK := reviewHostOK(hostHeader, originValue, len(origins) > 1, allows)
		trustedReject := trustedMode == 2
		if trustedMode == 1 && reviewTrustName(hostHeader) == "" {
			ht.Fatalf("host %q", hostHeader)
		}

		var opts []gfast.Option
		if len(allows) > 0 {
			opts = append(opts, gfast.WebSocketOrigins(allows...))
		}
		switch corsMode {
		case 1:
			opts = append(opts, gfast.CORS())
		case 2:
			listed := originValue
			if listed == "" {
				listed = "https://unused.example"
			}
			opts = append(opts, gfast.CORS(listed))
		case 3:
			opts = append(opts, gfast.CORS("https://evil.example"), gfast.AllowCredentials(true))
		}
		switch trustedMode {
		case 1:
			opts = append(opts, gfast.TrustedHost(reviewTrustName(hostHeader)))
		case 2:
			opts = append(opts, gfast.TrustedHost("blocked.example"))
		}

		var hits atomic.Int32
		base, stop := reviewWSServer(ht, &hits, sessionOn, opts)
		defer stop()
		cookie := ""
		if sessionOn && !trustedReject {
			cookie = reviewLogin(ht, base, hostHeader)
			meStatus, _, meBody := reviewHTTP(ht, http.MethodGet, base, hostHeader, "/me", cookie, nil)
			if meStatus != http.StatusOK || !strings.Contains(string(meBody), `"ada"`) {
				ht.Fatalf("session %d %s host %q", meStatus, meBody, hostHeader)
			}
		}
		want := http.StatusForbidden
		echo := false
		switch {
		case trustedReject:
			want = http.StatusBadRequest
		case hostOK:
			want = http.StatusSwitchingProtocols
			echo = true
		}
		header := make(http.Header)
		for _, origin := range origins {
			header.Add("Origin", origin)
		}
		reviewWSCloses.Store(0)
		hits.Store(0)
		status, resHeader, body, conn := reviewHandshake(ht, base, hostHeader, "/ws", cookie, header)
		if conn != nil {
			defer conn.Close()
		}
		if status == http.StatusSwitchingProtocols && !echo {
			ht.Fatalf("101 for host %q origin %q allows %q session %v cors %d trusted %d", hostHeader, origins, allows, sessionOn, corsMode, trustedMode)
		}
		if status != want {
			ht.Fatalf("status %d want %d host %q origin %q allows %q body %s", status, want, hostHeader, origins, allows, body)
		}
		if echo {
			reviewEcho(ht, conn, payload)
			if hits.Load() != 1 {
				ht.Fatalf("hits %d", hits.Load())
			}
			reviewWaitCloses(ht, 1)
			return
		}
		if hits.Load() != 0 {
			ht.Fatalf("handler ran status %d body %s", status, body)
		}
		if want == http.StatusForbidden {
			reviewProblem(ht, resHeader, body, wsReviewDetail)
			if reviewCORSEcho(corsMode, originValue) {
				if got := resHeader.Get("Access-Control-Allow-Origin"); got != originValue {
					ht.Fatalf("cors %q origin %q", got, originValue)
				}
			}
			reviewWaitCloses(ht, 1)
			return
		}
		if !strings.Contains(string(body), "Invalid host header") {
			ht.Fatalf("trusted body %s", body)
		}
		reviewWaitCloses(ht, 0)
	})
}

const wsReviewDetail = "websocket origin rejected"

func reviewWSServer(t testFail, hits *atomic.Int32, sessions bool, extra []gfast.Option) (string, func()) {
	t.Helper()
	opts := append([]gfast.Option{}, extra...)
	if sessions {
		opts = append([]gfast.Option{gfast.Sessions(gfast.SessionConfig{Secret: "review-ws-secret"})}, opts...)
	}
	app := gfast.New(opts...)
	if sessions {
		app.Post("/login", func(ctx context.Context, in *struct{}) (*struct {
			OK bool `json:"ok"`
		}, error) {
			gfast.SessionFrom(ctx)["user"] = "ada"
			return &struct {
				OK bool `json:"ok"`
			}{OK: true}, nil
		})
		app.Get("/me", func(ctx context.Context, in *struct{}) (*struct {
			User string `json:"user"`
		}, error) {
			user, _ := gfast.SessionFrom(ctx)["user"].(string)
			return &struct {
				User string `json:"user"`
			}{User: user}, nil
		})
	}
	app.WebSocket("/ws", func(ctx context.Context, in *reviewWSIn) error {
		hits.Add(1)
		if sessions {
			if c, err := gfast.RequestFrom(ctx).Cookie("session"); err == nil && c.Value != "" {
				user, _ := gfast.SessionFrom(ctx)["user"].(string)
				if user != "ada" {
					return gfast.Forbidden("session user")
				}
			}
		}
		conn := gfast.ConnFrom(ctx)
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		return conn.Write(ctx, typ, data)
	})
	srv := httptest.NewServer(app.Handler())
	return srv.URL, srv.Close
}

func reviewOneWS(t *testing.T, hits *atomic.Int32, base, host string, origins []string, cookie string, want int, echo, cors bool) {
	t.Helper()
	reviewWSCloses.Store(0)
	hits.Store(0)
	header := make(http.Header)
	for _, origin := range origins {
		header.Add("Origin", origin)
	}
	status, resHeader, body, conn := reviewHandshake(t, base, host, "/ws", cookie, header)
	if conn != nil {
		defer conn.Close()
	}
	if status == http.StatusSwitchingProtocols && want != http.StatusSwitchingProtocols {
		t.Fatalf("101 host %q origin %q body %s", host, origins, body)
	}
	if status != want {
		t.Fatalf("status %d want %d host %q origin %q body %s", status, want, host, origins, body)
	}
	if echo {
		reviewEcho(t, conn, "hi")
		if hits.Load() != 1 {
			t.Fatalf("hits %d", hits.Load())
		}
		reviewWaitCloses(t, 1)
		return
	}
	if hits.Load() != 0 {
		t.Fatalf("handler ran status %d", status)
	}
	if want == http.StatusForbidden {
		reviewProblem(t, resHeader, body, wsReviewDetail)
		if cors {
			if got := resHeader.Get("Access-Control-Allow-Origin"); len(origins) != 1 || got != origins[0] {
				t.Fatalf("cors %q origin %q", got, origins)
			}
		}
		reviewWaitCloses(t, 1)
		return
	}
	if want == http.StatusBadRequest && !strings.Contains(string(body), "Invalid host header") {
		t.Fatalf("body %s", body)
	}
	reviewWaitCloses(t, 0)
}

func reviewLogin(t testFail, base, host string) string {
	t.Helper()
	status, header, body := reviewHTTP(t, http.MethodPost, base, host, "/login", "", nil)
	if status != http.StatusOK {
		t.Fatalf("login %d %s", status, body)
	}
	cookies := (&http.Response{Header: header}).Cookies()
	for _, c := range cookies {
		if c.Name == "session" && c.Value != "" {
			return c.Value
		}
	}
	t.Fatalf("login cookies %v", header)
	return ""
}

func reviewHTTP(t testFail, method, base, host, path, cookie string, header http.Header) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	if cookie != "" {
		req.Header.Set("Cookie", "session="+cookie)
	}
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	res, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, res.Header.Clone(), body
}

func reviewHandshake(t testFail, base, host, path, cookie string, extra http.Header) (int, http.Header, []byte, net.Conn) {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp", hostPort(base))
	if err != nil {
		t.Fatal(err)
	}
	fail := true
	defer func() {
		if fail {
			conn.Close()
		}
	}()
	var b strings.Builder
	fmtHeader(&b, "GET "+path+" HTTP/1.1")
	fmtHeader(&b, "Host: "+host)
	fmtHeader(&b, "Upgrade: websocket")
	fmtHeader(&b, "Connection: Upgrade")
	fmtHeader(&b, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==")
	fmtHeader(&b, "Sec-WebSocket-Version: 13")
	if cookie != "" {
		fmtHeader(&b, "Cookie: session="+cookie)
	}
	for name, values := range extra {
		for _, value := range values {
			fmtHeader(&b, name+": "+value)
		}
	}
	b.WriteString("\r\n")
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode == http.StatusSwitchingProtocols {
		if res.Header.Get("Sec-WebSocket-Accept") != acceptOf("dGhlIHNhbXBsZSBub25jZQ==") {
			t.Fatalf("accept %q", res.Header.Get("Sec-WebSocket-Accept"))
		}
		if res.Header.Get("Sec-WebSocket-Extensions") != "" {
			t.Fatal("extension accepted")
		}
		_ = conn.SetDeadline(time.Time{})
		fail = false
		return res.StatusCode, res.Header.Clone(), nil, &prefixConn{Conn: conn, r: br}
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, res.Header.Clone(), body, nil
}

func reviewEcho(t testFail, conn net.Conn, payload string) {
	t.Helper()
	writeMasked(t, conn, true, 0x1, []byte(payload), true)
	fin, op, got := readUnmasked(t, conn)
	if !fin || op != 0x1 || string(got) != payload {
		t.Fatalf("echo fin %v op %d %q", fin, op, got)
	}
}

func reviewProblem(t testFail, header http.Header, body []byte, detail string) {
	t.Helper()
	if header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("type %q body %s", header.Get("Content-Type"), body)
	}
	var prob struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &prob); err != nil {
		t.Fatal(err)
	}
	if prob.Status != http.StatusForbidden || prob.Title != http.StatusText(http.StatusForbidden) || prob.Detail != detail {
		t.Fatalf("problem %+v", prob)
	}
}

func reviewWaitCloses(t testFail, want int32) {
	t.Helper()
	if want == 0 {
		time.Sleep(20 * time.Millisecond)
		if got := reviewWSCloses.Load(); got != 0 {
			t.Fatalf("closes %d", got)
		}
		return
	}
	deadline := time.Now().Add(time.Second)
	for reviewWSCloses.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("closes %d want %d", reviewWSCloses.Load(), want)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func reviewWSName(label string, kind int, fold, dot bool) string {
	var name string
	switch kind {
	case 0:
		name = label + ".example"
	case 1:
		name = "evil.example"
	case 2:
		name = "a." + label + ".example"
	case 3:
		name = "app.example"
	default:
		name = "::1"
	}
	if dot && !strings.Contains(name, ":") {
		name += "."
	}
	if fold {
		name = strings.ToUpper(name)
	}
	return name
}

func reviewJoinHost(name, port string) string {
	host := name
	if strings.Contains(name, ":") {
		host = "[" + name + "]"
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

func reviewBuildOrigin(scheme, name, port string, junk int) string {
	host := reviewJoinHost(name, port)
	if junk == 2 {
		host = "user@" + host
	}
	raw := scheme + "://" + host
	switch junk {
	case 1:
		raw += "/x"
	case 3:
		raw += "#f"
	case 4:
		raw += "?q=1"
	}
	return raw
}

func reviewAllowRaw(name, port string, form int) string {
	host := name
	if strings.Contains(name, ":") {
		host = "[" + name + "]"
	}
	switch form {
	case 0:
		if port == "" {
			return host
		}
		return host + ":" + port
	case 1:
		return host + ":443"
	case 2:
		return "https://" + host
	case 3:
		return "https://" + host + ":443"
	case 4:
		return "http://" + host + ":80"
	default:
		return "https://" + host + ":8443"
	}
}

// reviewHostOK is the origin rule for the property: a missing Origin is
// allowed, and a browser Origin is allowed when its canonical host equals
// the request host or a configured host. Ports 80 and 443 are not part of
// that host. A session cookie is not an input.
func reviewHostOK(requestHost, origin string, multi bool, allows []string) bool {
	if multi {
		return false
	}
	if strings.TrimSpace(origin) == "" {
		return true
	}
	got, ok := reviewOriginHost(origin)
	if !ok {
		return false
	}
	if req, ok := reviewCanonical(requestHost); ok && req == got {
		return true
	}
	for _, raw := range allows {
		if reviewConfigHost(raw) == got {
			return true
		}
	}
	return false
}

func reviewOriginHost(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "null") || strings.ContainsAny(raw, " \t\r\n\\") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Opaque != "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", false
	}
	if strings.Contains(u.Host, "%") {
		return "", false
	}
	return reviewCanonical(u.Host)
}

func reviewConfigHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.EqualFold(raw, "null") {
		return ""
	}
	if strings.Contains(raw, "://") {
		host, ok := reviewOriginHost(raw)
		if !ok {
			return ""
		}
		return host
	}
	host, ok := reviewCanonical(raw)
	if !ok {
		return ""
	}
	return host
}

func reviewCanonical(hostport string) (string, bool) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" || strings.ContainsAny(hostport, " /?#@\\") {
		return "", false
	}
	host := hostport
	port := ""
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, p
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		host = hostport[1 : len(hostport)-1]
	} else if strings.Count(hostport, ":") > 0 {
		return "", false
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || strings.ContainsAny(host, " /?#@\\[]") {
		return "", false
	}
	if port == "" {
		return host, true
	}
	if len(port) > 5 {
		return "", false
	}
	n := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return "", false
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 || n > 65535 {
		return "", false
	}
	if n == 80 || n == 443 {
		return host, true
	}
	if strings.Contains(host, ":") {
		return net.JoinHostPort(host, fmt.Sprintf("%d", n)), true
	}
	return host + ":" + fmt.Sprintf("%d", n), true
}

func reviewTrustName(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = h
	} else if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		hostport = hostport[1 : len(hostport)-1]
	}
	return strings.TrimSuffix(strings.ToLower(hostport), ".")
}

func reviewCORSEcho(mode int, origin string) bool {
	switch mode {
	case 1:
		return strings.TrimSpace(origin) != ""
	case 2:
		return strings.TrimSpace(origin) != ""
	case 3:
		return origin == "https://evil.example"
	default:
		return false
	}
}

// reviewQRows is the quality oracle for one Accept-Encoding parameter list.
// The bool is whether that coding is acceptable. It is not the production scan:
// a missing parameter means quality 1, the first q wins, a q above 1 stays
// acceptable, and a negative or non-numeric q is not.
var reviewQRows = []struct {
	param string
	ok    bool
}{
	{param: "", ok: true},
	{param: "q=1", ok: true},
	{param: "q=0.8", ok: true},
	{param: "q=0.001", ok: true},
	{param: "q=1.0", ok: true},
	{param: "q=1.5", ok: true},
	{param: "q=2", ok: true},
	{param: "Q=0.5", ok: true},
	{param: "q=1;q=0", ok: true},
	{param: "x=1", ok: true},
	{param: "x=1;q=0.2", ok: true},
	{param: "q=inf", ok: true},
	{param: "q=0", ok: false},
	{param: "q=0.0", ok: false},
	{param: "q=0.000", ok: false},
	{param: "q=+0", ok: false},
	{param: "q=-1", ok: false},
	{param: "q=-0.1", ok: false},
	{param: "q=nope", ok: false},
	{param: "q=", ok: false},
	{param: "q=1.2.3", ok: false},
	{param: "q=0;q=1", ok: false},
	{param: "q=NaN", ok: false},
	{param: "q=-Inf", ok: false},
}

// reviewGzipDecision is gzip precedence.
// Rows: gzip absent, gzip listed but unacceptable, gzip listed and acceptable.
// Columns: "*" not acceptable, "*" acceptable.
// An explicit gzip row ignores the wildcard, so gzip;q=0 loses to nothing.
var reviewGzipDecision = [3][2]bool{
	{false, true},
	{false, false},
	{true, true},
}

var reviewGzipPads = []string{"", " ", "  ", "\t"}

var reviewOtherCodings = []string{"identity", "deflate", "br", "compress"}

func reviewGzipWant(gzipSeen, gzipOK, starOK bool) bool {
	g := 0
	if gzipSeen {
		g = 1
		if gzipOK {
			g = 2
		}
	}
	s := 0
	if starOK {
		s = 1
	}
	return reviewGzipDecision[g][s]
}

func reviewPad(ht *hegel.T) string {
	return reviewGzipPads[hegel.Draw(ht, hegel.Integers(0, len(reviewGzipPads)-1))]
}

func reviewVaryCase(ht *hegel.T, name string) string {
	if name == "*" {
		return name
	}
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' && hegel.Draw(ht, hegel.Booleans()) {
			c = c - 'a' + 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func reviewGzipToken(ht *hegel.T, name, param string) string {
	shown := reviewVaryCase(ht, name)
	if param == "" {
		return reviewPad(ht) + shown + reviewPad(ht)
	}
	return reviewPad(ht) + shown + reviewPad(ht) + ";" + reviewPad(ht) + param + reviewPad(ht)
}

// reviewGzipApp serves a fixed plain body and the responses gzip must not encode.
func reviewGzipApp(plain string) *gfast.App {
	app := gfast.New(gfast.Gzip())
	app.Get("/body", func(ctx context.Context, in *struct{}) (*string, error) {
		gfast.ResponseFrom(ctx).SetContentType("text/plain")
		s := plain
		return &s, nil
	})
	app.Get("/empty", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		return nil, nil
	})
	app.Get("/mod", func(ctx context.Context, in *struct{}) (*string, error) {
		gfast.ResponseFrom(ctx).SetStatus(http.StatusNotModified)
		gfast.ResponseFrom(ctx).SetContentType("text/plain")
		s := plain
		return &s, nil
	})
	app.Get("/events", func(ctx context.Context, in *struct{}) (*gfast.Events, error) {
		return gfast.SSE(func(ctx context.Context, send func(gfast.Event) error) error {
			return send(gfast.Event{Data: plain})
		}), nil
	})
	app.Get("/raw", func(ctx context.Context, in *struct{}) (*string, error) {
		gfast.ResponseFrom(ctx).SetContentType("application/octet-stream")
		gfast.ResponseFrom(ctx).Header().Set("Content-Encoding", "deflate")
		s := plain
		return &s, nil
	})
	return app
}

func reviewGzipClient() *http.Client {
	return &http.Client{Transport: &http.Transport{DisableCompression: true}}
}

func reviewGzipDo(t testing.TB, client *http.Client, method, rawURL string, accept *string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if accept != nil {
		req.Header.Set("Accept-Encoding", *accept)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode, res.Header.Clone(), body
}

func reviewExpectGzip(t testing.TB, client *http.Client, method, rawURL string, accept *string, wantGzip bool, status int, plain string, encoding string) {
	t.Helper()
	gotStatus, header, body := reviewGzipDo(t, client, method, rawURL, accept)
	if gotStatus != status {
		t.Fatalf("status %d want %d accept %q body %q", gotStatus, status, reviewAccept(accept), body)
	}
	if wantGzip {
		decoded, err := pendGunzip(body)
		if err != nil {
			t.Fatalf("gunzip accept %q: %v body %q", reviewAccept(accept), err, body)
		}
		if header.Get("Content-Encoding") != "gzip" || !strings.Contains(header.Get("Vary"), "Accept-Encoding") || string(decoded) != plain {
			t.Fatalf("gzip enc %q vary %q body %q accept %q", header.Get("Content-Encoding"), header.Get("Vary"), decoded, reviewAccept(accept))
		}
		return
	}
	if header.Get("Content-Encoding") != encoding || string(body) != plain {
		t.Fatalf("plain enc %q want %q body %q want %q accept %q", header.Get("Content-Encoding"), encoding, body, plain, reviewAccept(accept))
	}
}

func reviewAccept(accept *string) string {
	if accept == nil {
		return "<missing>"
	}
	return *accept
}

func reviewPtr(s string) *string { return &s }

// TestIssue8ExplicitGzipBeatsWildcard is the minimal counterexample from
// issue 8: gzip;q=0, *;q=1 must not be compressed.
func TestIssue8ExplicitGzipBeatsWildcard(t *testing.T) {
	const plain = "handler-bytes"
	app := reviewGzipApp(plain)
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	client := reviewGzipClient()
	body := srv.URL + "/body"
	events := "data: " + plain + "\n\n"

	reviewExpectGzip(t, client, http.MethodGet, body, reviewPtr("gzip;q=0, *;q=1"), false, http.StatusOK, plain, "")
	reviewExpectGzip(t, client, http.MethodGet, body, reviewPtr("*"), true, http.StatusOK, plain, "")
	reviewExpectGzip(t, client, http.MethodGet, body, reviewPtr("*;q=1"), true, http.StatusOK, plain, "")
	reviewExpectGzip(t, client, http.MethodGet, body, reviewPtr("gzip"), true, http.StatusOK, plain, "")
	reviewExpectGzip(t, client, http.MethodGet, body, reviewPtr("gzip;q=0, gzip;q=0.4"), true, http.StatusOK, plain, "")
	reviewExpectGzip(t, client, http.MethodGet, body, reviewPtr("gzip;q=0, gzip;q=0"), false, http.StatusOK, plain, "")
	reviewExpectGzip(t, client, http.MethodGet, body, reviewPtr("gzip;q=bogus, *;q=1"), false, http.StatusOK, plain, "")
	reviewExpectGzip(t, client, http.MethodGet, body, reviewPtr("gzip;q=1;q=0"), true, http.StatusOK, plain, "")
	reviewExpectGzip(t, client, http.MethodGet, body, reviewPtr("identity;q=0, *;q=1"), true, http.StatusOK, plain, "")
	reviewExpectGzip(t, client, http.MethodGet, body, nil, false, http.StatusOK, plain, "")
	reviewExpectGzip(t, client, http.MethodHead, body, reviewPtr("gzip"), false, http.StatusOK, "", "")
	reviewExpectGzip(t, client, http.MethodHead, body, reviewPtr("gzip;q=0, *;q=1"), false, http.StatusOK, "", "")
	reviewExpectGzip(t, client, http.MethodGet, srv.URL+"/empty", reviewPtr("gzip"), false, http.StatusNoContent, "", "")
	reviewExpectGzip(t, client, http.MethodGet, srv.URL+"/empty", reviewPtr("gzip;q=0, *;q=1"), false, http.StatusNoContent, "", "")
	// A 304 has no message body on the wire. It must not be claimed as gzip.
	reviewExpectGzip(t, client, http.MethodGet, srv.URL+"/mod", reviewPtr("gzip"), false, http.StatusNotModified, "", "")
	reviewExpectGzip(t, client, http.MethodGet, srv.URL+"/events", reviewPtr("gzip"), false, http.StatusOK, events, "")
	reviewExpectGzip(t, client, http.MethodGet, srv.URL+"/raw", reviewPtr("gzip"), false, http.StatusOK, plain, "deflate")

	compressed, uncompressed := "gzip", "gzip;q=0, *;q=1"
	yesStatus, yesHeader, yesBody := reviewGzipDo(t, client, http.MethodGet, body, &compressed)
	noStatus, noHeader, noBody := reviewGzipDo(t, client, http.MethodGet, body, &uncompressed)
	yesPlain, err := pendGunzip(yesBody)
	if err != nil {
		t.Fatal(err)
	}
	if yesStatus != http.StatusOK || noStatus != http.StatusOK || string(yesPlain) != plain || string(noBody) != plain {
		t.Fatalf("variants yes %d %q no %d %q", yesStatus, yesPlain, noStatus, noBody)
	}
	if yesHeader.Get("Content-Encoding") != "gzip" || !strings.Contains(yesHeader.Get("Vary"), "Accept-Encoding") || noHeader.Get("Content-Encoding") != "" {
		t.Fatalf("vary yes %q enc %q no enc %q", yesHeader.Get("Vary"), yesHeader.Get("Content-Encoding"), noHeader.Get("Content-Encoding"))
	}
}

// TestPropIssue8AcceptEncoding draws qualities, order, case, whitespace, and
// unrelated codings. The oracle is reviewGzipDecision, not the production loop.
func TestPropIssue8AcceptEncoding(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		text := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MaxSize(24))
		nGzip := hegel.Draw(ht, hegel.Integers(0, 2))
		nStar := hegel.Draw(ht, hegel.Integers(0, 2))
		nOther := hegel.Draw(ht, hegel.Integers(0, 3))
		type tok struct {
			name  string
			param string
		}
		var toks []tok
		gzipSeen := false
		gzipOK := false
		starOK := false
		for i := 0; i < nGzip; i++ {
			row := reviewQRows[hegel.Draw(ht, hegel.Integers(0, len(reviewQRows)-1))]
			toks = append(toks, tok{name: "gzip", param: row.param})
			gzipSeen = true
			if row.ok {
				gzipOK = true
			}
		}
		for i := 0; i < nStar; i++ {
			row := reviewQRows[hegel.Draw(ht, hegel.Integers(0, len(reviewQRows)-1))]
			toks = append(toks, tok{name: "*", param: row.param})
			if row.ok {
				starOK = true
			}
		}
		for i := 0; i < nOther; i++ {
			name := reviewOtherCodings[hegel.Draw(ht, hegel.Integers(0, len(reviewOtherCodings)-1))]
			row := reviewQRows[hegel.Draw(ht, hegel.Integers(0, len(reviewQRows)-1))]
			toks = append(toks, tok{name: name, param: row.param})
		}
		for i := len(toks) - 1; i > 0; i-- {
			j := hegel.Draw(ht, hegel.Integers(0, i))
			toks[i], toks[j] = toks[j], toks[i]
		}
		var b strings.Builder
		for i, token := range toks {
			if i > 0 {
				b.WriteString(reviewPad(ht))
				b.WriteByte(',')
				b.WriteString(reviewPad(ht))
			}
			b.WriteString(reviewGzipToken(ht, token.name, token.param))
		}
		header := b.String()
		want := reviewGzipWant(gzipSeen, gzipOK, starOK)

		app := reviewGzipApp(text)
		srv := httptest.NewServer(app.Handler())
		defer srv.Close()
		reviewExpectGzip(ht, reviewGzipClient(), http.MethodGet, srv.URL+"/body", &header, want, http.StatusOK, text, "")
	})
}

func reviewCSRFReject(skip bool, method, cookie, site string) bool {
	if skip || cookie == "" {
		return false
	}
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	return strings.EqualFold(strings.TrimSpace(site), "cross-site")
}

// reviewWire is the session envelope built by the tests. It is not the
// production type. Exp is Unix milliseconds; a nil Exp has no server deadline.
type reviewWire struct {
	V   int               `json:"v"`
	Exp *int64            `json:"exp,omitempty"`
	D   map[string]string `json:"d,omitempty"`
}

// reviewSignCookie builds a cookie in the documented wire format:
// raw-url base64(JSON) + "." + raw-url base64(HMAC-SHA256(secret, base64 JSON)).
func reviewSignCookie(secret string, payload []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func reviewSignEnv(secret string, env reviewWire) string {
	raw, err := json.Marshal(env)
	if err != nil {
		panic(err)
	}
	return reviewSignCookie(secret, raw)
}

func reviewSplitCookie(value string) (payload, sig []byte, ok bool) {
	encoded, sigEncoded, found := strings.Cut(value, ".")
	if !found || encoded == "" || sigEncoded == "" || strings.Contains(sigEncoded, ".") {
		return nil, nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, false
	}
	sig, err = base64.RawURLEncoding.DecodeString(sigEncoded)
	if err != nil {
		return nil, nil, false
	}
	return payload, sig, true
}

func reviewJoinCookie(payload, sig []byte) string {
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// reviewFlipMAC flips one signature byte. The payload, including any expiry, stays put.
func reviewFlipMAC(value string) (string, bool) {
	payload, sig, ok := reviewSplitCookie(value)
	if !ok || len(sig) == 0 {
		return "", false
	}
	flipped := bytes.Clone(sig)
	flipped[0] ^= 0x01
	if bytes.Equal(flipped, sig) {
		return "", false
	}
	return reviewJoinCookie(payload, flipped), true
}

// reviewFlipExp sets the first non-nine expiry digit to nine.
// The new deadline is later and the original signature is kept.
func reviewFlipExp(value string) (flipped string, oldExp, newExp int64, ok bool) {
	payload, sig, good := reviewSplitCookie(value)
	if !good {
		return "", 0, 0, false
	}
	i := bytes.Index(payload, []byte(`"exp":`))
	if i < 0 {
		return "", 0, 0, false
	}
	j := i + len(`"exp":`)
	k := j
	for k < len(payload) && payload[k] >= '0' && payload[k] <= '9' {
		k++
	}
	if k == j {
		return "", 0, 0, false
	}
	oldExp, err := strconv.ParseInt(string(payload[j:k]), 10, 64)
	if err != nil {
		return "", 0, 0, false
	}
	out := bytes.Clone(payload)
	changed := false
	for p := j; p < k; p++ {
		if out[p] != '9' {
			out[p] = '9'
			changed = true
			break
		}
	}
	if !changed {
		return "", 0, 0, false
	}
	newExp, err = strconv.ParseInt(string(out[j:k]), 10, 64)
	if err != nil || newExp <= oldExp {
		return "", 0, 0, false
	}
	return reviewJoinCookie(out, sig), oldExp, newExp, true
}

// reviewExpiryLive reports whether exp is still in the future at every
// instant in [before, after]. certain is false when that window contains
// the deadline, so a slow request is not a failed case.
func reviewExpiryLive(hasExp bool, exp int64, before, after time.Time) (live, certain bool) {
	if !hasExp {
		return true, true
	}
	if exp > after.UnixMilli() {
		return true, true
	}
	if exp <= before.UnixMilli() {
		return false, true
	}
	return false, false
}

type reviewTB interface {
	Helper()
	Fatalf(string, ...any)
}

func reviewSessionApp(secret string, maxAge int) *gfast.App {
	app := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: secret, MaxAge: maxAge}))
	app.Post("/set", func(ctx context.Context, in *struct {
		V string `query:"v"`
	}) (*struct{}, error) {
		gfast.SessionFrom(ctx)["user"] = in.V
		return &struct{}{}, nil
	})
	app.Post("/clear", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		sess := gfast.SessionFrom(ctx)
		for key := range sess {
			delete(sess, key)
		}
		return nil, nil
	})
	app.Get("/get", func(ctx context.Context, in *struct{}) (*struct {
		User string `json:"user"`
	}, error) {
		user, _ := gfast.SessionFrom(ctx)["user"].(string)
		return &struct {
			User string `json:"user"`
		}{User: user}, nil
	})
	return app
}

func reviewUser(t reviewTB, app *gfast.App, cookie string) string {
	t.Helper()
	header := http.Header{}
	if cookie != "" {
		header.Set("Cookie", "session="+cookie)
	}
	res := app.Request(http.MethodGet, "/get", nil, header)
	if res.Status != http.StatusOK {
		t.Fatalf("status %d body %s", res.Status, res.Body)
	}
	if res.Header.Get("Set-Cookie") != "" {
		t.Fatalf("read set-cookie %q", res.Header.Get("Set-Cookie"))
	}
	var body struct {
		User string `json:"user"`
	}
	if err := res.JSON(&body); err != nil {
		t.Fatalf("json %v body %s", err, res.Body)
	}
	return body.User
}

func reviewSetCookie(t *testing.T, app *gfast.App, cookie, user string) *http.Cookie {
	t.Helper()
	header := http.Header{}
	if cookie != "" {
		header.Set("Cookie", "session="+cookie)
	}
	res := app.Request(http.MethodPost, "/set?v="+url.QueryEscape(user), nil, header)
	if res.Status != http.StatusOK {
		t.Fatalf("set %d %s", res.Status, res.Body)
	}
	cookies := (&http.Response{Header: res.Header}).Cookies()
	if len(cookies) != 1 || cookies[0].Name != "session" || cookies[0].Value == "" {
		t.Fatalf("set cookie %+v", cookies)
	}
	return cookies[0]
}

// TestIssue4CopiedCookieExpires is the minimal counterexample from issue 4:
// MaxAge=1 signed {"user":"alice"} and was still accepted 1.1s later.
func TestIssue4CopiedCookieExpires(t *testing.T) {
	const secret = "test-secret"
	app := reviewSessionApp(secret, 1)
	before := time.Now().UnixMilli()
	issued := reviewSetCookie(t, app, "", "alice")
	after := time.Now().UnixMilli()
	if !issued.HttpOnly || issued.MaxAge != 1 || issued.Path != "/" {
		t.Fatalf("issued cookie %+v", issued)
	}
	payload, _, ok := reviewSplitCookie(issued.Value)
	if !ok {
		t.Fatalf("issued cookie did not split")
	}
	var env reviewWire
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatal(err)
	}
	if env.V != 1 || env.D["user"] != "alice" || env.Exp == nil {
		t.Fatalf("issued envelope %+v", env)
	}
	if *env.Exp < before+1000 || *env.Exp > after+1000 {
		t.Fatalf("deadline %d not within [%d, %d]", *env.Exp, before+1000, after+1000)
	}
	if reviewUser(t, app, issued.Value) != "alice" {
		t.Fatal("fresh MaxAge=1 cookie was rejected")
	}

	// Replay after 1.1s without sleeping: the deadline is issue+1s, and issue was 1.1s ago.
	issue := time.Now().Add(-1100 * time.Millisecond).UnixMilli()
	expiredAt := issue + 1000
	expired := reviewSignEnv(secret, reviewWire{V: 1, Exp: &expiredAt, D: map[string]string{"user": "alice"}})
	if reviewUser(t, app, expired) != "" {
		t.Fatal("copied MaxAge=1 cookie lived past 1.1s")
	}
	now := time.Now().UnixMilli()
	if reviewUser(t, app, reviewSignEnv(secret, reviewWire{V: 1, Exp: &now, D: map[string]string{"user": "alice"}})) != "" {
		t.Fatal("cookie expiring now was accepted")
	}
	later := now + 5000
	future := reviewSignEnv(secret, reviewWire{V: 1, Exp: &later, D: map[string]string{"user": "alice"}})
	if reviewUser(t, app, future) != "alice" {
		t.Fatal("future cookie was rejected")
	}

	legacy, err := json.Marshal(map[string]string{"user": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if reviewUser(t, app, reviewSignCookie(secret, legacy)) != "" {
		t.Fatal("pre-envelope cookie was accepted")
	}
	if reviewUser(t, app, reviewSignEnv(secret, reviewWire{V: 0, Exp: &later, D: map[string]string{"user": "alice"}})) != "" {
		t.Fatal("version 0 was accepted")
	}
	if reviewUser(t, app, reviewSignEnv(secret, reviewWire{V: 2, Exp: &later, D: map[string]string{"user": "alice"}})) != "" {
		t.Fatal("version 2 was accepted")
	}
	badMAC, ok := reviewFlipMAC(future)
	if !ok || reviewUser(t, app, badMAC) != "" {
		t.Fatal("flipped MAC was accepted")
	}
	extended, oldExp, newExp, ok := reviewFlipExp(expired)
	if !ok || newExp <= oldExp || reviewUser(t, app, extended) != "" {
		t.Fatalf("flipped expiry old %d new %d ok %v was accepted", oldExp, newExp, ok)
	}

	browser := reviewSessionApp(secret, 0)
	held := reviewSetCookie(t, browser, "", "alice")
	if held.MaxAge != 0 {
		t.Fatalf("browser cookie %+v", held)
	}
	bare, _, ok := reviewSplitCookie(held.Value)
	if !ok || bytes.Contains(bare, []byte(`"exp"`)) {
		t.Fatalf("browser session stored an expiry %s", bare)
	}
	if reviewUser(t, browser, held.Value) != "alice" {
		t.Fatal("browser session was rejected")
	}
	if reviewUser(t, browser, expired) != "" {
		t.Fatal("browser-session server accepted a past deadline")
	}
	cleared := browser.Request(http.MethodPost, "/clear", nil, http.Header{"Cookie": []string{"session=" + held.Value}})
	if cleared.Status != http.StatusNoContent {
		t.Fatalf("clear %d %s", cleared.Status, cleared.Body)
	}
	gone := (&http.Response{Header: cleared.Header}).Cookies()
	if len(gone) != 1 || gone[0].MaxAge >= 0 || gone[0].Value != "" {
		t.Fatalf("logout cookie %+v", gone)
	}
	if reviewUser(t, browser, held.Value) != "alice" {
		t.Fatal("logout revoked a copy the client kept")
	}

	live := reviewSessionApp(secret, 30)
	first := reviewSetCookie(t, live, "", "alice")
	second := reviewSetCookie(t, live, first.Value, "bob")
	if reviewUser(t, live, first.Value) != "alice" || reviewUser(t, live, second.Value) != "bob" {
		t.Fatal("replacing the session revoked the previous cookie")
	}
	out := live.Request(http.MethodPost, "/clear", nil, http.Header{"Cookie": []string{"session=" + second.Value}})
	wiped := (&http.Response{Header: out.Header}).Cookies()
	if out.Status != http.StatusNoContent || len(wiped) != 1 || wiped[0].MaxAge >= 0 || wiped[0].Value != "" {
		t.Fatalf("clear status %d cookies %+v", out.Status, wiped)
	}
	if reviewUser(t, live, first.Value) != "alice" || reviewUser(t, live, second.Value) != "bob" {
		t.Fatal("logout revoked a cookie the client kept")
	}
}

// TestPropIssue4SessionExpiry draws a lifetime and how far the clock moves.
// Envelopes are built at those timestamps. Nothing sleeps.
// A deadline still in the future loads. A deadline at now or earlier does not.
// A flipped MAC byte or a flipped expiry byte does not extend that life.
func TestPropIssue4SessionExpiry(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		lifetime := hegel.Draw(ht, hegel.Integers(0, 20))
		move := hegel.Draw(ht, hegel.Integers(-5, 30))
		tamper := hegel.Draw(ht, hegel.Integers(0, 2))
		secret := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		user := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))

		before := time.Now()
		var exp *int64
		if lifetime > 0 {
			ms := before.UnixMilli() + int64(lifetime-move)*1000
			exp = &ms
		}
		cookie := reviewSignEnv(secret, reviewWire{V: 1, Exp: exp, D: map[string]string{"user": user}})
		extended := false
		switch tamper {
		case 1:
			flipped, ok := reviewFlipMAC(cookie)
			if !ok {
				ht.Fatal("mac flip failed")
			}
			cookie = flipped
		case 2:
			if lifetime == 0 {
				payload, sig, ok := reviewSplitCookie(cookie)
				if !ok || len(payload) == 0 {
					ht.Fatal("payload flip failed")
				}
				payload = bytes.Clone(payload)
				payload[0] ^= 0x01
				cookie = reviewJoinCookie(payload, sig)
			} else {
				flipped, oldExp, newExp, ok := reviewFlipExp(cookie)
				if !ok || newExp <= oldExp {
					ht.Fatalf("expiry flip old %d new %d ok %v", oldExp, newExp, ok)
				}
				cookie = flipped
				extended = true
			}
		}
		app := reviewSessionApp(secret, 1)
		got := reviewUser(ht, app, cookie)
		after := time.Now()

		hasExp := exp != nil
		var deadline int64
		if hasExp {
			deadline = *exp
		}
		live, certain := reviewExpiryLive(hasExp, deadline, before, after)
		if tamper != 0 {
			if got != "" {
				ht.Fatalf("tamper %d extended life user %q extended %v", tamper, got, extended)
			}
			return
		}
		if !certain {
			if got != "" && got != user {
				ht.Fatalf("user %q want empty or %q", got, user)
			}
			return
		}
		want := ""
		if live {
			want = user
		}
		if got != want {
			ht.Fatalf("user %q want %q lifetime %d move %d exp %v", got, want, lifetime, move, exp)
		}
	})
}

// TestIssue7RepeatedAPIKeyHeader is the minimal counterexample from issue 7:
// a second APIKeyHeader("X-Review-Key") panicked with
// "gfast: duplicate dependency apiKey_header_X_Review_Key".
func TestIssue7RepeatedAPIKeyHeader(t *testing.T) {
	first := gfast.APIKeyHeader("X-Review-Key")
	appA := reviewMarkApp("A", first)
	before := appA.Request(http.MethodGet, "/k", nil, http.Header{"X-Review-Key": []string{"alpha"}})
	reviewMarkOK(t, before, "A")

	second := gfast.APIKeyHeader("X-Review-Key")
	appB := reviewMarkApp("B", second)
	after := appA.Request(http.MethodGet, "/k", nil, http.Header{"X-Review-Key": []string{"alpha"}})
	reviewMarkOK(t, after, "A")
	if before.Status != after.Status || string(before.Body) != string(after.Body) {
		t.Fatalf("building app B changed app A from %d %s to %d %s", before.Status, before.Body, after.Status, after.Body)
	}
	gotB := appB.Request(http.MethodGet, "/k", nil, http.Header{"X-Review-Key": []string{"beta"}})
	reviewMarkOK(t, gotB, "B")
	if strings.Contains(string(gotB.Body), `"A"`) || strings.Contains(string(after.Body), `"B"`) {
		t.Fatalf("crossed results A %s B %s", after.Body, gotB.Body)
	}

	missing := appA.Request(http.MethodGet, "/k", nil)
	if missing.Status != http.StatusUnauthorized || strings.Contains(string(missing.Body), `"A"`) {
		t.Fatalf("missing %d %s", missing.Status, missing.Body)
	}
	_ = gfast.APIKeyHeader("X-Review-Key", gfast.Optional())
	again := gfast.APIKeyHeader("X-Review-Key", gfast.Optional())
	optApp := reviewMarkApp("O", again)
	optMissing := optApp.Request(http.MethodGet, "/k", nil)
	reviewMarkOK(t, optMissing, "O")
	still := appA.Request(http.MethodGet, "/k", nil)
	if still.Status != http.StatusUnauthorized || strings.Contains(string(still.Body), `"A"`) {
		t.Fatalf("optional registration changed required app %d %s", still.Status, still.Body)
	}

	var ready sync.WaitGroup
	var start sync.WaitGroup
	const n = 8
	deps := make([]gfast.Dependency, n)
	ready.Add(n)
	start.Add(1)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer ready.Done()
			start.Wait()
			deps[i] = gfast.APIKeyHeader("X-Review-Key")
		}(i)
	}
	start.Done()
	ready.Wait()
	left := reviewMarkApp("L", deps[0])
	right := reviewMarkApp("R", deps[n-1])
	reviewMarkOK(t, left.Request(http.MethodGet, "/k", nil, http.Header{"X-Review-Key": []string{"alpha"}}), "L")
	reviewMarkOK(t, right.Request(http.MethodGet, "/k", nil, http.Header{"X-Review-Key": []string{"beta"}}), "R")
	reviewMarkOK(t, appA.Request(http.MethodGet, "/k", nil, http.Header{"X-Review-Key": []string{"alpha"}}), "A")
}

// TestIssue7DifferentProviderPanics keeps a second provider under a taken
// name as a panic, including a sanitized API key collision.
func TestIssue7DifferentProviderPanics(t *testing.T) {
	const depName = "issue7DupProvider"
	reviewAllowDup(t, depName, func() {
		gfast.Dep(depName, func(ctx context.Context) (reviewDup, error) {
			return reviewDup{N: 1}, nil
		})
	})
	reviewMustDup(t, depName, func() {
		gfast.Dep(depName, func(ctx context.Context) (reviewDup, error) {
			return reviewDup{N: 2}, nil
		})
	})

	const collided = "apiKey_header_Issue7_Key"
	reviewAllowDup(t, collided, func() { gfast.APIKeyHeader("Issue7-Key") })
	reviewMustDup(t, collided, func() { gfast.APIKeyHeader("Issue7_Key") })

	const headerName = "apiKey_header_Issue7DepClash"
	reviewAllowDup(t, headerName, func() { gfast.APIKeyHeader("Issue7DepClash") })
	reviewMustDup(t, headerName, func() {
		gfast.Dep(headerName, func(ctx context.Context) (reviewDup, error) {
			return reviewDup{N: 3}, nil
		})
	})

	const taken = "apiKey_header_Issue7DepFirst"
	reviewAllowDup(t, taken, func() {
		gfast.Dep(taken, func(ctx context.Context) (reviewDup, error) {
			return reviewDup{}, nil
		})
	})
	reviewMustDup(t, taken, func() { gfast.APIKeyHeader("Issue7DepFirst") })
}

type reviewDup struct{ N int }

func reviewAllowDup(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		rec := recover()
		if rec == nil {
			return
		}
		if !strings.Contains(fmt.Sprint(rec), "duplicate dependency "+name) {
			t.Fatalf("panic %v", rec)
		}
	}()
	fn()
}

func reviewMustDup(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		rec := recover()
		if rec == nil {
			t.Fatal("expected panic")
		}
		if !strings.Contains(fmt.Sprint(rec), "duplicate dependency "+name) {
			t.Fatalf("panic %v", rec)
		}
	}()
	fn()
}

func reviewMarkApp(stamp string, dep gfast.Dependency) *gfast.App {
	app := gfast.New()
	app.Get("/k", func(ctx context.Context, in *struct{}) (*struct {
		App string `json:"app"`
	}, error) {
		return &struct {
			App string `json:"app"`
		}{App: stamp}, nil
	}, gfast.Require(dep))
	return app
}

func reviewCountApp(stamp string, dep gfast.Dependency, hits *atomic.Int32) *gfast.App {
	app := gfast.New()
	app.Get("/k", func(ctx context.Context, in *struct{}) (*struct {
		App  string `json:"app"`
		Hits int32  `json:"hits"`
	}, error) {
		return &struct {
			App  string `json:"app"`
			Hits int32  `json:"hits"`
		}{App: stamp, Hits: hits.Load()}, nil
	}, gfast.Require(dep, dep))
	return app
}

func reviewMarkOK(t *testing.T, res *gfast.Result, stamp string) {
	t.Helper()
	if res.Status != http.StatusOK {
		t.Fatalf("status %d want 200 body %s", res.Status, res.Body)
	}
	var body struct {
		App string `json:"app"`
	}
	if err := res.JSON(&body); err != nil {
		t.Fatal(err)
	}
	if body.App != stamp {
		t.Fatalf("app %q want %q body %s", body.App, stamp, res.Body)
	}
}

const (
	reviewCredHeader = iota
	reviewCredQuery
	reviewCredCookie
	reviewCredBearer
	reviewCredBasic
)

// TestPropIssue7RepeatedCredentials builds two apps from one repeated
// credential constructor. The duplicate name does not panic, and each app
// keeps the handler result the oracle predicts from that app's own request.
func TestPropIssue7RepeatedCredentials(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		kind := hegel.Draw(ht, hegel.Integers(0, 4))
		optional := hegel.Draw(ht, hegel.Booleans())
		name := hegel.Draw(ht, hegel.Text().Alphabet("ABab12").MinSize(1).MaxSize(8))
		value := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(6))
		user := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ").MinSize(1).MaxSize(6))
		pass := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(6))
		stampA := "A" + hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(4))
		stampB := "B" + hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(4))
		reps := hegel.Draw(ht, hegel.Integers(2, 4))
		aFirst := hegel.Draw(ht, hegel.Booleans())

		var opts []gfast.AuthOption
		if optional {
			opts = append(opts, gfast.Optional())
		}
		var first, last gfast.Dependency
		for i := 0; i < reps; i++ {
			dep := reviewCredDep(kind, name, opts)
			if i == 0 {
				first = dep
			}
			last = dep
		}

		type side struct {
			app   *gfast.App
			stamp string
			hits  *atomic.Int32
		}
		var earlyHits, lateHits atomic.Int32
		var early, late side
		var earlyRes *gfast.Result
		if aFirst {
			early = side{reviewCountApp(stampA, first, &earlyHits), stampA, &earlyHits}
			earlyRes = reviewCredCall(early.app, kind, name, true, value, user, pass)
			reviewCredCheck(ht, earlyRes, stampA, kind, name, optional, true)
			late = side{reviewCountApp(stampB, last, &lateHits), stampB, &lateHits}
		} else {
			early = side{reviewCountApp(stampB, first, &earlyHits), stampB, &earlyHits}
			earlyRes = reviewCredCall(early.app, kind, name, true, value, user, pass)
			reviewCredCheck(ht, earlyRes, stampB, kind, name, optional, true)
			late = side{reviewCountApp(stampA, last, &lateHits), stampA, &lateHits}
		}
		again := reviewCredCall(early.app, kind, name, true, value, user, pass)
		if again.Status != earlyRes.Status || string(again.Body) != string(earlyRes.Body) {
			ht.Fatalf("second app changed %q from %d %s to %d %s", early.stamp, earlyRes.Status, earlyRes.Body, again.Status, again.Body)
		}
		reviewCredCheck(ht, reviewCredCall(early.app, kind, name, false, value, user, pass), early.stamp, kind, name, optional, false)
		reviewCredCheck(ht, reviewCredCall(early.app, kind, name, true, value, user, pass), early.stamp, kind, name, optional, true)
		reviewCredCheck(ht, reviewCredCall(late.app, kind, name, false, value, user, pass), late.stamp, kind, name, optional, false)
		reviewCredCheck(ht, reviewCredCall(late.app, kind, name, true, value, user, pass), late.stamp, kind, name, optional, true)
		if early.hits.Load() != 0 || late.hits.Load() != 0 {
			ht.Fatalf("reader counts early %d late %d", early.hits.Load(), late.hits.Load())
		}

		// Route used last. Override is applied to first. One request lists the
		// dependency twice, so a shared identity memoizes the success once.
		late.app.Override(first, reviewCredCount(late.hits, kind))
		for i := 1; i <= 2; i++ {
			res := reviewCredCall(late.app, kind, name, true, value, user, pass)
			reviewCredHits(ht, res, late.stamp, int32(i))
		}
		if late.hits.Load() != 2 || early.hits.Load() != 0 {
			ht.Fatalf("hits late %d early %d", late.hits.Load(), early.hits.Load())
		}
		kept := reviewCredCall(early.app, kind, name, true, value, user, pass)
		if kept.Status != earlyRes.Status || string(kept.Body) != string(earlyRes.Body) {
			ht.Fatalf("override changed %q from %d %s to %d %s", early.stamp, earlyRes.Status, earlyRes.Body, kept.Status, kept.Body)
		}
		reviewCredCheck(ht, reviewCredCall(early.app, kind, name, false, value, user, pass), early.stamp, kind, name, optional, false)
	})
}

func reviewCredDep(kind int, name string, opts []gfast.AuthOption) gfast.Dependency {
	switch kind {
	case reviewCredHeader:
		return gfast.APIKeyHeader(name, opts...)
	case reviewCredQuery:
		return gfast.APIKeyQuery(name, opts...)
	case reviewCredCookie:
		return gfast.APIKeyCookie(name, opts...)
	case reviewCredBearer:
		return gfast.BearerAuth(opts...)
	default:
		return gfast.BasicAuth(opts...)
	}
}

func reviewCredCall(app *gfast.App, kind int, name string, present bool, value, user, pass string) *gfast.Result {
	header := http.Header{}
	target := "/k"
	if present {
		switch kind {
		case reviewCredHeader:
			header.Set(name, value)
		case reviewCredQuery:
			target = "/k?" + url.Values{name: {value}}.Encode()
		case reviewCredCookie:
			header.Set("Cookie", name+"="+value)
		case reviewCredBearer:
			header.Set("Authorization", "Bearer "+value)
		default:
			header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
		}
	}
	return app.Request(http.MethodGet, target, nil, header)
}

// reviewCredWant is the handler result for one drawn request.
// A supplied credential runs the handler. A missing credential runs it only
// when the reader was built with Optional. The detail and challenge are the
// ones documented for that reader, not a replay of the reader.
func reviewCredWant(kind int, name string, optional, present bool) (status int, detail, challenge string, ran bool) {
	if present || optional {
		return http.StatusOK, "", "", true
	}
	switch kind {
	case reviewCredBearer:
		return http.StatusUnauthorized, "missing bearer token", "Bearer", false
	case reviewCredBasic:
		return http.StatusUnauthorized, "missing basic credentials", `Basic realm="api"`, false
	case reviewCredHeader:
		return http.StatusUnauthorized, "missing api key", name, false
	default:
		return http.StatusUnauthorized, "missing api key", "apiKey", false
	}
}

func reviewCredCheck(ht *hegel.T, res *gfast.Result, stamp string, kind int, name string, optional, present bool) {
	ht.Helper()
	status, detail, challenge, ran := reviewCredWant(kind, name, optional, present)
	if !ran {
		hpProblem(ht, res, status, detail)
		hpChallenge(ht, res, challenge)
		if strings.Contains(string(res.Body), `"`+stamp+`"`) {
			ht.Fatalf("handler result leaked into %s", res.Body)
		}
		return
	}
	if res.Status != status {
		ht.Fatalf("status %d want %d body %s", res.Status, status, res.Body)
	}
	if got := res.Header.Get("WWW-Authenticate"); got != "" {
		ht.Fatalf("challenge %q body %s", got, res.Body)
	}
	var body struct {
		App string `json:"app"`
	}
	if err := res.JSON(&body); err != nil {
		ht.Fatal(err)
	}
	if body.App != stamp {
		ht.Fatalf("app %q want %q body %s", body.App, stamp, res.Body)
	}
}

func reviewCredHits(ht *hegel.T, res *gfast.Result, stamp string, hits int32) {
	ht.Helper()
	if res.Status != http.StatusOK {
		ht.Fatalf("status %d want 200 body %s", res.Status, res.Body)
	}
	var body struct {
		App  string `json:"app"`
		Hits int32  `json:"hits"`
	}
	if err := res.JSON(&body); err != nil {
		ht.Fatal(err)
	}
	if body.App != stamp || body.Hits != hits {
		ht.Fatalf("got %+v want app %q hits %d body %s", body, stamp, hits, res.Body)
	}
}

// reviewAlias is a time.Time alias, so it uses the date-time wire format.
type reviewAlias = time.Time

type reviewBlob []byte

type reviewLabel string

type reviewCount uint8

type reviewText struct {
	S string
}

func (t reviewText) MarshalText() ([]byte, error) {
	return []byte("T:" + t.S), nil
}

type reviewCustom struct {
	N int
}

func (c reviewCustom) MarshalJSON() ([]byte, error) {
	return fmt.Appendf(nil, "%d", c.N), nil
}

type reviewEmbed struct {
	Note string `json:"note,omitempty"`
	Need string `json:"need" required:"true"`
}

type issue5Out struct {
	reviewEmbed
	At      time.Time      `json:"at"`
	Alias   reviewAlias    `json:"alias,omitzero"`
	Data    []byte         `json:"data"`
	Fixed   [4]byte        `json:"fixed"`
	Nums    []int          `json:"nums"`
	Grid    [][]int        `json:"grid"`
	Counts  []reviewCount  `json:"counts"`
	Blob    reviewBlob     `json:"blob,omitempty"`
	Labels  []reviewLabel  `json:"labels,omitempty"`
	Label   reviewLabel    `json:"label"`
	Ptr     *string        `json:"ptr"`
	Opt     string         `json:"opt,omitempty"`
	ZeroN   int            `json:"zeroN,omitzero"`
	Body    string         `json:"body"`
	RawBody string         `json:"rawBody,omitempty"`
	Items   []reviewEmbed  `json:"items"`
	Bag     map[string]int `json:"bag,omitempty"`
	Text    reviewText     `json:"text"`
	Custom  reviewCustom   `json:"custom"`
}

type reviewIn struct {
	Name   string  `json:"name" required:"true"`
	Note   *string `json:"note" required:"true"`
	Maybe  *string `json:"maybe"`
	Title  string  `json:"title,omitempty"`
	Extra  int     `json:"extra,omitzero"`
	OptReq string  `json:"optReq,omitempty" required:"true"`
}

// TestIssue5JSONSchemaWire is the counterexample from GitHub issue 5:
// time.Time, []byte, an omitted empty string, and a JSON field named Body.
func TestIssue5JSONSchemaWire(t *testing.T) {
	type payload struct {
		Name string `json:"name" required:"true"`
	}
	type out struct {
		At   time.Time `json:"at"`
		Data []byte    `json:"data"`
		Opt  string    `json:"opt,omitempty"`
		Body string    `json:"body"`
	}
	app := gfast.New()
	app.Post("/out", func(ctx context.Context, in *struct{}) (*out, error) {
		return &out{
			At:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Data: []byte("abc"),
			Body: "hello",
		}, nil
	})
	app.Post("/in", func(ctx context.Context, in *struct{ Body payload }) (*payload, error) {
		return &in.Body, nil
	})

	got := app.Request(http.MethodPost, "/out", []byte(`{}`))
	const want = `{"at":"2026-01-01T00:00:00Z","data":"YWJj","body":"hello"}`
	if got.Status != http.StatusOK || string(got.Body) != want {
		t.Fatalf("wire %d %s", got.Status, got.Body)
	}
	empty := app.Request(http.MethodPost, "/in", nil)
	if empty.Status != http.StatusUnprocessableEntity || !strings.Contains(string(empty.Body), "name is required") {
		t.Fatalf("empty %d %s", empty.Status, empty.Body)
	}
	blank := app.Request(http.MethodPost, "/in", []byte(`{}`))
	if blank.Status != http.StatusUnprocessableEntity || !strings.Contains(string(blank.Body), "name is required") {
		t.Fatalf("object %d %s", blank.Status, blank.Body)
	}
	zero := app.Request(http.MethodPost, "/in", []byte(`{"name":""}`))
	if zero.Status != http.StatusOK || string(zero.Body) != `{"name":""}` {
		t.Fatalf("zero %d %s", zero.Status, zero.Body)
	}
	nullNote := app.Request(http.MethodPost, "/in", []byte(`{"name":null}`))
	if nullNote.Status != http.StatusOK || string(nullNote.Body) != `{"name":""}` {
		t.Fatalf("null %d %s", nullNote.Status, nullNote.Body)
	}

	spec := app.Request(http.MethodGet, "/openapi.json", nil)
	if spec.Status != http.StatusOK {
		t.Fatalf("spec %d %s", spec.Status, spec.Body)
	}
	var doc map[string]any
	if err := json.Unmarshal(spec.Body, &doc); err != nil {
		t.Fatal(err)
	}
	props := reviewSchemaProps(t, doc, "/out", "post", false)
	if props["at"].(map[string]any)["type"] != "string" || props["at"].(map[string]any)["format"] != "date-time" {
		t.Fatalf("at %#v", props["at"])
	}
	if props["data"].(map[string]any)["type"] != "string" || props["data"].(map[string]any)["format"] != "byte" {
		t.Fatalf("data %#v", props["data"])
	}
	if _, ok := props["body"]; !ok || props["body"].(map[string]any)["type"] != "string" {
		t.Fatalf("body %#v", props["body"])
	}
	if _, ok := props["opt"]; !ok {
		t.Fatal("opt missing from properties")
	}
	required, _ := reviewSchemaObject(t, doc, "/out", "post", false)["required"].([]any)
	if !reviewSameAny(required, []any{"at", "data", "body"}) {
		t.Fatalf("required %#v", required)
	}
	inProps := reviewSchemaProps(t, doc, "/in", "post", true)
	if inProps["name"].(map[string]any)["type"] != "string" {
		t.Fatalf("name %#v", inProps["name"])
	}
	inRequired, _ := reviewSchemaObject(t, doc, "/in", "post", true)["required"].([]any)
	if !reviewSameAny(inRequired, []any{"name"}) {
		t.Fatalf("input required %#v", inRequired)
	}
}

func TestPropIssue5JSONSchemaWire(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		mode := hegel.Draw(ht, hegel.Integers(0, 8))
		name := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(6))
		noteText := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ").MinSize(1).MaxSize(4))
		optReq := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(4))
		atUnix := hegel.Draw(ht, hegel.Integers(0, 1_700_000_000))
		aliasZero := hegel.Draw(ht, hegel.Booleans())
		aliasUnix := hegel.Draw(ht, hegel.Integers(1, 1_700_000_000))
		dataText := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MaxSize(4))
		fixedText := hegel.Draw(ht, hegel.Text().Alphabet("abcd").MinSize(4).MaxSize(4))
		nums := hegel.Draw(ht, hegel.Lists(hegel.Integers(-3, 3)).MaxSize(3))
		grid := hegel.Draw(ht, hegel.Lists(hegel.Lists(hegel.Integers(-2, 2)).MaxSize(2)).MaxSize(2))
		countNums := hegel.Draw(ht, hegel.Lists(hegel.Integers(0, 5)).MaxSize(3))
		blobOn := hegel.Draw(ht, hegel.Booleans())
		blobText := hegel.Draw(ht, hegel.Text().Alphabet("ab").MaxSize(3))
		label := reviewLabel(hegel.Draw(ht, hegel.Text().Alphabet("abc").MaxSize(4)))
		labelsOn := hegel.Draw(ht, hegel.Booleans())
		ptrNil := hegel.Draw(ht, hegel.Booleans())
		ptrText := hegel.Draw(ht, hegel.Text().Alphabet("xyz").MaxSize(3))
		opt := hegel.Draw(ht, hegel.Text().Alphabet("op").MaxSize(2))
		zeroN := hegel.Draw(ht, hegel.Integers(0, 4))
		bodyText := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ").MinSize(1).MaxSize(6))
		rawOn := hegel.Draw(ht, hegel.Booleans())
		rawText := hegel.Draw(ht, hegel.Text().Alphabet("rw").MaxSize(3))
		need := hegel.Draw(ht, hegel.Text().Alphabet("nd").MaxSize(3))
		noteField := hegel.Draw(ht, hegel.Text().Alphabet("nt").MaxSize(3))
		itemOn := hegel.Draw(ht, hegel.Booleans())
		bagOn := hegel.Draw(ht, hegel.Booleans())
		bagVal := hegel.Draw(ht, hegel.Integers(-2, 4))
		textS := hegel.Draw(ht, hegel.Text().Alphabet("tx").MaxSize(3))
		customN := hegel.Draw(ht, hegel.Integers(-3, 5))

		var fixed [4]byte
		copy(fixed[:], fixedText)
		counts := make([]reviewCount, len(countNums))
		for i, n := range countNums {
			counts[i] = reviewCount(n)
		}
		var blob reviewBlob
		if blobOn {
			blob = reviewBlob(blobText)
		}
		var labels []reviewLabel
		if labelsOn {
			labels = []reviewLabel{label}
		}
		var ptr *string
		if !ptrNil {
			ptr = &ptrText
		}
		rawBody := ""
		if rawOn {
			rawBody = rawText
		}
		var alias reviewAlias
		if !aliasZero {
			alias = time.Unix(int64(aliasUnix), 0).UTC()
		}
		var items []reviewEmbed
		if itemOn {
			items = []reviewEmbed{{Note: noteField, Need: need}}
		}
		var bag map[string]int
		if bagOn {
			bag = map[string]int{"k": bagVal}
		}
		wire := issue5Out{
			reviewEmbed: reviewEmbed{Note: noteField, Need: need},
			At:          time.Unix(int64(atUnix), 0).UTC(),
			Alias:       alias,
			Data:        []byte(dataText),
			Fixed:       fixed,
			Nums:        nums,
			Grid:        grid,
			Counts:      counts,
			Blob:        blob,
			Labels:      labels,
			Label:       label,
			Ptr:         ptr,
			Opt:         opt,
			ZeroN:       zeroN,
			Body:        bodyText,
			RawBody:     rawBody,
			Items:       items,
			Bag:         bag,
			Text:        reviewText{S: textS},
			Custom:      reviewCustom{N: customN},
		}
		oracle, err := jsonv2.Marshal(&wire)
		if err != nil {
			ht.Fatal(err)
		}

		app := gfast.New()
		app.Post("/out", func(ctx context.Context, in *struct{}) (*issue5Out, error) {
			return &wire, nil
		})
		app.Post("/in", func(ctx context.Context, in *struct{ Body reviewIn }) (*reviewIn, error) {
			return &in.Body, nil
		})

		res := app.Request(http.MethodPost, "/out", nil)
		if res.Status != http.StatusOK || string(res.Body) != string(oracle) {
			ht.Fatalf("wire %d\n%s\nwant %s", res.Status, res.Body, oracle)
		}

		spec := app.Request(http.MethodGet, "/openapi.json", nil)
		if spec.Status != http.StatusOK {
			ht.Fatalf("spec %d %s", spec.Status, spec.Body)
		}
		var doc map[string]any
		if err := json.Unmarshal(spec.Body, &doc); err != nil {
			ht.Fatal(err)
		}
		outSchema := reviewSchemaObject(ht, doc, "/out", "post", false)
		props := outSchema["properties"].(map[string]any)
		reviewWantType(ht, props, "at", "string", "date-time")
		reviewWantType(ht, props, "alias", "string", "date-time")
		reviewWantType(ht, props, "data", "string", "byte")
		reviewWantType(ht, props, "fixed", "string", "byte")
		reviewWantType(ht, props, "blob", "string", "byte")
		reviewWantType(ht, props, "label", "string", "")
		reviewWantType(ht, props, "body", "string", "")
		reviewWantType(ht, props, "rawBody", "string", "")
		reviewWantType(ht, props, "ptr", "string", "")
		reviewWantType(ht, props, "opt", "string", "")
		reviewWantType(ht, props, "need", "string", "")
		reviewWantType(ht, props, "note", "string", "")
		reviewWantType(ht, props, "text", "string", "")
		if _, ok := props["custom"].(map[string]any)["type"]; ok {
			ht.Fatalf("custom schema %#v", props["custom"])
		}
		numsSchema := reviewWantType(ht, props, "nums", "array", "")
		if numsSchema["items"].(map[string]any)["type"] != "integer" {
			ht.Fatalf("nums %#v", numsSchema)
		}
		countsSchema := reviewWantType(ht, props, "counts", "array", "")
		if countsSchema["items"].(map[string]any)["type"] != "integer" || countsSchema["items"].(map[string]any)["format"] != nil {
			ht.Fatalf("counts %#v", countsSchema)
		}
		labelsSchema := reviewWantType(ht, props, "labels", "array", "")
		if labelsSchema["items"].(map[string]any)["type"] != "string" {
			ht.Fatalf("labels %#v", labelsSchema)
		}
		gridSchema := reviewWantType(ht, props, "grid", "array", "")
		gridItems := gridSchema["items"].(map[string]any)
		if gridItems["type"] != "array" || gridItems["items"].(map[string]any)["type"] != "integer" {
			ht.Fatalf("grid %#v", gridSchema)
		}
		bagSchema := reviewWantType(ht, props, "bag", "object", "")
		if bagSchema["additionalProperties"].(map[string]any)["type"] != "integer" {
			ht.Fatalf("bag %#v", bagSchema)
		}
		itemsSchema := reviewWantType(ht, props, "items", "array", "")
		itemRef, _ := itemsSchema["items"].(map[string]any)["$ref"].(string)
		if itemRef != "#/components/schemas/reviewEmbed" {
			ht.Fatalf("items %#v", itemsSchema)
		}
		embed := reviewResolveRef(ht, doc, itemRef)
		if embed["properties"].(map[string]any)["need"].(map[string]any)["type"] != "string" {
			ht.Fatalf("embed %#v", embed)
		}
		if !reviewSameAny(embed["required"], []any{"need"}) {
			ht.Fatalf("embed required %#v", embed["required"])
		}
		wantRequired := []any{"need", "at", "data", "fixed", "nums", "grid", "counts", "label", "ptr", "body", "items", "text", "custom"}
		if !reviewSameAny(outSchema["required"], wantRequired) {
			ht.Fatalf("required %#v", outSchema["required"])
		}
		for _, optional := range []string{"note", "alias", "blob", "labels", "opt", "zeroN", "rawBody", "bag"} {
			for _, got := range outSchema["required"].([]any) {
				if got == optional {
					ht.Fatalf("optional %s listed required", optional)
				}
			}
		}

		inSchema := reviewSchemaObject(ht, doc, "/in", "post", true)
		if !reviewSameAny(inSchema["required"], []any{"name", "note", "maybe", "optReq"}) {
			ht.Fatalf("input required %#v", inSchema["required"])
		}
		inProps := inSchema["properties"].(map[string]any)
		reviewWantType(ht, inProps, "name", "string", "")
		reviewWantType(ht, inProps, "note", "string", "")
		if _, listed := inSchema["required"].([]any); !listed {
			ht.Fatal("input required missing")
		}

		var raw []byte
		var wantStatus int
		var wantDetail string
		var wantBody *reviewIn
		switch mode {
		case 0:
			wantStatus = http.StatusUnprocessableEntity
			wantDetail = "name is required; note is required; optReq is required"
		case 1:
			raw = []byte(`{}`)
			wantStatus = http.StatusUnprocessableEntity
			wantDetail = "name is required; note is required; optReq is required"
		case 2:
			raw = []byte(`{"name":"","note":null}`)
			wantStatus = http.StatusUnprocessableEntity
			wantDetail = "optReq is required"
		case 3:
			raw = []byte(`{"note":null,"optReq":"z"}`)
			wantStatus = http.StatusUnprocessableEntity
			wantDetail = "name is required"
		case 4:
			raw = []byte(`{"name":"","optReq":"z"}`)
			wantStatus = http.StatusUnprocessableEntity
			wantDetail = "note is required"
		case 5:
			raw = []byte(`{"name":"","note":null,"optReq":""}`)
			wantStatus = http.StatusOK
			wantBody = &reviewIn{Name: ""}
		case 6:
			raw = []byte(`{"name":"","note":"","optReq":"z","maybe":""}`)
			wantStatus = http.StatusOK
			empty := ""
			wantBody = &reviewIn{Name: "", Note: &empty, Maybe: &empty, OptReq: "z"}
		case 7:
			payload, err := jsonv2.Marshal(map[string]any{"name": name, "note": noteText, "optReq": optReq, "title": "", "extra": 0})
			if err != nil {
				ht.Fatal(err)
			}
			raw = payload
			wantStatus = http.StatusOK
			wantBody = &reviewIn{Name: name, Note: &noteText, OptReq: optReq}
		default:
			raw = []byte(`{"name":null,"note":null,"optReq":null}`)
			wantStatus = http.StatusOK
			wantBody = &reviewIn{}
		}
		inRes := app.Request(http.MethodPost, "/in", raw)
		if wantBody == nil {
			hpProblem(ht, inRes, wantStatus, wantDetail)
			return
		}
		if inRes.Status != wantStatus {
			ht.Fatalf("input %d %s", inRes.Status, inRes.Body)
		}
		wantBytes, err := jsonv2.Marshal(wantBody)
		if err != nil {
			ht.Fatal(err)
		}
		if string(inRes.Body) != string(wantBytes) {
			ht.Fatalf("input body %s want %s", inRes.Body, wantBytes)
		}
	})
}

func reviewSchemaObject(t reviewTB, doc map[string]any, path, method string, request bool) map[string]any {
	t.Helper()
	paths := doc["paths"].(map[string]any)
	op := paths[path].(map[string]any)[method].(map[string]any)
	var schema map[string]any
	if request {
		body := op["requestBody"].(map[string]any)
		schema = body["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	} else {
		resp := op["responses"].(map[string]any)["200"].(map[string]any)
		schema = resp["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
	}
	if ref, _ := schema["$ref"].(string); ref != "" {
		return reviewResolveRef(t, doc, ref)
	}
	return schema
}

func reviewSchemaProps(t reviewTB, doc map[string]any, path, method string, request bool) map[string]any {
	t.Helper()
	return reviewSchemaObject(t, doc, path, method, request)["properties"].(map[string]any)
}

func reviewResolveRef(t reviewTB, doc map[string]any, ref string) map[string]any {
	t.Helper()
	name := strings.TrimPrefix(ref, "#/components/schemas/")
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	got, ok := schemas[name].(map[string]any)
	if !ok {
		t.Fatalf("missing schema %s", name)
	}
	return got
}

func reviewWantType(t reviewTB, props map[string]any, name, typ, format string) map[string]any {
	t.Helper()
	prop, ok := props[name].(map[string]any)
	if !ok {
		t.Fatalf("missing %s in %#v", name, props)
	}
	if prop["type"] != typ {
		t.Fatalf("%s type %#v", name, prop["type"])
	}
	if format == "" {
		if _, ok := prop["format"]; ok {
			t.Fatalf("%s format %#v", name, prop["format"])
		}
	} else if prop["format"] != format {
		t.Fatalf("%s format %#v", name, prop["format"])
	}
	return prop
}

func reviewSameAny(got any, want []any) bool {
	list, ok := got.([]any)
	if !ok || len(list) != len(want) {
		return false
	}
	for i := range want {
		if list[i] != want[i] {
			return false
		}
	}
	return true
}

func reviewCredCount(calls *atomic.Int32, kind int) any {
	tick := func() error {
		calls.Add(1)
		return nil
	}
	switch kind {
	case reviewCredBearer:
		return func(ctx context.Context) (gfast.Bearer, error) {
			return gfast.Bearer{}, tick()
		}
	case reviewCredBasic:
		return func(ctx context.Context) (gfast.Basic, error) {
			return gfast.Basic{}, tick()
		}
	default:
		return func(ctx context.Context) (gfast.APIKey, error) {
			return gfast.APIKey{}, tick()
		}
	}
}

// reviewCodeStore is an independent model of the authorization-code map.
// An issue drops codes that can no longer be exchanged, then refuses the new
// code when the remaining ones already fill the cap. It does not evict a code
// that can still be exchanged.
type reviewCodeStore struct {
	cap   int
	slots []reviewCodeSlot
	gone  []string
}

type reviewCodeSlot struct {
	id     string
	usable bool
}

func (s *reviewCodeStore) issue(id string, usable bool) int {
	var keep []reviewCodeSlot
	for _, slot := range s.slots {
		if slot.usable {
			keep = append(keep, slot)
			continue
		}
		s.gone = append(s.gone, slot.id)
	}
	s.slots = keep
	if len(s.slots) >= s.cap {
		return http.StatusServiceUnavailable
	}
	s.slots = append(s.slots, reviewCodeSlot{id: id, usable: usable})
	return http.StatusFound
}

func (s *reviewCodeStore) expire() {
	for i := range s.slots {
		s.slots[i].usable = false
	}
}

func (s *reviewCodeStore) usable(id string) bool {
	for _, slot := range s.slots {
		if slot.id == id && slot.usable {
			return true
		}
	}
	return false
}

// TestPropOAuthExpiredCodeSweep issues several authorization codes with a
// negative CodeTTL, then one live code. Only the live code can be exchanged.
// Expired codes are removed on the next issue, so the stored count stays
// within MaxCodes and a live code is not dropped to make room.
func TestPropOAuthExpiredCodeSweep(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		maxCodes := hegel.Draw(ht, hegel.Integers(1, 4))
		extra := hegel.Draw(ht, hegel.Integers(1, 5))
		n := maxCodes + extra
		neg := -time.Nanosecond
		if hegel.Draw(ht, hegel.Booleans()) {
			neg = -time.Second
		}
		clientID := hegel.Draw(ht, hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(6))
		subject := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		state := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ012").MinSize(1).MaxSize(6))
		verifier := hegel.Draw(ht, hegel.Text().Alphabet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~").MinSize(43).MaxSize(43))
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		const redirect = "https://app.example/cb"

		// Negative lifetimes are expired as soon as they are stored. The next
		// issue drops them before it applies the cap, so more than MaxCodes
		// authorizations still succeed and none of those codes exchange.
		deadApp := hpOAuthTTLApp(clientID, subject, gfast.OAuthConfig{CodeTTL: neg, MaxCodes: maxCodes})
		deadStore := &reviewCodeStore{cap: maxCodes}
		deadIDs := make([]string, 0, n)
		for i := 0; i < n; i++ {
			id := hpSessionCode(ht, deadApp, clientID, redirect, state+"d"+strconv.Itoa(i), challenge)
			deadIDs = append(deadIDs, id)
			if got := deadStore.issue(id, false); got != http.StatusFound {
				ht.Fatalf("oracle refused expired code %d cap %d", i, maxCodes)
			}
		}
		if len(deadStore.slots) != 1 || deadStore.slots[0].usable || len(deadStore.slots) > maxCodes {
			ht.Fatalf("oracle stored %+v cap %d", deadStore.slots, maxCodes)
		}
		for _, id := range deadIDs {
			if deadStore.usable(id) {
				ht.Fatalf("oracle treats expired code %s as usable", id)
			}
			hpOAuthErr(ht, hpExchange(deadApp, clientID, id, redirect, verifier), http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		}

		// Same cap, one server: fill it, let those codes expire, then issue
		// one live code. Only that code remains usable. Further live codes
		// stop at MaxCodes, and the refusal does not evict it.
		start := time.Unix(1_700_000_000, 0).UTC()
		now := start
		clockApp := hpOAuthTTLApp(clientID, subject, gfast.OAuthConfig{
			CodeTTL:  time.Minute,
			MaxCodes: maxCodes,
			Now:      func() time.Time { return now },
		})
		clockStore := &reviewCodeStore{cap: maxCodes}
		abandoned := make([]string, 0, maxCodes)
		for i := 0; i < maxCodes; i++ {
			id := hpSessionCode(ht, clockApp, clientID, redirect, state+"a"+strconv.Itoa(i), challenge)
			abandoned = append(abandoned, id)
			if got := clockStore.issue(id, true); got != http.StatusFound {
				ht.Fatalf("oracle refused live fill %d", i)
			}
		}
		now = start.Add(2 * time.Minute)
		clockStore.expire()
		liveID := hpSessionCode(ht, clockApp, clientID, redirect, state+"live", challenge)
		if got := clockStore.issue(liveID, true); got != http.StatusFound {
			ht.Fatal("oracle refused the live code")
		}
		if len(clockStore.slots) != 1 || !clockStore.usable(liveID) {
			ht.Fatalf("oracle live %+v", clockStore.slots)
		}
		for _, id := range abandoned {
			if clockStore.usable(id) {
				ht.Fatalf("abandoned %s still usable in the oracle", id)
			}
			hpOAuthErr(ht, hpExchange(clockApp, clientID, id, redirect, verifier), http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		}
		accepted := 1
		for accepted <= maxCodes {
			res := clockApp.Request(http.MethodGet, hpAuthorizePath(clientID, redirect, state+"f"+strconv.Itoa(accepted), challenge, "code", ""), nil)
			if res.Status == http.StatusServiceUnavailable {
				if got := clockStore.issue("refused", true); got != res.Status || accepted != maxCodes {
					ht.Fatalf("cap status %d oracle %d accepted %d cap %d body %s", res.Status, got, accepted, maxCodes, res.Body)
				}
				hpOAuthErr(ht, res, http.StatusServiceUnavailable, "server_error", "token storage is full")
				if res.Header.Get("Location") != "" {
					ht.Fatalf("cap redirect %q", res.Header.Get("Location"))
				}
				break
			}
			if res.Status != http.StatusFound {
				ht.Fatalf("fill %d %s", res.Status, res.Body)
			}
			id := hpRedirectCode(ht, res, state+"f"+strconv.Itoa(accepted))
			if got := clockStore.issue(id, true); got != http.StatusFound {
				ht.Fatalf("oracle refused fill %s", id)
			}
			accepted++
		}
		if accepted != maxCodes || len(clockStore.slots) != maxCodes {
			ht.Fatalf("accepted %d stored %d cap %d", accepted, len(clockStore.slots), maxCodes)
		}
		if !clockStore.usable(liveID) {
			ht.Fatal("oracle evicted the live code")
		}
		liveTok := hpExchange(clockApp, clientID, liveID, redirect, verifier)
		if liveTok.Status != http.StatusOK || !strings.Contains(string(liveTok.Body), `"access_token"`) {
			ht.Fatalf("live code %d %s", liveTok.Status, liveTok.Body)
		}
		for _, id := range deadIDs {
			hpOAuthErr(ht, hpExchange(deadApp, clientID, id, redirect, verifier), http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		}
	})
}

// TestIssue6TenExpiredCodesThenOneLive is the minimal counterexample from
// issue 6: ten expired authorization codes followed by one live code used to
// leave 11 codes stored.
func TestIssue6TenExpiredCodesThenOneLive(t *testing.T) {
	const (
		redirect = "https://app.example/cb"
		clientID = "app"
		subject  = "ada"
		verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	start := time.Unix(1_700_000_000, 0).UTC()
	now := start
	app := hpOAuthTTLApp(clientID, subject, gfast.OAuthConfig{
		CodeTTL:  time.Minute,
		MaxCodes: 10,
		Now:      func() time.Time { return now },
	})
	dead := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		dead = append(dead, reviewAuthCode(t, app, clientID, redirect, fmt.Sprintf("s%d", i), challenge))
	}
	now = start.Add(2 * time.Minute)
	live := reviewAuthCode(t, app, clientID, redirect, "live", challenge)
	for _, code := range dead {
		reviewOAuthErr(t, hpExchange(app, clientID, code, redirect, verifier), http.StatusBadRequest, "invalid_grant", "invalid authorization code")
	}
	for i := 0; i < 9; i++ {
		reviewAuthCode(t, app, clientID, redirect, fmt.Sprintf("f%d", i), challenge)
	}
	full := app.Request(http.MethodGet, hpAuthorizePath(clientID, redirect, "full", challenge, "code", ""), nil)
	reviewOAuthErr(t, full, http.StatusServiceUnavailable, "server_error", "token storage is full")
	if full.Header.Get("Location") != "" || strings.Contains(string(full.Body), "access_token") {
		t.Fatalf("cap response %q %s", full.Header.Get("Location"), full.Body)
	}
	if got := hpExchange(app, clientID, live, redirect, verifier); got.Status != http.StatusOK {
		t.Fatalf("live code evicted %d %s", got.Status, got.Body)
	}

	// A negative code lifetime is already expired and is deleted by the next issue.
	negApp := hpOAuthTTLApp(clientID, subject, gfast.OAuthConfig{CodeTTL: -time.Nanosecond, MaxCodes: 1})
	first := reviewAuthCode(t, negApp, clientID, redirect, "n0", challenge)
	second := reviewAuthCode(t, negApp, clientID, redirect, "n1", challenge)
	reviewOAuthErr(t, hpExchange(negApp, clientID, first, redirect, verifier), http.StatusBadRequest, "invalid_grant", "invalid authorization code")
	reviewOAuthErr(t, hpExchange(negApp, clientID, second, redirect, verifier), http.StatusBadRequest, "invalid_grant", "invalid authorization code")

	// Refresh tokens use the same sweep and cap. A live token is not evicted.
	refreshApp := reviewPasswordApp(clientID, gfast.OAuthConfig{MaxRefresh: 1})
	_, refresh := reviewPasswordToken(t, refreshApp, clientID)
	again := reviewPasswordGrant(refreshApp, clientID)
	reviewOAuthErr(t, again, http.StatusServiceUnavailable, "server_error", "token storage is full")
	if rotated := hpRefreshGrant(refreshApp, clientID, refresh); rotated.Status != http.StatusOK {
		t.Fatalf("refresh evicted %d %s", rotated.Status, rotated.Body)
	}

	// A negative refresh lifetime is swept, so a second issue still fits in a cap of one.
	short := reviewPasswordApp(clientID, gfast.OAuthConfig{RefreshTTL: -time.Second, MaxRefresh: 1})
	_, oldRefresh := reviewPasswordToken(t, short, clientID)
	_, newRefresh := reviewPasswordToken(t, short, clientID)
	reviewOAuthErr(t, hpRefreshGrant(short, clientID, oldRefresh), http.StatusBadRequest, "invalid_grant", "invalid refresh token")
	reviewOAuthErr(t, hpRefreshGrant(short, clientID, newRefresh), http.StatusBadRequest, "invalid_grant", "invalid refresh token")

	reviewPanic(t, "gfast: oauth MaxCodes is negative", func() {
		gfast.New(gfast.OAuthServer(gfast.OAuthConfig{
			Clients:  []gfast.OAuthClient{{ID: clientID}},
			MaxCodes: -1,
		}))
	})
	reviewPanic(t, "gfast: oauth MaxRefresh is negative", func() {
		gfast.New(gfast.OAuthServer(gfast.OAuthConfig{
			Clients:    []gfast.OAuthClient{{ID: clientID}},
			MaxRefresh: -1,
		}))
	})

	// Zero means 1024. The code that filled the store is still exchanged.
	// The clock stays put so a slow run cannot expire the code under test.
	frozen := start
	defCodes := hpOAuthTTLApp(clientID, subject, gfast.OAuthConfig{
		CodeTTL: time.Hour,
		Now:     func() time.Time { return frozen },
	})
	var kept string
	for i := 0; i < 1024; i++ {
		code := reviewAuthCode(t, defCodes, clientID, redirect, strconv.Itoa(i), challenge)
		if i == 0 {
			kept = code
		}
	}
	overflow := defCodes.Request(http.MethodGet, hpAuthorizePath(clientID, redirect, "over", challenge, "code", ""), nil)
	reviewOAuthErr(t, overflow, http.StatusServiceUnavailable, "server_error", "token storage is full")
	if got := hpExchange(defCodes, clientID, kept, redirect, verifier); got.Status != http.StatusOK {
		t.Fatalf("default cap evicted %d %s", got.Status, got.Body)
	}

	defRefresh := reviewPasswordApp(clientID, gfast.OAuthConfig{})
	_, firstRefresh := reviewPasswordToken(t, defRefresh, clientID)
	for i := 1; i < 1024; i++ {
		if res := reviewPasswordGrant(defRefresh, clientID); res.Status != http.StatusOK {
			t.Fatalf("default refresh %d at %d %s", res.Status, i, res.Body)
		}
	}
	reviewOAuthErr(t, reviewPasswordGrant(defRefresh, clientID), http.StatusServiceUnavailable, "server_error", "token storage is full")
	if rotated := hpRefreshGrant(defRefresh, clientID, firstRefresh); rotated.Status != http.StatusOK {
		t.Fatalf("default refresh evicted %d %s", rotated.Status, rotated.Body)
	}
}

func reviewAuthCode(t *testing.T, app *gfast.App, clientID, redirect, state, challenge string) string {
	t.Helper()
	res := app.Request(http.MethodGet, hpAuthorizePath(clientID, redirect, state, challenge, "code", ""), nil)
	if res.Status != http.StatusFound {
		t.Fatalf("authorize %d %s", res.Status, res.Body)
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("state") != state || loc.Query().Get("code") == "" || loc.Query().Get("error") != "" {
		t.Fatalf("location %q", res.Header.Get("Location"))
	}
	return loc.Query().Get("code")
}

func reviewOAuthErr(t *testing.T, res *gfast.Result, status int, code, desc string) {
	t.Helper()
	if res.Status != status {
		t.Fatalf("status %d want %d body %s", res.Status, status, res.Body)
	}
	if res.Header.Get("Content-Type") != "application/json" || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("headers %#v", res.Header)
	}
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := res.JSON(&body); err != nil {
		t.Fatal(err)
	}
	if body.Error != code || body.Description != desc {
		t.Fatalf("oauth %+v want %s %s", body, code, desc)
	}
}

func reviewPasswordApp(clientID string, cfg gfast.OAuthConfig) *gfast.App {
	cfg.Clients = []gfast.OAuthClient{{ID: clientID}}
	cfg.Password = func(ctx context.Context, username, password string) (string, error) {
		if username == "ada" && password == "pw" {
			return "ada", nil
		}
		return "", nil
	}
	return gfast.New(gfast.OAuthServer(cfg))
}

func reviewPasswordGrant(app *gfast.App, clientID string) *gfast.Result {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "ada")
	form.Set("password", "pw")
	form.Set("client_id", clientID)
	return app.Request(http.MethodPost, "/oauth/token", []byte(form.Encode()), http.Header{
		"Content-Type": []string{"application/x-www-form-urlencoded"},
	})
}

// issue9Count counts bytes read from a request body.
type issue9Count struct {
	r io.Reader
	n int
}

func (c *issue9Count) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func (c *issue9Count) Close() error { return nil }

func issue9Send(app *gfast.App, method, target string, body []byte, cl int64, header http.Header) (*gfast.Result, int) {
	counted := &issue9Count{r: bytes.NewReader(body)}
	req := httptest.NewRequest(method, target, counted)
	req.ContentLength = cl
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	rec := httptest.NewRecorder()
	app.Handler().ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	payload, _ := io.ReadAll(res.Body)
	return &gfast.Result{Status: res.StatusCode, Header: res.Header.Clone(), Body: payload}, counted.n
}

func issue9Problem(t *testing.T, res *gfast.Result) {
	t.Helper()
	if res.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d body %s", res.Status, res.Body)
	}
	if res.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("content type %q", res.Header.Get("Content-Type"))
	}
	if res.Header.Get("Connection") != "close" {
		t.Fatalf("connection %q", res.Header.Get("Connection"))
	}
	var body struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := res.JSON(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != http.StatusRequestEntityTooLarge || body.Title != http.StatusText(http.StatusRequestEntityTooLarge) || body.Detail != "request body too large" {
		t.Fatalf("problem %+v", body)
	}
}

func issue9JSON() http.Header {
	return http.Header{"Content-Type": []string{"application/json"}}
}

func issue9Form() http.Header {
	return http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}}
}

// TestIssue9BodyLimit is the minimal over-limit body: a 2-byte payload with
// Content-Length 1 against MaxBodyBytes(1). The handler is not called, the
// read stops by the second byte, and the next request still succeeds.
func TestIssue9BodyLimit(t *testing.T) {
	mustPanic(t, "negative", func() { gfast.New(gfast.MaxBodyBytes(-1)) })
	mustPanic(t, "negative", func() {
		gfast.New().Post("/x", func(ctx context.Context, in *struct{ Body int }) (*struct{}, error) {
			return &struct{}{}, nil
		}, gfast.MaxBodyBytes(-1))
	})

	var hits int
	app := gfast.New(gfast.MaxBodyBytes(1))
	app.Post("/n", func(ctx context.Context, in *struct{ Body int }) (*struct{ N int }, error) {
		hits++
		return &struct{ N int }{N: in.Body}, nil
	})
	okRes, n := issue9Send(app, http.MethodPost, "/n", []byte("1"), 1, issue9JSON())
	if okRes.Status != http.StatusOK || hits != 1 || n != 1 || !strings.Contains(string(okRes.Body), `"N":1`) {
		t.Fatalf("fit status %d hits %d read %d body %s", okRes.Status, hits, n, okRes.Body)
	}
	short, n := issue9Send(app, http.MethodPost, "/n", []byte("10"), 1, issue9JSON())
	issue9Problem(t, short)
	if hits != 1 || n == 0 || n > 2 {
		t.Fatalf("short length hits %d read %d", hits, n)
	}
	chunked, n := issue9Send(app, http.MethodPost, "/n", []byte("10"), -1, issue9JSON())
	issue9Problem(t, chunked)
	if hits != 1 || n == 0 || n > 2 {
		t.Fatalf("chunked hits %d read %d", hits, n)
	}
	again, n := issue9Send(app, http.MethodPost, "/n", []byte("1"), -1, issue9JSON())
	if again.Status != http.StatusOK || hits != 2 || n != 1 {
		t.Fatalf("after reject status %d hits %d read %d", again.Status, hits, n)
	}

	var placed int
	placedApp := gfast.New(gfast.MaxBodyBytes(8))
	echo := func(ctx context.Context, in *struct{ Body string }) (*struct{ N int }, error) {
		placed++
		return &struct{ N int }{N: len(in.Body)}, nil
	}
	placedApp.Post("/app", echo)
	placedApp.Post("/route", echo, gfast.MaxBodyBytes(3))
	group := placedApp.Group("/g", gfast.MaxBodyBytes(4))
	group.Post("/n", echo)
	group.Post("/wide", echo, gfast.MaxBodyBytes(0))
	routeOver, _ := issue9Send(placedApp, http.MethodPost, "/route", []byte(`"ab"`), 4, issue9JSON())
	issue9Problem(t, routeOver)
	if placed != 0 {
		t.Fatalf("route handler %d", placed)
	}
	routeFit, _ := issue9Send(placedApp, http.MethodPost, "/route", []byte(`"a"`), 3, issue9JSON())
	if routeFit.Status != http.StatusOK || placed != 1 || !strings.Contains(string(routeFit.Body), `"N":1`) {
		t.Fatalf("route fit %d %s hits %d", routeFit.Status, routeFit.Body, placed)
	}
	groupFit, _ := issue9Send(placedApp, http.MethodPost, "/g/n", []byte(`"ab"`), 4, issue9JSON())
	if groupFit.Status != http.StatusOK || placed != 2 {
		t.Fatalf("group fit %d hits %d", groupFit.Status, placed)
	}
	groupOver, _ := issue9Send(placedApp, http.MethodPost, "/g/n", []byte(`"abc"`), 1, issue9JSON())
	issue9Problem(t, groupOver)
	if placed != 2 {
		t.Fatalf("group over hits %d", placed)
	}
	wideBody := []byte(`"` + strings.Repeat("a", 18) + `"`)
	wide, _ := issue9Send(placedApp, http.MethodPost, "/g/wide", wideBody, int64(len(wideBody)), issue9JSON())
	if wide.Status != http.StatusOK || placed != 3 {
		t.Fatalf("zero route %d hits %d body %s", wide.Status, placed, wide.Body)
	}
	appOver, _ := issue9Send(placedApp, http.MethodPost, "/app", wideBody, int64(len(wideBody)), issue9JSON())
	issue9Problem(t, appOver)
	if placed != 3 {
		t.Fatalf("app over hits %d", placed)
	}
	def := gfast.New()
	var defHits int
	def.Post("/d", func(ctx context.Context, in *struct{ Body string }) (*struct{}, error) {
		defHits++
		return &struct{}{}, nil
	})
	defRes, _ := issue9Send(def, http.MethodPost, "/d", []byte(`""`), 2, issue9JSON())
	if defRes.Status != http.StatusOK || defHits != 1 {
		t.Fatalf("default %d hits %d", defRes.Status, defHits)
	}

	var authHits int
	auth := gfast.New(gfast.MaxBodyBytes(4))
	auth.Post("/a", func(ctx context.Context, in *struct{ Body string }) (*struct{}, error) {
		authHits++
		return &struct{}{}, nil
	}, gfast.Require(gfast.BearerAuth()))
	missing, _ := issue9Send(auth, http.MethodPost, "/a", []byte(`"ab"`), 4, issue9JSON())
	if missing.Status != http.StatusUnauthorized || authHits != 0 {
		t.Fatalf("bearer fit %d hits %d", missing.Status, authHits)
	}
	tooBig, _ := issue9Send(auth, http.MethodPost, "/a", []byte(`"abcd"`), 1, issue9JSON())
	issue9Problem(t, tooBig)
	if authHits != 0 {
		t.Fatalf("bearer over hits %d", authHits)
	}
	bearer := issue9JSON()
	bearer.Set("Authorization", "Bearer ok")
	authed, _ := issue9Send(auth, http.MethodPost, "/a", []byte(`"ab"`), 4, bearer)
	if authed.Status != http.StatusOK || authHits != 1 {
		t.Fatalf("bearer ok %d hits %d body %s", authed.Status, authHits, authed.Body)
	}

	var mounted int
	mounts := gfast.New()
	mounts.Group("/m", gfast.MaxBodyBytes(4)).Mount("/h", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mounted++
		w.WriteHeader(http.StatusNoContent)
	}))
	mountOver, _ := issue9Send(mounts, http.MethodPost, "/m/h/", []byte("12345"), 5, nil)
	issue9Problem(t, mountOver)
	if mounted != 0 {
		t.Fatalf("mount hits %d", mounted)
	}
	mountFit, _ := issue9Send(mounts, http.MethodPost, "/m/h/", []byte("12"), 2, nil)
	if mountFit.Status != http.StatusNoContent || mounted != 1 {
		t.Fatalf("mount fit %d hits %d", mountFit.Status, mounted)
	}

	issue9CSRF(t)
	issue9OAuth(t)
	issue9Concurrent(t)
}

func issue9CSRF(t *testing.T) {
	t.Helper()
	var hits int
	app := gfast.New(gfast.Sessions(gfast.SessionConfig{Secret: "issue9-secret"}), gfast.CSRFToken())
	app.Get("/tok", func(ctx context.Context, in *struct{}) (*struct {
		T string `json:"t"`
	}, error) {
		return &struct {
			T string `json:"t"`
		}{T: gfast.CSRFTokenFrom(ctx)}, nil
	})
	primed := app.Request(http.MethodGet, "/tok", nil)
	if primed.Status != http.StatusOK {
		t.Fatalf("token %d %s", primed.Status, primed.Body)
	}
	var tok struct {
		T string `json:"t"`
	}
	if err := primed.JSON(&tok); err != nil || len(tok.T) != 43 {
		t.Fatalf("token %q %v", tok.T, err)
	}
	cookie := ""
	for _, c := range (&http.Response{Header: primed.Header}).Cookies() {
		if c.Name == "session" && c.Value != "" {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("missing session")
	}
	valid := []byte("csrf_token=" + tok.T + "&v=a")
	app.Post("/form", func(ctx context.Context, in *struct {
		V string `form:"v"`
	}) (*struct {
		V string `json:"v"`
	}, error) {
		hits++
		return &struct {
			V string `json:"v"`
		}{V: in.V}, nil
	}, gfast.MaxBodyBytes(len(valid)))
	header := issue9Form()
	header.Set("Cookie", "session="+cookie)
	fit, n := issue9Send(app, http.MethodPost, "/form", valid, -1, header)
	if fit.Status != http.StatusOK || hits != 1 || n != len(valid) || !strings.Contains(string(fit.Body), `"v":"a"`) {
		t.Fatalf("csrf fit %d hits %d read %d body %s", fit.Status, hits, n, fit.Body)
	}
	overBody := append(append([]byte{}, valid...), bytes.Repeat([]byte{'b'}, 8)...)
	over, n := issue9Send(app, http.MethodPost, "/form", overBody, 1, header)
	issue9Problem(t, over)
	if hits != 1 || n == 0 || n > len(valid)+1 {
		t.Fatalf("csrf over hits %d read %d", hits, n)
	}
	small, big := issue9Multi(t, tok.T, 1, 40)
	app.Post("/file", func(ctx context.Context, in *struct{}) (*struct{}, error) {
		hits++
		return &struct{}{}, nil
	}, gfast.MaxBodyBytes(len(small.body)))
	fileHeader := http.Header{
		"Content-Type": []string{small.ctype},
		"Cookie":       []string{"session=" + cookie},
	}
	fileFit, n := issue9Send(app, http.MethodPost, "/file", small.body, -1, fileHeader)
	if fileFit.Status != http.StatusOK || hits != 2 || n != len(small.body) {
		t.Fatalf("csrf file %d hits %d read %d body %s", fileFit.Status, hits, n, fileFit.Body)
	}
	fileHeader.Set("Content-Type", big.ctype)
	fileOver, n := issue9Send(app, http.MethodPost, "/file", big.body, 1, fileHeader)
	issue9Problem(t, fileOver)
	if hits != 2 || n == 0 || n > len(small.body)+1 {
		t.Fatalf("csrf file over hits %d read %d", hits, n)
	}
	again, _ := issue9Send(app, http.MethodPost, "/form", valid, int64(len(valid)), header)
	if again.Status != http.StatusOK || hits != 3 {
		t.Fatalf("csrf again %d hits %d", again.Status, hits)
	}
}

type issue9Part struct {
	body  []byte
	ctype string
}

func issue9Multi(t *testing.T, token string, smallN, extra int) (issue9Part, issue9Part) {
	t.Helper()
	build := func(n int) issue9Part {
		t.Helper()
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		if err := w.SetBoundary("issue9boundary"); err != nil {
			t.Fatal(err)
		}
		if token != "" {
			if err := w.WriteField("csrf_token", token); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.WriteField("v", strings.Repeat("a", n)); err != nil {
			t.Fatal(err)
		}
		part, err := w.CreateFormFile("f", "a.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(bytes.Repeat([]byte{'b'}, n)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return issue9Part{body: buf.Bytes(), ctype: w.FormDataContentType()}
	}
	return build(smallN), build(smallN + extra)
}

func issue9OAuth(t *testing.T) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", "ada")
	form.Set("password", "pw")
	form.Set("client_id", "c")
	encoded := []byte(form.Encode())
	big := append(append([]byte{}, encoded...), bytes.Repeat([]byte{'a'}, 8)...)
	var calls atomic.Int32
	app := gfast.New(gfast.MaxBodyBytes(len(encoded)), gfast.OAuthServer(gfast.OAuthConfig{
		Clients: []gfast.OAuthClient{{ID: "c"}},
		Password: func(ctx context.Context, username, password string) (string, error) {
			calls.Add(1)
			if username == "ada" && password == "pw" {
				return "ada", nil
			}
			return "", nil
		},
	}))
	token, n := issue9Send(app, http.MethodPost, "/oauth/token", big, 1, issue9Form())
	issue9Problem(t, token)
	auth, n2 := issue9Send(app, http.MethodPost, "/oauth/authorize?client_id=c", big, int64(len(big)), issue9Form())
	issue9Problem(t, auth)
	if calls.Load() != 0 || n == 0 || n > len(encoded)+1 || n2 != 0 {
		t.Fatalf("oauth calls %d token read %d authorize read %d", calls.Load(), n, n2)
	}
	ok := app.Request(http.MethodPost, "/oauth/token", encoded, issue9Form())
	if ok.Status != http.StatusOK || calls.Load() != 1 || !strings.Contains(string(ok.Body), "access_token") {
		t.Fatalf("oauth after %d calls %d body %s", ok.Status, calls.Load(), ok.Body)
	}
}

func issue9Concurrent(t *testing.T) {
	t.Helper()
	app := gfast.New(gfast.MaxBodyBytes(1))
	var hits atomic.Int32
	app.Post("/n", func(ctx context.Context, in *struct{ Body int }) (*struct{}, error) {
		hits.Add(1)
		return &struct{}{}, nil
	})
	var wg sync.WaitGroup
	var bad atomic.Int32
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			res, n := issue9Send(app, http.MethodPost, "/n", []byte("10"), -1, issue9JSON())
			if res.Status != http.StatusRequestEntityTooLarge || n == 0 || n > 2 {
				bad.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			res, n := issue9Send(app, http.MethodPost, "/n", []byte("1"), 1, issue9JSON())
			if res.Status != http.StatusOK || n != 1 {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 || hits.Load() != 8 {
		t.Fatalf("concurrent bad %d hits %d", bad.Load(), hits.Load())
	}
}

func TestIssue9ChunkedTCP(t *testing.T) {
	var hits int
	app := gfast.New(gfast.MaxBodyBytes(4))
	app.Post("/j", func(ctx context.Context, in *struct{ Body int }) (*struct{}, error) {
		hits++
		return &struct{}{}, nil
	})
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	host := srv.Listener.Addr().String()
	over := "POST /j HTTP/1.1\r\nHost: " + host + "\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n12345\r\n0\r\n\r\n"
	if status := issue9Dial(t, host, over); status != http.StatusRequestEntityTooLarge || hits != 0 {
		t.Fatalf("tcp chunked %d hits %d", status, hits)
	}
	fit := "POST /j HTTP/1.1\r\nHost: " + host + "\r\nContent-Type: application/json\r\nContent-Length: 1\r\n\r\n1"
	if status := issue9Dial(t, host, fit); status != http.StatusOK || hits != 1 {
		t.Fatalf("tcp next %d hits %d", status, hits)
	}
}

func issue9Dial(t *testing.T, host, payload string) int {
	t.Helper()
	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		t.Fatalf("status %q", line)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	length := 0
	for {
		header, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if header == "\r\n" || header == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(header), "content-length:") {
			length, err = strconv.Atoi(strings.TrimSpace(header[len("content-length:"):]))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if length > 0 {
		if _, err := io.ReadFull(br, make([]byte, length)); err != nil {
			t.Fatal(err)
		}
	}
	return status
}

func TestPropMaxBodyBytes(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		kind := hegel.Draw(ht, hegel.Integers(0, 5)) // json, form, multipart field, multipart file, oauth, csrf
		rel := hegel.Draw(ht, hegel.Integers(-1, 1)) // -1 under, 0 at, +1 over
		framing := hegel.Draw(ht, hegel.Integers(0, 2))
		where := hegel.Draw(ht, hegel.Integers(0, 2)) // app, group, route
		part := hegel.Draw(ht, hegel.Integers(0, 16))
		want := strings.Repeat("a", part)
		var raw []byte
		var ctype string
		switch kind {
		case 0:
			raw = []byte(`{"v":"` + want + `"}`)
			ctype = "application/json"
		case 1:
			raw = []byte("v=" + want)
			ctype = "application/x-www-form-urlencoded"
		case 2, 3:
			built, _ := issue9Multi(t, "", part, 0)
			raw = built.body
			ctype = built.ctype
		case 4:
			raw = []byte("grant_type=password&username=ada&password=pw&client_id=c&x=" + want)
			ctype = "application/x-www-form-urlencoded"
		default:
			raw = []byte("csrf_token=" + strings.Repeat("x", 43) + "&v=" + want)
			ctype = "application/x-www-form-urlencoded"
		}
		if rel == 1 && len(raw) < 2 {
			ht.Fatalf("body %d", len(raw))
		}
		limit := len(raw) - rel
		over := len(raw) > limit
		var calls atomic.Int32
		opts := []gfast.Option{}
		if kind == 4 || where == 0 {
			opts = append(opts, gfast.MaxBodyBytes(limit))
		}
		if kind == 4 {
			opts = append(opts, gfast.OAuthServer(gfast.OAuthConfig{
				Clients: []gfast.OAuthClient{{ID: "c"}},
				Password: func(ctx context.Context, username, password string) (string, error) {
					calls.Add(1)
					if username == "ada" && password == "pw" {
						return "ada", nil
					}
					return "", nil
				},
			}))
		}
		if kind == 5 {
			opts = append(opts, gfast.Sessions(gfast.SessionConfig{Secret: "prop-secret"}), gfast.CSRFToken())
		}
		app := gfast.New(opts...)
		var hits int
		var path string
		switch kind {
		case 0:
			path = issue9At(app, where, limit, func(ctx context.Context, in *struct {
				V string `json:"v"`
			}) (*struct {
				V string `json:"v"`
			}, error) {
				hits++
				return in, nil
			})
		case 1, 5:
			path = issue9At(app, where, limit, func(ctx context.Context, in *struct {
				V string `form:"v"`
			}) (*struct {
				V string `json:"v"`
			}, error) {
				hits++
				return &struct {
					V string `json:"v"`
				}{V: in.V}, nil
			})
		case 2:
			path = issue9At(app, where, limit, func(ctx context.Context, in *struct {
				V string `form:"v"`
			}) (*struct {
				V string `json:"v"`
			}, error) {
				hits++
				return &struct {
					V string `json:"v"`
				}{V: in.V}, nil
			})
		case 3:
			path = issue9At(app, where, limit, func(ctx context.Context, in *struct {
				F *multipart.FileHeader `file:"f"`
			}) (*struct {
				N int `json:"n"`
			}, error) {
				hits++
				if in.F == nil {
					return nil, gfast.BadRequest("missing file")
				}
				f, err := in.F.Open()
				if err != nil {
					return nil, err
				}
				defer f.Close()
				buf, err := io.ReadAll(f)
				if err != nil {
					return nil, err
				}
				return &struct {
					N int `json:"n"`
				}{N: len(buf)}, nil
			})
		}
		header := http.Header{"Content-Type": []string{ctype}}
		if kind == 5 {
			app.Get("/tok", func(ctx context.Context, in *struct{}) (*struct {
				T string `json:"t"`
			}, error) {
				return &struct {
					T string `json:"t"`
				}{T: gfast.CSRFTokenFrom(ctx)}, nil
			})
			primed := app.Request(http.MethodGet, "/tok", nil)
			if primed.Status != http.StatusOK {
				ht.Fatalf("token %d %s", primed.Status, primed.Body)
			}
			var tok struct {
				T string `json:"t"`
			}
			if err := primed.JSON(&tok); err != nil {
				ht.Fatal(err)
			}
			if len(tok.T) != 43 {
				ht.Fatalf("token length %d", len(tok.T))
			}
			raw = []byte("csrf_token=" + tok.T + "&v=" + want)
			if len(raw) != limit+rel {
				ht.Fatalf("csrf body %d limit %d rel %d", len(raw), limit, rel)
			}
			cookie := ""
			for _, c := range (&http.Response{Header: primed.Header}).Cookies() {
				if c.Name == "session" {
					cookie = c.Value
				}
			}
			if cookie == "" {
				ht.Fatal("missing session")
			}
			header.Set("Cookie", "session="+cookie)
		}
		if kind != 4 {
			app.Post("/ok", func(ctx context.Context, in *struct{}) (*struct{}, error) {
				return &struct{}{}, nil
			}, gfast.MaxBodyBytes(0))
		}
		cl := int64(len(raw))
		if framing == 1 {
			cl = 1
		}
		if framing == 2 {
			cl = -1
		}
		target := path
		if kind == 4 {
			target = "/oauth/token"
		}
		res, counted := issue9Send(app, http.MethodPost, target, raw, cl, header)
		if counted > limit+1 {
			ht.Fatalf("read %d limit %d kind %d framing %d", counted, limit, kind, framing)
		}
		if over && framing != 0 && (counted <= limit || counted > limit+1) {
			ht.Fatalf("short or chunked read %d limit %d kind %d", counted, limit, kind)
		}
		if over && framing == 0 && counted != 0 {
			ht.Fatalf("declared length consumed %d", counted)
		}
		if !over && counted != len(raw) {
			ht.Fatalf("fit read %d body %d kind %d framing %d", counted, len(raw), kind, framing)
		}
		if kind == 4 {
			if over {
				if calls.Load() != 0 {
					ht.Fatalf("password ran")
				}
				hpProblem(ht, res, http.StatusRequestEntityTooLarge, "request body too large")
			} else if res.Status != http.StatusOK || calls.Load() != 1 || !strings.Contains(string(res.Body), "access_token") {
				ht.Fatalf("token %d calls %d body %s", res.Status, calls.Load(), res.Body)
			}
			form := url.Values{}
			form.Set("grant_type", "password")
			form.Set("username", "ada")
			form.Set("password", "pw")
			form.Set("client_id", "c")
			next := app.Request(http.MethodPost, "/oauth/token", []byte(form.Encode()), issue9Form())
			wantCalls := int32(1)
			if !over {
				wantCalls = 2
			}
			if next.Status != http.StatusOK || calls.Load() != wantCalls {
				ht.Fatalf("next %d calls %d body %s", next.Status, calls.Load(), next.Body)
			}
			return
		}
		if over {
			if hits != 0 {
				ht.Fatalf("handler ran kind %d", kind)
			}
			hpProblem(ht, res, http.StatusRequestEntityTooLarge, "request body too large")
		} else if hits != 1 || res.Status != http.StatusOK {
			ht.Fatalf("kind %d status %d hits %d body %s", kind, res.Status, hits, res.Body)
		} else if kind == 3 {
			var got struct {
				N int `json:"n"`
			}
			if err := res.JSON(&got); err != nil {
				ht.Fatal(err)
			}
			if got.N != part {
				ht.Fatalf("file %d want %d", got.N, part)
			}
		} else {
			var got struct {
				V string `json:"v"`
			}
			if err := res.JSON(&got); err != nil {
				ht.Fatal(err)
			}
			if got.V != want {
				ht.Fatalf("value %q want %q", got.V, want)
			}
		}
		if res.Status == http.StatusRequestEntityTooLarge && res.Header.Get("Connection") != "close" {
			ht.Fatalf("connection %q", res.Header.Get("Connection"))
		}
		ok := app.Request(http.MethodPost, "/ok", nil)
		if ok.Status != http.StatusOK {
			ht.Fatalf("next %d %s", ok.Status, ok.Body)
		}
	})
}

func issue9At[I, O any](app *gfast.App, where, limit int, handler func(context.Context, *I) (*O, error)) string {
	switch where {
	case 1:
		app.Group("/g", gfast.MaxBodyBytes(limit)).Post("/p", handler)
		return "/g/p"
	case 2:
		app.Post("/p", handler, gfast.MaxBodyBytes(limit))
		return "/p"
	default:
		app.Post("/p", handler)
		return "/p"
	}
}

func reviewPasswordToken(t *testing.T, app *gfast.App, clientID string) (string, string) {
	t.Helper()
	res := reviewPasswordGrant(app, clientID)
	if res.Status != http.StatusOK {
		t.Fatalf("password %d %s", res.Status, res.Body)
	}
	var body struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if err := res.JSON(&body); err != nil {
		t.Fatal(err)
	}
	if body.Access == "" || body.Refresh == "" {
		t.Fatalf("password body %s", res.Body)
	}
	return body.Access, body.Refresh
}

func reviewPanic(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		rec := recover()
		if rec != want {
			t.Fatalf("panic %v want %q", rec, want)
		}
	}()
	fn()
}
