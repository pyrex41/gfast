package gfast

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type contractResource struct {
	id     string
	events *[]string
}

func (r *contractResource) Close() error {
	*r.events = append(*r.events, "close:"+r.id)
	if strings.HasSuffix(r.id, "!panic") {
		panic(r.id)
	}
	return nil
}

type contractChild struct{ contractResource }
type contractContextKey struct{}

var contractRoot = Dep("contractRoot", func(ctx context.Context) (*contractResource, error) {
	events := ctx.Value(contractContextKey{}).(*[]string)
	*events = append(*events, "acquire:root")
	return &contractResource{"root", events}, nil
})
var contractLeaf = Dep("contractLeaf", func(ctx context.Context, root *contractResource) (*contractChild, error) {
	*root.events = append(*root.events, "acquire:leaf")
	return &contractChild{contractResource{"leaf", root.events}}, nil
})

func TestContractDependencyCleanup(t *testing.T) {
	for _, mode := range []string{"success", "error", "panic", "cancel", "partial"} {
		t.Run(mode, func(t *testing.T) {
			app := New(Docs(false))
			if mode == "partial" {
				app.Override(contractLeaf, func(ctx context.Context, root *contractResource) (*contractChild, error) {
					return nil, errors.New("acquisition failed")
				})
			}
			app.Get("/", func(ctx context.Context, in *struct {
				A *contractResource `gfast:"dep=contractRoot"`
				B *contractResource `gfast:"dep=contractRoot"`
				C *contractChild    `gfast:"dep=contractLeaf"`
			}) (*struct{}, error) {
				if in.A != in.B {
					t.Error("request memoization lost identity")
				}
				switch mode {
				case "panic":
					panic("handler panic")
				case "error":
					return nil, errors.New("handler failure")
				case "cancel":
					if ctx.Err() != context.Canceled {
						t.Error("cancellation lost")
					}
				}
				return &struct{}{}, nil
			})
			var events []string
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contractContextKey{}, &events))
			defer cancel()
			if mode == "cancel" {
				cancel()
			}
			var recovered any
			func() {
				defer func() { recovered = recover() }()
				app.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil).WithContext(ctx))
			}()
			if (recovered != nil) != (mode == "panic") {
				t.Fatalf("unexpected panic: %v", recovered)
			}
			want := []string{"acquire:root", "acquire:leaf", "close:leaf", "close:root"}
			if mode == "partial" {
				want = []string{"acquire:root", "close:root"}
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("events %v want %v", events, want)
			}
		})
	}
}

func TestContractCleanupDespiteCallbackPanic(t *testing.T) {
	for _, mode := range []string{"closer", "background", "both-closers"} {
		t.Run(mode, func(t *testing.T) {
			app := New(Docs(false))
			if mode != "background" {
				app.Override(contractLeaf, func(ctx context.Context, root *contractResource) (*contractChild, error) {
					*root.events = append(*root.events, "acquire:leaf")
					return &contractChild{contractResource{"leaf!panic", root.events}}, nil
				})
			}
			if mode == "both-closers" {
				app.Override(contractRoot, func(ctx context.Context) (*contractResource, error) {
					events := ctx.Value(contractContextKey{}).(*[]string)
					*events = append(*events, "acquire:root")
					return &contractResource{"root!panic", events}, nil
				})
			}
			app.Get("/", func(ctx context.Context, in *struct {
				C *contractChild `gfast:"dep=contractLeaf"`
			}) (*struct{}, error) {
				if mode == "background" {
					Background(ctx, func() { panic("background") })
				}
				return &struct{}{}, nil
			})
			var events []string
			var recovered any
			ctx := context.WithValue(context.Background(), contractContextKey{}, &events)
			func() {
				defer func() { recovered = recover() }()
				app.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil).WithContext(ctx))
			}()
			wantPanic := "leaf!panic"
			leaf, root := "leaf!panic", "root"
			if mode == "background" {
				wantPanic, leaf = "background", "leaf"
			}
			if mode == "both-closers" {
				root = "root!panic"
			}
			want := []string{"acquire:root", "acquire:leaf", "close:" + leaf, "close:" + root}
			if recovered != wantPanic || !reflect.DeepEqual(events, want) {
				t.Fatalf("panic=%v events=%v; want panic=%s events=%v", recovered, events, wantPanic, want)
			}
		})
	}
}

func TestContractAuthorizationMetamorphic(t *testing.T) {
	app := New(Docs(false))
	called := 0
	app.Get("/private", func(context.Context, *struct{}) (*struct{}, error) { called++; return &struct{}{}, nil }, Require(BearerAuth()))
	for _, extra := range []string{"", "irrelevant", "another-value"} {
		for _, token := range []string{"", "Basic abc", "Bearer token"} {
			r := httptest.NewRequest("GET", "/private?unrelated="+extra, nil)
			r.Header.Set("X-Unrelated", extra)
			r.Header.Set("Authorization", token)
			before := called
			w := httptest.NewRecorder()
			app.Handler().ServeHTTP(w, r)
			want := 401
			if token == "Bearer token" {
				want = 200
			}
			if w.Code != want || (called > before) != (want == 200) {
				t.Fatalf("token %q extra %q: status=%d calls=%d", token, extra, w.Code, called-before)
			}
		}
	}
}

func contractOAuth(now func() time.Time, capacity int) *oauthServer {
	return newOAuthServer(&OAuthConfig{Clients: []OAuthClient{{ID: "client", Secret: "secret"}}, MaxCodes: capacity, MaxRefresh: capacity, Now: now})
}

// Barrier release forces all consumers to compete for the same stored token.
func TestContractOAuthConcurrentConsume(t *testing.T) {
	for _, kind := range []string{"code", "refresh"} {
		t.Run(kind, func(t *testing.T) {
			s := contractOAuth(nil, 2)
			var raw string
			if kind == "code" {
				var err error
				raw, err = s.putCode(&authCode{clientID: "client", redirectURI: "/callback"})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				issued, err := s.issue("user", "client", nil, true)
				if err != nil {
					t.Fatal(err)
				}
				raw = issued.RefreshToken
			}
			start := make(chan struct{})
			results := make(chan bool, 32)
			var ready sync.WaitGroup
			ready.Add(32)
			for range 32 {
				go func() {
					ready.Done()
					<-start
					if kind == "code" {
						results <- s.consumeCode(raw, "client", "/callback") != nil
					} else {
						results <- s.consumeRefresh(raw, "client") != nil
					}
				}()
			}
			ready.Wait()
			close(start)
			successes := 0
			for range 32 {
				if <-results {
					successes++
				}
			}
			if successes != 1 {
				t.Fatalf("%d consumers succeeded", successes)
			}
		})
	}
}

func refreshRequest(s *oauthServer, token, scope string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/oauth/token", nil)
	r.PostForm = url.Values{"refresh_token": {token}, "scope": {scope}}
	w := httptest.NewRecorder()
	s.grantRefresh(w, r, s.clients["client"])
	return w
}

func TestContractOAuthRotation(t *testing.T) {
	s := contractOAuth(nil, 1)
	first, err := s.issue("user", "client", []string{"read"}, true)
	if err != nil {
		t.Fatal(err)
	}
	w := refreshRequest(s, first.RefreshToken, "read")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var next tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	if next.RefreshToken == "" || next.RefreshToken == first.RefreshToken {
		t.Fatal("rotation did not replace token")
	}
	if w := refreshRequest(s, first.RefreshToken, ""); w.Code != 400 {
		t.Fatal("old token was reusable")
	}
	if w := refreshRequest(s, next.RefreshToken, "admin"); w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_scope") {
		t.Fatal("scope escalation accepted")
	}
	if w := refreshRequest(s, next.RefreshToken, "read"); w.Code != 400 {
		t.Fatal("failed scope check must burn consumed token")
	}
}

// This trace also appears in formal/README.md. Consume and issue are separate
// critical sections: a competing issuer may take the newly freed slot.
func TestContractOAuthCapacityFailureTrace(t *testing.T) {
	s := contractOAuth(nil, 1)
	first, err := s.issue("user", "client", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if s.consumeRefresh(first.RefreshToken, "client") == nil {
		t.Fatal("consume failed")
	}
	if _, err := s.issue("competitor", "client", nil, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.issue("user", "client", nil, true); !errors.Is(err, errOAuthStoreFull) {
		t.Fatalf("want capacity failure: %v", err)
	}
	if s.consumeRefresh(first.RefreshToken, "client") != nil {
		t.Fatal("failed rotation resurrected old token")
	}
	if len(s.refreshes) != 1 {
		t.Fatal("capacity exceeded")
	}
}

func TestContractOAuthExpiryBoundary(t *testing.T) {
	now := time.Unix(1000, 0)
	s := contractOAuth(func() time.Time { return now }, 1)
	code, err := s.putCode(&authCode{clientID: "client", redirectURI: "/callback"})
	if err != nil {
		t.Fatal(err)
	}
	if s.consumeCode(code, "wrong", "/callback") != nil {
		t.Fatal("wrong client accepted")
	}
	now = now.Add(s.codeTTL)
	if s.consumeCode(code, "client", "/callback") != nil {
		t.Fatal("token valid at expiry")
	}
	if len(s.codes) != 0 {
		t.Fatal("expired code not swept")
	}
	issued, err := s.issue("user", "client", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(s.refreshTTL)
	if s.consumeRefresh(issued.RefreshToken, "client") != nil {
		t.Fatal("refresh valid at expiry")
	}
}

func TestContractIndependentApps(t *testing.T) {
	apps := []*App{New(Docs(false)), New(Docs(false))}
	for i, app := range apps {
		app.Override(contractRoot, func(context.Context) (*contractResource, error) {
			events := []string{}
			return &contractResource{fmt.Sprint(i), &events}, nil
		})
		app.Get("/", func(_ context.Context, in *struct {
			R *contractResource `gfast:"dep=contractRoot"`
		}) (*string, error) {
			return &in.R.id, nil
		})
	}
	var wg sync.WaitGroup
	for i, app := range apps {
		wg.Go(func() {
			for range 20 {
				w := httptest.NewRecorder()
				app.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
				if w.Body.String() != fmt.Sprintf("%q", fmt.Sprint(i)) {
					t.Errorf("app %d received %s", i, w.Body.String())
				}
			}
		})
	}
	wg.Wait()
}
