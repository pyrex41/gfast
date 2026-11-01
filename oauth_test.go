package gfast_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/pyrex41/gfast"
)

type oauthWho struct {
	Subject  string `json:"subject"`
	ClientID string `json:"clientId"`
	Route    string `json:"route"`
	Granted  string `json:"granted"`
}

var oauthHits atomic.Int32

var oauthSubject = gfast.Dep("OAuthSubject", func(ctx context.Context, cred gfast.Bearer) (oauthWho, error) {
	oauthHits.Add(1)
	return oauthWho{
		Subject:  cred.Subject,
		ClientID: cred.ClientID,
		Route:    strings.Join(cred.Scopes, " "),
		Granted:  strings.Join(cred.TokenScopes, " "),
	}, nil
})

func TestOAuthCodeExchangeAndPKCE(t *testing.T) {
	const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	challenge := pkceChallenge(verifier)
	app := newOAuthApp(t, true)

	code := authorizeCode(t, app, challenge, http.Header{"Cookie": []string{"sid=ok"}}, http.StatusFound)
	good := exchangeCode(t, app, code, "http://localhost/cb", verifier)
	if good.TokenType != "Bearer" || good.ExpiresIn != 3600 || good.Scope != "items:write" || good.Refresh == "" || good.Access == "" {
		t.Fatalf("token response %+v", good)
	}
	oauthHits.Store(0)
	me := app.Request(http.MethodGet, "/me", nil, http.Header{"Authorization": []string{"Bearer " + good.Access}})
	if me.Status != http.StatusOK || oauthHits.Load() != 1 {
		t.Fatalf("me %d %s hits %d", me.Status, me.Body, oauthHits.Load())
	}
	var who oauthWho
	if err := me.JSON(&who); err != nil {
		t.Fatal(err)
	}
	if who.Subject != "ada" || who.ClientID != "app" || who.Route != "items:read" || who.Granted != "items:write" {
		t.Fatalf("who %+v", who)
	}

	oauthHits.Store(0)
	badBearer := app.Request(http.MethodGet, "/me", nil, http.Header{"Authorization": []string{"Bearer nope"}})
	if badBearer.Status != http.StatusUnauthorized || oauthHits.Load() != 0 || !strings.Contains(string(badBearer.Body), "invalid bearer token") {
		t.Fatalf("bad bearer %d %s hits %d", badBearer.Status, badBearer.Body, oauthHits.Load())
	}

	second := authorizeCode(t, app, challenge, http.Header{"Cookie": []string{"sid=ok"}}, http.StatusFound)
	bad := tokenForm(t, app, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {second},
		"redirect_uri":  {"http://localhost/cb"},
		"client_id":     {"app"},
		"code_verifier": {strings.Repeat("a", 43)},
	})
	if bad.Status != http.StatusBadRequest || !strings.Contains(string(bad.Body), `"invalid_grant"`) || !strings.Contains(string(bad.Body), "pkce verification failed") {
		t.Fatalf("bad pkce %d %s", bad.Status, bad.Body)
	}
	reused := tokenForm(t, app, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {second},
		"redirect_uri":  {"http://localhost/cb"},
		"client_id":     {"app"},
		"code_verifier": {verifier},
	})
	if reused.Status != http.StatusBadRequest || !strings.Contains(string(reused.Body), `"invalid_grant"`) {
		t.Fatalf("reused code %d %s", reused.Status, reused.Body)
	}

	refreshed := tokenForm(t, app, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {good.Refresh},
		"client_id":     {"app"},
	})
	if refreshed.Status != http.StatusOK || !strings.Contains(string(refreshed.Body), `"refresh_token"`) {
		t.Fatalf("refresh %d %s", refreshed.Status, refreshed.Body)
	}
	var rotated oauthToken
	if err := refreshed.JSON(&rotated); err != nil {
		t.Fatal(err)
	}
	if rotated.Refresh == "" || rotated.Refresh == good.Refresh || rotated.Access == "" {
		t.Fatalf("rotated %+v", rotated)
	}
	again := tokenForm(t, app, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {good.Refresh},
		"client_id":     {"app"},
	})
	if again.Status != http.StatusBadRequest || !strings.Contains(string(again.Body), `"invalid_grant"`) {
		t.Fatalf("spent refresh %d %s", again.Status, again.Body)
	}

	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc:top-secret"))
	clientTok := tokenForm(t, app, url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"items:read"},
	}, http.Header{"Authorization": []string{basic}})
	if clientTok.Status != http.StatusOK || strings.Contains(string(clientTok.Body), `"refresh_token"`) {
		t.Fatalf("client credentials %d %s", clientTok.Status, clientTok.Body)
	}
	var svc oauthToken
	if err := clientTok.JSON(&svc); err != nil {
		t.Fatal(err)
	}
	svcMe := app.Request(http.MethodGet, "/me", nil, http.Header{"Authorization": []string{"Bearer " + svc.Access}})
	var svcWho oauthWho
	if err := svcMe.JSON(&svcWho); err != nil {
		t.Fatal(err)
	}
	if svcMe.Status != http.StatusOK || svcWho.Subject != "svc" || svcWho.ClientID != "svc" || svcWho.Granted != "items:read" {
		t.Fatalf("svc %d %+v", svcMe.Status, svcWho)
	}

	password := tokenForm(t, app, url.Values{
		"grant_type": {"password"},
		"username":   {"ada"},
		"password":   {"secret"},
		"client_id":  {"app"},
		"scope":      {"items:read"},
	})
	if password.Status != http.StatusOK || !strings.Contains(string(password.Body), `"access_token"`) {
		t.Fatalf("password grant %d %s", password.Status, password.Body)
	}

	form := app.Request(http.MethodGet, authorizePath(challenge), nil)
	if form.Status != http.StatusOK || !strings.Contains(string(form.Body), `action="/oauth/authorize?`) || !strings.Contains(string(form.Body), "Sign in") {
		t.Fatalf("login form %d %s", form.Status, form.Body)
	}
	posted := app.Request(http.MethodPost, authorizePath(challenge), []byte(url.Values{
		"username": {"ada"},
		"password": {"secret"},
	}.Encode()), http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}})
	if posted.Status != http.StatusSeeOther {
		t.Fatalf("login redirect %d %s", posted.Status, posted.Body)
	}
	loginCode := codeFrom(t, posted.Header.Get("Location"))
	loggedIn := exchangeCode(t, app, loginCode, "http://localhost/cb", verifier)
	if loggedIn.Access == "" {
		t.Fatal("login exchange missed a token")
	}

	spec := app.Request(http.MethodGet, "/openapi.json", nil)
	var doc map[string]any
	if err := spec.JSON(&doc); err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	op := paths["/me"].(map[string]any)["get"].(map[string]any)
	sec := op["security"].([]any)[0].(map[string]any)
	rawScopes := sec["bearerAuth"].([]any)
	if len(rawScopes) != 1 || rawScopes[0] != "items:read" {
		t.Fatalf("security %#v", sec)
	}
	schemes := doc["components"].(map[string]any)["securitySchemes"].(map[string]any)
	bearer := schemes["bearerAuth"].(map[string]any)
	if bearer["type"] != "oauth2" || bearer["scheme"] != nil {
		t.Fatalf("scheme %#v", bearer)
	}
	if !strings.Contains(bearer["description"].(string), "process restart drops them") {
		t.Fatalf("description %#v", bearer["description"])
	}
	flows := bearer["flows"].(map[string]any)
	authFlow := flows["authorizationCode"].(map[string]any)
	if authFlow["authorizationUrl"] != "/oauth/authorize" || authFlow["tokenUrl"] != "/oauth/token" {
		t.Fatalf("auth flow %#v", authFlow)
	}
	if flows["clientCredentials"].(map[string]any)["tokenUrl"] != "/oauth/token" {
		t.Fatalf("client flow %#v", flows["clientCredentials"])
	}
	if flows["password"].(map[string]any)["tokenUrl"] != "/oauth/token" {
		t.Fatalf("password flow %#v", flows["password"])
	}
	if authFlow["scopes"].(map[string]any)["items:read"] != "Read items" {
		t.Fatalf("scopes %#v", authFlow["scopes"])
	}

	docs := app.Request(http.MethodGet, "/docs", nil)
	if !strings.Contains(string(docs.Body), `oauth2RedirectUrl: window.location.origin + "/docs/oauth2-redirect"`) || !strings.Contains(string(docs.Body), "usePkceWithAuthorizationCodeGrant:true") {
		t.Fatalf("docs missing oauth config: %s", docs.Body)
	}
	if strings.Contains(string(docs.Body), "clientId:") {
		t.Fatalf("docs prefilled a client id for more than one client: %s", docs.Body)
	}
	page := app.Request(http.MethodGet, "/docs/oauth2-redirect", nil)
	if page.Status != http.StatusOK || !strings.Contains(page.Header.Get("Content-Type"), "text/html") || !strings.Contains(string(page.Body), "oauth2-redirect.js") {
		t.Fatalf("redirect page %d %s", page.Status, page.Body)
	}
	script := app.Request(http.MethodGet, "/docs/oauth2-redirect.js", nil)
	if script.Status != http.StatusOK || !strings.Contains(string(script.Body), "swaggerUIRedirectOauth2") {
		t.Fatalf("redirect script %d", script.Status)
	}

	docsCode := authorizeCode(t, app, challenge, http.Header{"Cookie": []string{"sid=ok"}}, http.StatusFound, "http://example.com/docs/oauth2-redirect")
	docsTok := exchangeCode(t, app, docsCode, "http://example.com/docs/oauth2-redirect", verifier)
	if docsTok.Access == "" {
		t.Fatal("docs redirect exchange failed")
	}
}

func TestOAuthDisabledAndPasswordGrantOff(t *testing.T) {
	off := gfast.New()
	off.Get("/me", func(ctx context.Context, in *struct {
		User principal `gfast:"dep=CurrentUser"`
	}) (*principal, error) {
		return &principal{ID: "u"}, nil
	})
	token := off.Request(http.MethodPost, "/oauth/token", []byte("grant_type=client_credentials"), http.Header{
		"Content-Type": []string{"application/x-www-form-urlencoded"},
	})
	if token.Status != http.StatusNotFound {
		t.Fatalf("token mounted %d %s", token.Status, token.Body)
	}
	auth := off.Request(http.MethodGet, "/oauth/authorize", nil)
	if auth.Status != http.StatusNotFound {
		t.Fatalf("authorize mounted %d", auth.Status)
	}
	docs := off.Request(http.MethodGet, "/docs", nil)
	if !strings.Contains(string(docs.Body), `oauth2RedirectUrl: window.location.origin + "/docs/oauth2-redirect"`) || strings.Contains(string(docs.Body), "initOAuth") {
		t.Fatalf("docs oauth config %s", docs.Body)
	}
	spec := off.Request(http.MethodGet, "/openapi.json", nil)
	if !strings.Contains(string(spec.Body), `"scheme":"bearer"`) || strings.Contains(string(spec.Body), `"oauth2"`) {
		t.Fatalf("scheme changed while server is off: %s", spec.Body)
	}
	page := off.Request(http.MethodGet, "/docs/oauth2-redirect", nil)
	if page.Status != http.StatusOK || !strings.Contains(string(page.Body), "oauth2-redirect.js") {
		t.Fatalf("redirect asset %d %s", page.Status, page.Body)
	}

	sessionOnly := gfast.New(gfast.OAuthServer(gfast.OAuthConfig{
		Clients: []gfast.OAuthClient{{
			ID:           "only",
			RedirectURIs: []string{"http://localhost/cb"},
		}},
		Session: func(ctx context.Context, r *http.Request) (string, error) {
			return "", nil
		},
	}))
	sessionOnly.Get("/me", func(ctx context.Context, in *struct {
		Who oauthWho `gfast:"dep=OAuthSubject"`
	}) (*oauthWho, error) {
		return &in.Who, nil
	})
	denied := tokenForm(t, sessionOnly, url.Values{
		"grant_type": {"password"},
		"username":   {"ada"},
		"password":   {"secret"},
		"client_id":  {"only"},
	})
	if denied.Status != http.StatusBadRequest || !strings.Contains(string(denied.Body), `"unsupported_grant_type"`) {
		t.Fatalf("password grant %d %s", denied.Status, denied.Body)
	}
	one := sessionOnly.Request(http.MethodGet, "/docs", nil)
	if !strings.Contains(string(one.Body), `clientId:"only"`) || !strings.Contains(string(one.Body), "usePkceWithAuthorizationCodeGrant:true") {
		t.Fatalf("single client docs %s", one.Body)
	}
	oneSpec := sessionOnly.Request(http.MethodGet, "/openapi.json", nil)
	if strings.Contains(string(oneSpec.Body), `"password"`) {
		t.Fatalf("password flow advertised: %s", oneSpec.Body)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	gfast.New(gfast.OAuthServer(gfast.OAuthConfig{}))
}

type oauthToken struct {
	Access    string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
	Refresh   string `json:"refresh_token"`
	Scope     string `json:"scope"`
}

func newOAuthApp(t *testing.T, password bool) *gfast.App {
	t.Helper()
	cfg := gfast.OAuthConfig{
		Clients: []gfast.OAuthClient{
			{ID: "app", RedirectURIs: []string{"http://localhost/cb"}},
			{ID: "svc", Secret: "top-secret"},
		},
		Scopes: map[string]string{
			"items:read":  "Read items",
			"items:write": "Write items",
		},
		Session: func(ctx context.Context, r *http.Request) (string, error) {
			c, err := r.Cookie("sid")
			if err != nil || c.Value != "ok" {
				return "", nil
			}
			return "ada", nil
		},
	}
	if password {
		cfg.Password = func(ctx context.Context, username, password string) (string, error) {
			if username == "ada" && password == "secret" {
				return "ada", nil
			}
			return "", gfast.Unauthorized("invalid username or password")
		}
	}
	app := gfast.New(gfast.OAuthServer(cfg))
	app.Get("/me", func(ctx context.Context, in *struct {
		Who oauthWho `gfast:"dep=OAuthSubject"`
	}) (*oauthWho, error) {
		return &in.Who, nil
	}, gfast.Scopes("items:read"))
	return app
}

func authorizePath(challenge string) string {
	return authorizePathRedirect(challenge, "http://localhost/cb")
}

func authorizePathRedirect(challenge, redirect string) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"app"},
		"redirect_uri":          {redirect},
		"state":                 {"xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"items:write"},
	}
	return "/oauth/authorize?" + q.Encode()
}

func authorizeCode(t *testing.T, app *gfast.App, challenge string, header http.Header, status int, redirect ...string) string {
	t.Helper()
	target := "http://localhost/cb"
	if len(redirect) > 0 {
		target = redirect[0]
	}
	res := app.Request(http.MethodGet, authorizePathRedirect(challenge, target), nil, header)
	if res.Status != status {
		t.Fatalf("authorize %d %s location %q", res.Status, res.Body, res.Header.Get("Location"))
	}
	return codeFrom(t, res.Header.Get("Location"))
}

func codeFrom(t *testing.T, location string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("state") != "" && u.Query().Get("state") != "xyz" {
		t.Fatalf("state %q", location)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("location %q", location)
	}
	return code
}

func exchangeCode(t *testing.T, app *gfast.App, code, redirect, verifier string) oauthToken {
	t.Helper()
	res := tokenForm(t, app, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirect},
		"client_id":     {"app"},
		"code_verifier": {verifier},
	})
	if res.Status != http.StatusOK {
		t.Fatalf("exchange %d %s", res.Status, res.Body)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache %q", res.Header.Get("Cache-Control"))
	}
	var tok oauthToken
	if err := res.JSON(&tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

func tokenForm(t *testing.T, app *gfast.App, form url.Values, headers ...http.Header) *gfast.Result {
	t.Helper()
	header := http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}}
	if len(headers) > 0 {
		for key, values := range headers[0] {
			for _, value := range values {
				header.Add(key, value)
			}
		}
	}
	return app.Request(http.MethodPost, "/oauth/token", []byte(form.Encode()), header)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
