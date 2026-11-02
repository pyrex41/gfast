package gfast

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	jsonv2 "encoding/json/v2"
)

const (
	oauthAuthorizePath = "/oauth/authorize"
	oauthTokenPath     = "/oauth/token"
	oauthDocsRedirect  = "/docs/oauth2-redirect"

	oauthCodeTTL    = time.Minute
	oauthAccessTTL  = time.Hour
	oauthRefreshTTL = 24 * time.Hour
)

// OAuthClient is a client of the in-process authorization server.
// An empty Secret is a public client. A public client can use the
// authorization code and password grants. Client credentials requires a secret.
// RedirectURIs are absolute http or https URLs, or paths such as
// /docs/oauth2-redirect. A path matches that path on the request host.
// The docs redirect is also accepted when it is not listed, so Swagger UI can
// finish Authorize. Scopes empty means the client may request any catalog scope.
type OAuthClient struct {
	ID           string
	Secret       string
	RedirectURIs []string
	Scopes       []string
}

// OAuthConfig opts an app into the authorization server.
// Password and Session may both be set. Password enables the password grant
// and the authorization endpoint's login form. Session reads a signed-in user
// from the authorization request. Client credentials needs neither.
// Password and Session are called on requests and must be safe for concurrent use.
//
// Authorization codes and refresh tokens are stored in memory. A process
// restart drops them. The access-token signing key is created in memory too,
// so access tokens from before the restart no longer verify.
//
// Codes last one minute, access tokens one hour, and refresh tokens 24 hours.
// Refresh tokens are single use. CodeTTL, AccessTTL, and RefreshTTL override
// those lifetimes. Zero keeps the default. A negative duration is already
// expired. The server does not implement OpenID Connect discovery, dynamic
// client registration, or the device-code grant.
type OAuthConfig struct {
	Clients []OAuthClient
	// Scopes is the OpenAPI catalog. The value is the description.
	// Nil advertises the scopes listed on the clients, or none.
	Scopes map[string]string
	// Password checks a username and password and returns the user's subject.
	// A nil error with an empty subject refuses the login.
	// The password grant exists only when this is set.
	Password func(ctx context.Context, username, password string) (subject string, err error)
	// Session checks the authorization request and returns the signed-in subject.
	// An empty subject means there is no session.
	Session func(ctx context.Context, r *http.Request) (subject string, err error)
	// CodeTTL is how long an authorization code stays valid.
	// Zero means one minute.
	CodeTTL time.Duration
	// AccessTTL is how long an access token stays valid.
	// Zero means one hour.
	AccessTTL time.Duration
	// RefreshTTL is how long a refresh token stays valid.
	// Zero means 24 hours.
	RefreshTTL time.Duration
}

type oauthServer struct {
	clients   map[string]*oauthClient
	scopeDocs map[string]string
	password  func(context.Context, string, string) (string, error)
	session   func(context.Context, *http.Request) (string, error)
	key       []byte

	codeTTL    time.Duration
	accessTTL  time.Duration
	refreshTTL time.Duration

	mu        sync.Mutex
	codes     map[string]*authCode
	refreshes map[string]*refreshToken
}

type oauthClient struct {
	id        string
	secret    string
	redirects []string
	scopes    []string
	public    bool
}

type authCode struct {
	clientID    string
	redirectURI string
	subject     string
	scopes      []string
	challenge   string
	expires     time.Time
}

type refreshToken struct {
	clientID string
	subject  string
	scopes   []string
	expires  time.Time
}

type jwtClaims struct {
	Sub   string `json:"sub"`
	CID   string `json:"cid"`
	Scope string `json:"scope,omitempty"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
	JTI   string `json:"jti"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type oauthErrBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

var errInvalidScope = errors.New("invalid scope")

func newOAuthServer(cfg *OAuthConfig) *oauthServer {
	if cfg == nil || len(cfg.Clients) == 0 {
		panic("gfast: oauth server requires a client")
	}
	docs := map[string]string{}
	explicit := len(cfg.Scopes) > 0
	for name, desc := range cfg.Scopes {
		if strings.TrimSpace(name) == "" {
			panic("gfast: oauth scope name is empty")
		}
		docs[name] = desc
	}
	clients := make(map[string]*oauthClient, len(cfg.Clients))
	for _, c := range cfg.Clients {
		id := strings.TrimSpace(c.ID)
		if id == "" {
			panic("gfast: oauth client id is empty")
		}
		if _, ok := clients[id]; ok {
			panic("gfast: duplicate oauth client " + id)
		}
		redirects := make([]string, 0, len(c.RedirectURIs))
		for _, uri := range c.RedirectURIs {
			if !validRegisteredRedirect(uri) {
				panic("gfast: oauth client " + id + " has a bad redirect uri")
			}
			redirects = append(redirects, uri)
		}
		scopes := make([]string, 0, len(c.Scopes))
		seen := map[string]struct{}{}
		for _, scope := range c.Scopes {
			if strings.TrimSpace(scope) == "" {
				panic("gfast: oauth client " + id + " has an empty scope")
			}
			if _, ok := seen[scope]; ok {
				continue
			}
			seen[scope] = struct{}{}
			if explicit {
				if _, ok := docs[scope]; !ok {
					panic("gfast: oauth client " + id + " scope is not in the catalog")
				}
			} else if _, ok := docs[scope]; !ok {
				docs[scope] = scope
			}
			scopes = append(scopes, scope)
		}
		clients[id] = &oauthClient{
			id:        id,
			secret:    c.Secret,
			redirects: redirects,
			scopes:    scopes,
			public:    c.Secret == "",
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("gfast: oauth signing key: " + err.Error())
	}
	return &oauthServer{
		clients:    clients,
		scopeDocs:  docs,
		password:   cfg.Password,
		session:    cfg.Session,
		key:        key,
		codeTTL:    ttlOr(cfg.CodeTTL, oauthCodeTTL),
		accessTTL:  ttlOr(cfg.AccessTTL, oauthAccessTTL),
		refreshTTL: ttlOr(cfg.RefreshTTL, oauthRefreshTTL),
		codes:      map[string]*authCode{},
		refreshes:  map[string]*refreshToken{},
	}
}

func ttlOr(set, fallback time.Duration) time.Duration {
	if set == 0 {
		return fallback
	}
	return set
}

func registerOAuth(mux *http.ServeMux, srv *oauthServer) {
	mux.HandleFunc("GET "+oauthAuthorizePath, srv.authorize)
	mux.HandleFunc("POST "+oauthAuthorizePath, srv.authorize)
	mux.HandleFunc("POST "+oauthTokenPath, srv.token)
}

func (a *App) documentedScheme(scheme *namedScheme) secScheme {
	if scheme.name == "bearerAuth" && a.oauth != nil {
		return a.oauth.securityScheme()
	}
	return secScheme{
		Type:        scheme.typ,
		Scheme:      scheme.scheme,
		In:          scheme.in,
		Name:        scheme.param,
		Description: scheme.description,
	}
}

func (s *oauthServer) securityScheme() secScheme {
	scopes := s.scopeDocs
	if scopes == nil {
		scopes = map[string]string{}
	}
	flows := &oauthFlowsDoc{
		AuthorizationCode: &oauthFlowDoc{
			AuthorizationURL: oauthAuthorizePath,
			TokenURL:         oauthTokenPath,
			Scopes:           scopes,
		},
		ClientCredentials: &oauthFlowDoc{
			TokenURL: oauthTokenPath,
			Scopes:   scopes,
		},
	}
	if s.password != nil {
		flows.Password = &oauthFlowDoc{
			TokenURL: oauthTokenPath,
			Scopes:   scopes,
		}
	}
	return secScheme{
		Type:        "oauth2",
		Description: "OAuth 2.1 access tokens from this server. Authorization codes and refresh tokens are stored in memory and a process restart drops them.",
		Flows:       flows,
	}
}

func (s *oauthServer) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := enforceCSRF(r, false); err != nil {
			writeErr(w, err)
			return
		}
		if !formContent(r) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "content type must be application/x-www-form-urlencoded")
			return
		}
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
			return
		}
	}
	q := r.URL.Query()
	client := s.clients[q.Get("client_id")]
	if client == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unknown client")
		return
	}
	redirectURI, ok := resolveRedirect(client, q.Get("redirect_uri"), r)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect uri is not registered")
		return
	}
	state := q.Get("state")
	if q.Get("response_type") != "code" {
		redirectOAuthError(w, r, redirectURI, state, "unsupported_response_type", "response type must be code")
		return
	}
	if q.Get("code_challenge_method") != "S256" || !validChallenge(q.Get("code_challenge")) {
		redirectOAuthError(w, r, redirectURI, state, "invalid_request", "pkce s256 is required")
		return
	}
	scopes, err := s.allowedScopes(client, q.Get("scope"))
	if err != nil {
		redirectOAuthError(w, r, redirectURI, state, "invalid_scope", "unknown scope")
		return
	}
	subject, done := s.authorizeUser(w, r, redirectURI, state)
	if done {
		return
	}
	raw, err := s.putCode(&authCode{
		clientID:    client.id,
		redirectURI: redirectURI,
		subject:     subject,
		scopes:      scopes,
		challenge:   q.Get("code_challenge"),
		expires:     time.Now().Add(s.codeTTL),
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue code")
		return
	}
	target, err := withQuery(redirectURI, url.Values{"code": {raw}, "state": {state}})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not redirect")
		return
	}
	status := http.StatusFound
	if r.Method == http.MethodPost {
		status = http.StatusSeeOther
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, status)
}

// authorizeUser returns done when the response is already written.
func (s *oauthServer) authorizeUser(w http.ResponseWriter, r *http.Request, redirectURI, state string) (string, bool) {
	if s.session != nil {
		subject, err := s.session(r.Context(), r)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "session check failed")
			return "", true
		}
		if subject != "" {
			return subject, false
		}
	}
	if s.password == nil {
		redirectOAuthError(w, r, redirectURI, state, "access_denied", "login required")
		return "", true
	}
	if r.Method == http.MethodGet {
		writeLogin(w, r, http.StatusOK, "")
		return "", true
	}
	subject, err := s.password(r.Context(), r.PostForm.Get("username"), r.PostForm.Get("password"))
	if err != nil || subject == "" {
		writeLogin(w, r, http.StatusUnauthorized, "The username or password is not valid.")
		return "", true
	}
	return subject, false
}

func (s *oauthServer) token(w http.ResponseWriter, r *http.Request) {
	if err := enforceCSRF(r, false); err != nil {
		writeErr(w, err)
		return
	}
	if !formContent(r) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "content type must be application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	client, status, code, desc := s.authenticate(r)
	if client == nil {
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		}
		writeOAuthError(w, status, code, desc)
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		s.grantCode(w, r, client)
	case "refresh_token":
		s.grantRefresh(w, r, client)
	case "client_credentials":
		s.grantClient(w, r, client)
	case "password":
		s.grantPassword(w, r, client)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant type is not supported")
	}
}

func (s *oauthServer) grantCode(w http.ResponseWriter, r *http.Request, client *oauthClient) {
	raw := r.PostForm.Get("code")
	redirectURI := r.PostForm.Get("redirect_uri")
	verifier := r.PostForm.Get("code_verifier")
	if raw == "" || redirectURI == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code and redirect uri are required")
		return
	}
	item := s.consumeCode(raw, client.id, redirectURI)
	if item == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		return
	}
	if verifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code verifier is required")
		return
	}
	if !pkceMatch(verifier, item.challenge) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "pkce verification failed")
		return
	}
	s.writeIssued(w, item.subject, client.id, item.scopes, true)
}

func (s *oauthServer) grantRefresh(w http.ResponseWriter, r *http.Request, client *oauthClient) {
	raw := r.PostForm.Get("refresh_token")
	if raw == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh token is required")
		return
	}
	item := s.consumeRefresh(raw, client.id)
	if item == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}
	scopes, err := subsetScopes(item.scopes, r.PostForm.Get("scope"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "unknown scope")
		return
	}
	s.writeIssued(w, item.subject, client.id, scopes, true)
}

func (s *oauthServer) grantClient(w http.ResponseWriter, r *http.Request, client *oauthClient) {
	if client.public {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "client credentials requires a client secret")
		return
	}
	scopes, err := s.allowedScopes(client, r.PostForm.Get("scope"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "unknown scope")
		return
	}
	s.writeIssued(w, client.id, client.id, scopes, false)
}

func (s *oauthServer) grantPassword(w http.ResponseWriter, r *http.Request, client *oauthClient) {
	if s.password == nil {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "password grant is not enabled")
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	if username == "" || password == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "username and password are required")
		return
	}
	subject, err := s.password(r.Context(), username, password)
	if err != nil || subject == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid username or password")
		return
	}
	scopes, err := s.allowedScopes(client, r.PostForm.Get("scope"))
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "unknown scope")
		return
	}
	s.writeIssued(w, subject, client.id, scopes, true)
}

func (s *oauthServer) writeIssued(w http.ResponseWriter, subject, clientID string, scopes []string, withRefresh bool) {
	res, err := s.issue(subject, clientID, scopes, withRefresh)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, res)
}

func (s *oauthServer) authenticate(r *http.Request) (*oauthClient, int, string, string) {
	id := ""
	secret := ""
	if user, pass, ok := r.BasicAuth(); ok {
		var err error
		id, err = url.QueryUnescape(user)
		if err != nil {
			return nil, http.StatusUnauthorized, "invalid_client", "invalid client"
		}
		secret, err = url.QueryUnescape(pass)
		if err != nil {
			return nil, http.StatusUnauthorized, "invalid_client", "invalid client"
		}
		if body := r.PostForm.Get("client_id"); body != "" && body != id {
			return nil, http.StatusBadRequest, "invalid_request", "client id does not match"
		}
	} else {
		id = r.PostForm.Get("client_id")
		secret = r.PostForm.Get("client_secret")
	}
	if id == "" {
		return nil, http.StatusUnauthorized, "invalid_client", "invalid client"
	}
	client := s.clients[id]
	if client == nil {
		return nil, http.StatusUnauthorized, "invalid_client", "invalid client"
	}
	if client.public {
		if secret != "" {
			return nil, http.StatusUnauthorized, "invalid_client", "invalid client"
		}
		return client, 0, "", ""
	}
	if !secretMatch(secret, client.secret) {
		return nil, http.StatusUnauthorized, "invalid_client", "invalid client"
	}
	return client, 0, "", ""
}

func (s *oauthServer) allowedScopes(client *oauthClient, requested string) ([]string, error) {
	want := splitScopes(requested)
	pool := client.scopes
	if len(pool) == 0 {
		pool = sortedScopeNames(s.scopeDocs)
	}
	if len(want) == 0 {
		return append([]string(nil), pool...), nil
	}
	if len(pool) == 0 {
		return want, nil
	}
	have := map[string]struct{}{}
	for _, name := range pool {
		have[name] = struct{}{}
	}
	for _, name := range want {
		if _, ok := have[name]; !ok {
			return nil, errInvalidScope
		}
	}
	return want, nil
}

func subsetScopes(granted []string, requested string) ([]string, error) {
	want := splitScopes(requested)
	if len(want) == 0 {
		return append([]string(nil), granted...), nil
	}
	have := map[string]struct{}{}
	for _, name := range granted {
		have[name] = struct{}{}
	}
	for _, name := range want {
		if _, ok := have[name]; !ok {
			return nil, errInvalidScope
		}
	}
	return want, nil
}

func splitScopes(raw string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, part := range strings.Fields(raw) {
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}

func sortedScopeNames(scopes map[string]string) []string {
	names := make([]string, 0, len(scopes))
	for name := range scopes {
		if name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func (s *oauthServer) putCode(item *authCode) (string, error) {
	raw, err := randomToken(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.codes[raw] = item
	s.mu.Unlock()
	return raw, nil
}

func (s *oauthServer) consumeCode(raw, clientID, redirectURI string) *authCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.codes[raw]
	if item == nil || !time.Now().Before(item.expires) {
		delete(s.codes, raw)
		return nil
	}
	if item.clientID != clientID || item.redirectURI != redirectURI {
		return nil
	}
	delete(s.codes, raw)
	return item
}

func (s *oauthServer) consumeRefresh(raw, clientID string) *refreshToken {
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.refreshes[raw]
	if item == nil || !time.Now().Before(item.expires) {
		delete(s.refreshes, raw)
		return nil
	}
	if item.clientID != clientID {
		return nil
	}
	delete(s.refreshes, raw)
	return item
}

func (s *oauthServer) issue(subject, clientID string, scopes []string, withRefresh bool) (tokenResponse, error) {
	now := time.Now()
	jti, err := randomToken(16)
	if err != nil {
		return tokenResponse{}, err
	}
	raw, err := signAccess(s.key, jwtClaims{
		Sub:   subject,
		CID:   clientID,
		Scope: strings.Join(scopes, " "),
		Exp:   now.Add(s.accessTTL).Unix(),
		Iat:   now.Unix(),
		JTI:   jti,
	})
	if err != nil {
		return tokenResponse{}, err
	}
	res := tokenResponse{
		AccessToken: raw,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.accessTTL / time.Second),
		Scope:       strings.Join(scopes, " "),
	}
	if !withRefresh {
		return res, nil
	}
	refresh, err := randomToken(32)
	if err != nil {
		return tokenResponse{}, err
	}
	s.mu.Lock()
	s.refreshes[refresh] = &refreshToken{
		clientID: clientID,
		subject:  subject,
		scopes:   append([]string(nil), scopes...),
		expires:  now.Add(s.refreshTTL),
	}
	s.mu.Unlock()
	res.RefreshToken = refresh
	return res, nil
}

func (s *oauthServer) accessClaims(raw string) (jwtClaims, error) {
	claims, err := parseAccess(s.key, raw)
	if err != nil {
		return jwtClaims{}, err
	}
	if claims.Sub == "" || claims.Exp <= time.Now().Unix() {
		return jwtClaims{}, errors.New("invalid token")
	}
	return claims, nil
}

func signAccess(key []byte, claims jwtClaims) (string, error) {
	header, err := jsonv2.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := jsonv2.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(input))
	return input + "." + enc.EncodeToString(mac.Sum(nil)), nil
}

func parseAccess(key []byte, raw string) (jwtClaims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return jwtClaims{}, errors.New("invalid token")
	}
	enc := base64.RawURLEncoding
	headerRaw, err := enc.DecodeString(parts[0])
	if err != nil {
		return jwtClaims{}, errors.New("invalid token")
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := jsonv2.Unmarshal(headerRaw, &header); err != nil {
		return jwtClaims{}, errors.New("invalid token")
	}
	if header.Alg != "HS256" {
		return jwtClaims{}, errors.New("invalid token")
	}
	payload, err := enc.DecodeString(parts[1])
	if err != nil {
		return jwtClaims{}, errors.New("invalid token")
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return jwtClaims{}, errors.New("invalid token")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return jwtClaims{}, errors.New("invalid token")
	}
	var claims jwtClaims
	if err := jsonv2.Unmarshal(payload, &claims); err != nil {
		return jwtClaims{}, errors.New("invalid token")
	}
	return claims, nil
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, status, oauthErrBody{Error: code, Description: desc})
}

func redirectOAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	vals := url.Values{"error": {code}}
	if desc != "" {
		vals.Set("error_description", desc)
	}
	if state != "" {
		vals.Set("state", state)
	}
	target, err := withQuery(redirectURI, vals)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect uri is not registered")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

func withQuery(raw string, extra url.Values) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || !safeAbsolute(raw) {
		return "", errors.New("bad redirect")
	}
	q := u.Query()
	for key, values := range extra {
		if key == "state" && (len(values) == 0 || values[0] == "") {
			continue
		}
		for _, value := range values {
			q.Set(key, value)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func writeLogin(w http.ResponseWriter, r *http.Request, status int, message string) {
	action := oauthAuthorizePath
	if r.URL.RawQuery != "" {
		action += "?" + r.URL.RawQuery
	}
	msg := ""
	if message != "" {
		msg = "<p>" + htmlText(message) + "</p>\n"
	}
	field := ""
	if token := CSRFTokenFrom(r.Context()); token != "" {
		field = `<input type="hidden" name="csrf_token" value="` + htmlAttr(token) + `">` + "\n"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`<!doctype html>
<meta charset="utf-8">
<title>Sign in</title>
<h1>Sign in</h1>
` + msg + `<form method="post" action="` + htmlAttr(action) + `">
` + field + `<label>Username <input name="username" autocomplete="username"></label>
<label>Password <input name="password" type="password" autocomplete="current-password"></label>
<button type="submit">Sign in</button>
</form>
`))
}

func formContent(r *http.Request) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return false
	}
	return media == "application/x-www-form-urlencoded"
}

func resolveRedirect(client *oauthClient, requested string, r *http.Request) (string, bool) {
	if requested == "" {
		if len(client.redirects) != 1 {
			return "", false
		}
		requested = expandRedirect(client.redirects[0], r)
	}
	if !redirectAllowed(client, requested, r) || !safeAbsolute(requested) {
		return "", false
	}
	return requested, true
}

func expandRedirect(registered string, r *http.Request) string {
	if strings.HasPrefix(registered, "/") {
		return requestOrigin(r) + registered
	}
	return registered
}

func redirectAllowed(client *oauthClient, requested string, r *http.Request) bool {
	for _, uri := range client.redirects {
		if uri == requested {
			return true
		}
		if strings.HasPrefix(uri, "/") && sameHostPath(requested, uri, r) {
			return true
		}
	}
	return sameHostPath(requested, oauthDocsRedirect, r)
}

func sameHostPath(requested, path string, r *http.Request) bool {
	u, err := url.Parse(requested)
	if err != nil || u.Host == "" || u.Path != path || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return strings.EqualFold(u.Host, requestHost(r))
}

func requestHost(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
}

func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + requestHost(r)
}

func safeAbsolute(raw string) bool {
	if raw == "" || strings.ContainsAny(raw, "\r\n\\ ") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func validRegisteredRedirect(uri string) bool {
	if strings.ContainsAny(uri, "\r\n\\ ") {
		return false
	}
	if strings.HasPrefix(uri, "/") && !strings.HasPrefix(uri, "//") && !strings.Contains(uri, "?") && !strings.Contains(uri, "#") {
		return true
	}
	return safeAbsolute(uri)
}

func validChallenge(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func validVerifier(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_', r == '~':
		default:
			return false
		}
	}
	return true
}

func pkceMatch(verifier, challenge string) bool {
	if !validVerifier(verifier) || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if len(got) != len(challenge) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

func secretMatch(got, want string) bool {
	if want == "" || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
