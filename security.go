package gfast

import (
	"context"
	"net/http"
	"strings"
)

// Bearer is the credential from an Authorization: Bearer header.
// Scopes is the list declared on the route with Scopes, not a claim parsed
// from the token. The framework does not reject a token for missing scopes.
// When OAuthServer is enabled, the server's validator checks the access token
// before this value is returned. Subject, ClientID, and TokenScopes are filled
// from that token. A token the validator rejects is 401.
type Bearer struct {
	Token       string
	Scopes      []string
	Subject     string
	ClientID    string
	TokenScopes []string
}

// Basic is the credential from HTTP basic authentication.
type Basic struct {
	Username string
	Password string
}

// APIKey is a key read from a header, a query parameter, or a cookie.
type APIKey struct {
	Name  string
	In    string
	Value string
}

// AuthOption configures BearerAuth, BasicAuth, and the API key readers.
type AuthOption func(*authOptions)

type authOptions struct {
	optional bool
}

// Optional makes a missing credential the zero value and lets the handler run.
// A credential that is present but does not parse is still 401.
// The optional dependency name is bearerAuthOptional, basicAuthOptional, or
// the API key name with _optional appended. OpenAPI keeps the scheme name,
// and bearer scopes stay on the operation.
func Optional() AuthOption {
	return func(o *authOptions) {
		o.optional = true
	}
}

func authOptional(opts []AuthOption) bool {
	var cfg authOptions
	for _, opt := range opts {
		if opt == nil {
			panic("gfast: nil auth option")
		}
		opt(&cfg)
	}
	return cfg.optional
}

// BearerAuth is the dependency that reads a bearer token.
// A provider parameter of type Bearer uses the required dependency and marks
// the route with the bearerAuth security scheme. Optional uses
// bearerAuthOptional and the same scheme. The same options return that
// existing dependency.
func BearerAuth(opts ...AuthOption) Dependency {
	if authOptional(opts) {
		return provider{entry: bearerOptionalEntry}
	}
	return provider{entry: bearerEntry}
}

// BasicAuth is the dependency that reads HTTP basic credentials.
// Optional uses the dependency name basicAuthOptional. The same options
// return that existing dependency.
func BasicAuth(opts ...AuthOption) Dependency {
	if authOptional(opts) {
		return provider{entry: basicOptionalEntry}
	}
	return provider{entry: basicEntry}
}

// APIKeyHeader returns a dependency that reads an API key from a header.
// The dependency name is apiKey_header_<name>, with non-alphanumeric
// characters replaced by underscores. Optional appends _optional.
// The same name and options return the existing dependency.
func APIKeyHeader(name string, opts ...AuthOption) Dependency {
	return newAPIKey("header", name, opts)
}

// APIKeyQuery returns a dependency that reads an API key from a query parameter.
// The dependency name is apiKey_query_<name>. Optional appends _optional.
// The same name and options return the existing dependency.
func APIKeyQuery(name string, opts ...AuthOption) Dependency {
	return newAPIKey("query", name, opts)
}

// APIKeyCookie returns a dependency that reads an API key from a cookie.
// The dependency name is apiKey_cookie_<name>. Optional appends _optional.
// The same name and options return the existing dependency.
func APIKeyCookie(name string, opts ...AuthOption) Dependency {
	return newAPIKey("cookie", name, opts)
}

const (
	credMissing = iota
	credBad
	credOK
)

func readBearer(ctx context.Context) (Bearer, error) {
	return finishBearer(ctx, false)
}

func readBearerOptional(ctx context.Context) (Bearer, error) {
	return finishBearer(ctx, true)
}

func finishBearer(ctx context.Context, optional bool) (Bearer, error) {
	st, err := stateFrom(ctx)
	if err != nil {
		return Bearer{}, err
	}
	token, kind := classifyBearer(st.req.Header.Get("Authorization"))
	if kind == credOK {
		cred := Bearer{Token: token, Scopes: append([]string(nil), st.scopes...)}
		if st.app.oauth != nil {
			claims, err := st.app.oauth.accessClaims(token)
			if err != nil {
				return Bearer{}, unauth("invalid bearer token", "Bearer")
			}
			cred.Subject = claims.Sub
			cred.ClientID = claims.CID
			cred.TokenScopes = splitScopes(claims.Scope)
		}
		return cred, nil
	}
	if optional && kind == credMissing {
		return Bearer{}, nil
	}
	return Bearer{}, unauth("missing bearer token", "Bearer")
}

// classifyBearer accepts the same tokens as a required reader.
// Another scheme, or no Authorization header, is missing. A Bearer scheme
// with an empty token is malformed.
func classifyBearer(h string) (string, int) {
	const prefix = "bearer "
	if len(h) >= len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		token := strings.TrimSpace(h[len(prefix):])
		if token == "" {
			return "", credBad
		}
		return token, credOK
	}
	if h != "" {
		scheme, _, _ := strings.Cut(h, " ")
		if strings.EqualFold(scheme, "bearer") {
			return "", credBad
		}
	}
	return "", credMissing
}

func readBasic(ctx context.Context) (Basic, error) {
	return finishBasic(ctx, false)
}

func readBasicOptional(ctx context.Context) (Basic, error) {
	return finishBasic(ctx, true)
}

func finishBasic(ctx context.Context, optional bool) (Basic, error) {
	st, err := stateFrom(ctx)
	if err != nil {
		return Basic{}, err
	}
	cred, kind := classifyBasic(st.req)
	if kind == credOK {
		return cred, nil
	}
	if optional && kind == credMissing {
		return Basic{}, nil
	}
	return Basic{}, unauth("missing basic credentials", `Basic realm="api"`)
}

// classifyBasic uses Request.BasicAuth for a valid header.
// Another scheme, or no Authorization header, is missing. A Basic scheme
// that does not decode is malformed.
func classifyBasic(r *http.Request) (Basic, int) {
	h := r.Header.Get("Authorization")
	u, p, ok := r.BasicAuth()
	if ok {
		return Basic{Username: u, Password: p}, credOK
	}
	if h != "" {
		scheme, _, _ := strings.Cut(h, " ")
		if strings.EqualFold(scheme, "basic") {
			return Basic{}, credBad
		}
	}
	return Basic{}, credMissing
}

func readAPIKey(in, name string, optional bool) func(context.Context) (APIKey, error) {
	return func(ctx context.Context) (APIKey, error) {
		st, err := stateFrom(ctx)
		if err != nil {
			return APIKey{}, err
		}
		value, kind, err := classifyAPIKey(st.req, in, name)
		if err != nil {
			return APIKey{}, err
		}
		if kind == credOK {
			return APIKey{Name: name, In: in, Value: value}, nil
		}
		if optional && kind == credMissing {
			return APIKey{}, nil
		}
		return APIKey{}, unauth("missing api key", apiKeyChallenge(in, name))
	}
}

// classifyAPIKey reports an empty header, query, or cookie value as malformed.
// An absent field is missing. The value is the first one, matching Header.Get
// and URL.Query().Get.
func classifyAPIKey(r *http.Request, in, name string) (string, int, error) {
	switch in {
	case "header":
		vals := r.Header.Values(name)
		if len(vals) == 0 {
			return "", credMissing, nil
		}
		if vals[0] == "" {
			return "", credBad, nil
		}
		return vals[0], credOK, nil
	case "query":
		vals, ok := r.URL.Query()[name]
		if !ok || len(vals) == 0 {
			return "", credMissing, nil
		}
		if vals[0] == "" {
			return "", credBad, nil
		}
		return vals[0], credOK, nil
	case "cookie":
		c, err := r.Cookie(name)
		if err == http.ErrNoCookie {
			return "", credMissing, nil
		}
		if err != nil {
			return "", 0, err
		}
		if c.Value == "" {
			return "", credBad, nil
		}
		return c.Value, credOK, nil
	default:
		return "", 0, BadRequest("unsupported api key location")
	}
}

func apiKeyChallenge(in, name string) string {
	if in == "header" {
		return name
	}
	return "apiKey"
}

func bearerScheme() *namedScheme {
	return &namedScheme{
		name:        "bearerAuth",
		typ:         "http",
		scheme:      "bearer",
		description: "Bearer token in the Authorization header.",
	}
}

func basicScheme() *namedScheme {
	return &namedScheme{
		name:        "basicAuth",
		typ:         "http",
		scheme:      "basic",
		description: "HTTP basic authentication.",
	}
}

func apiKeyScheme(in, name string) *namedScheme {
	return &namedScheme{
		name:        "apiKey_" + in + "_" + sanitize(name),
		typ:         "apiKey",
		in:          in,
		param:       name,
		description: "API key.",
	}
}
