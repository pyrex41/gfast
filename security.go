package gfast

import (
	"context"
	"strings"
)

// Bearer is the credential from an Authorization: Bearer header.
// Scopes is the list declared on the route with Scopes, not a claim parsed
// from the token.
type Bearer struct {
	Token  string
	Scopes []string
}

// Basic is the credential from HTTP basic authentication.
type Basic struct {
	Username string
	Password string
}

// APIKey is a key read from a header or a query parameter.
type APIKey struct {
	Name  string
	In    string
	Value string
}

// BearerAuth is the dependency that reads a bearer token.
// A provider parameter of type Bearer uses the same dependency and marks the
// route with the bearerAuth security scheme.
func BearerAuth() Dependency {
	return provider{entry: bearerEntry}
}

// BasicAuth is the dependency that reads HTTP basic credentials.
func BasicAuth() Dependency {
	return provider{entry: basicEntry}
}

// APIKeyHeader returns a dependency that reads an API key from a header.
func APIKeyHeader(name string) Dependency {
	return newAPIKey("header", name)
}

// APIKeyQuery returns a dependency that reads an API key from a query parameter.
func APIKeyQuery(name string) Dependency {
	return newAPIKey("query", name)
}

func readBearer(ctx context.Context) (Bearer, error) {
	st, err := stateFrom(ctx)
	if err != nil {
		return Bearer{}, err
	}
	h := st.req.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return Bearer{}, unauth("missing bearer token", "Bearer")
	}
	token := strings.TrimSpace(h[len(prefix):])
	if token == "" {
		return Bearer{}, unauth("missing bearer token", "Bearer")
	}
	return Bearer{Token: token, Scopes: append([]string(nil), st.scopes...)}, nil
}

func readBasic(ctx context.Context) (Basic, error) {
	st, err := stateFrom(ctx)
	if err != nil {
		return Basic{}, err
	}
	u, p, ok := st.req.BasicAuth()
	if !ok {
		return Basic{}, unauth("missing basic credentials", `Basic realm="api"`)
	}
	return Basic{Username: u, Password: p}, nil
}

func readAPIKey(in, name string) func(context.Context) (APIKey, error) {
	return func(ctx context.Context) (APIKey, error) {
		st, err := stateFrom(ctx)
		if err != nil {
			return APIKey{}, err
		}
		var value string
		switch in {
		case "header":
			value = st.req.Header.Get(name)
		case "query":
			value = st.req.URL.Query().Get(name)
		default:
			return APIKey{}, BadRequest("unsupported api key location")
		}
		if value == "" {
			return APIKey{}, unauth("missing api key", apiKeyChallenge(in, name))
		}
		return APIKey{Name: name, In: in, Value: value}, nil
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
