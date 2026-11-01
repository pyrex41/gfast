package gfast

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"

	jsonv2 "encoding/json/v2"
)

const (
	sessionCookieName = "session"
	sessionCookiePath = "/"
)

// SessionConfig configures signed-cookie sessions.
// Secret is the HMAC key. An empty secret panics.
// Secure sets the Secure attribute.
// MaxAge is the cookie lifetime in seconds. Zero omits Max-Age.
// A negative MaxAge panics.
// SameSite defaults to Lax. SameSite None requires Secure.
// The cookie is HttpOnly and its path is /.
type SessionConfig struct {
	Secret   string
	Secure   bool
	MaxAge   int
	SameSite http.SameSite
}

type sessionConfig struct {
	secret   string
	maxAge   int
	secure   bool
	sameSite http.SameSite
}

// Sessions turns on signed-cookie sessions.
// Sessions stay off unless this option is passed to New.
// The cookie named "session" holds an HMAC-signed JSON object.
// There is no server-side store. App-level.
func Sessions(cfg SessionConfig) Option {
	return func(b *optionBag) {
		if b.app == nil {
			return
		}
		b.app.sessions = configureSession(cfg)
	}
}

func configureSession(cfg SessionConfig) *sessionConfig {
	if cfg.Secret == "" {
		panic("gfast: session secret is empty")
	}
	if cfg.MaxAge < 0 {
		panic("gfast: session MaxAge must not be negative")
	}
	same := cfg.SameSite
	switch same {
	case 0, http.SameSiteDefaultMode, http.SameSiteLaxMode:
		same = http.SameSiteLaxMode
	case http.SameSiteStrictMode:
	case http.SameSiteNoneMode:
		if !cfg.Secure {
			panic("gfast: SameSite=None requires Secure")
		}
	default:
		panic("gfast: bad session SameSite")
	}
	return &sessionConfig{
		secret:   cfg.Secret,
		maxAge:   cfg.MaxAge,
		secure:   cfg.Secure,
		sameSite: same,
	}
}

// SessionFrom returns the session for this request.
// The map is a JSON object. Numbers come back as float64.
// Change the map in place. Removing every key deletes the cookie.
// A missing cookie or a bad signature is an empty map, not an error.
// It panics if ctx is not a gfast request, or if Sessions was not passed to New.
func SessionFrom(ctx context.Context) map[string]any {
	st, err := stateFrom(ctx)
	if err != nil {
		panic(fmt.Errorf("gfast.SessionFrom: %w", err))
	}
	if !st.sessionOn {
		panic("gfast: sessions are off")
	}
	if st.session == nil {
		st.session = map[string]any{}
	}
	return st.session
}

func loadSession(r *http.Request, cfg *sessionConfig) (map[string]any, []byte) {
	blank := func() (map[string]any, []byte) {
		m := map[string]any{}
		raw, err := marshalSession(m)
		if err != nil {
			panic("gfast: session value cannot be encoded: " + err.Error())
		}
		return m, raw
	}
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return blank()
	}
	m, ok := openSession(cfg.secret, c.Value)
	if !ok {
		return blank()
	}
	raw, err := marshalSession(m)
	if err != nil {
		return blank()
	}
	return m, raw
}

func marshalSession(m map[string]any) ([]byte, error) {
	if m == nil {
		m = map[string]any{}
	}
	return jsonv2.Marshal(m, jsonv2.Deterministic(true))
}

// The cookie value is base64(JSON) + "." + base64(HMAC-SHA256(secret, base64(JSON))).
func signSession(secret string, raw []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func openSession(secret, value string) (map[string]any, bool) {
	encoded, sigEncoded, ok := strings.Cut(value, ".")
	if !ok || encoded == "" || sigEncoded == "" || strings.Contains(sigEncoded, ".") {
		return nil, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigEncoded)
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(encoded))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, false
	}
	var m map[string]any
	if err := jsonv2.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

type sessionWriter struct {
	http.ResponseWriter
	cfg   *sessionConfig
	st    *requestState
	csrf  bool
	wrote bool
}

func (s *sessionWriter) WriteHeader(code int) {
	if !s.wrote {
		s.wrote = true
		s.commit()
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *sessionWriter) Write(p []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(p)
}

func (s *sessionWriter) Flush() {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *sessionWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hj.Hijack()
}

func (s *sessionWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *sessionWriter) finish() {
	if s.wrote {
		return
	}
	s.wrote = true
	s.commit()
}

func (s *sessionWriter) commit() {
	if s.st == nil || !s.st.sessionOn {
		return
	}
	raw, err := marshalSession(s.st.session)
	if err != nil {
		panic("gfast: session value cannot be encoded: " + err.Error())
	}
	if !bytes.Equal(raw, s.st.sessionSnap) {
		s.writeSessionCookie(raw)
		s.st.sessionSnap = raw
	}
	s.writeCSRFCookie()
}

func (s *sessionWriter) writeSessionCookie(raw []byte) {
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Path:     sessionCookiePath,
		HttpOnly: true,
		Secure:   s.cfg.secure,
		SameSite: s.cfg.sameSite,
	}
	if len(s.st.session) == 0 {
		cookie.Value = ""
		cookie.MaxAge = -1
	} else {
		cookie.Value = signSession(s.cfg.secret, raw)
		cookie.MaxAge = s.cfg.maxAge
	}
	http.SetCookie(s.ResponseWriter, cookie)
}
