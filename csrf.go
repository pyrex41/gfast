package gfast

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

const (
	csrfTokenName = "csrf_token"
	csrfHeader    = "X-CSRF-Token"
	csrfFailed    = "csrf check failed"
)

// NoCSRF turns CSRF checks off for the app.
// Sessions otherwise check unsafe requests that send the session cookie.
// App-level.
func NoCSRF() Option {
	return func(b *optionBag) {
		if b.app != nil {
			b.app.csrfOff = true
		}
	}
}

// CSRFStrict also rejects Sec-Fetch-Site: same-site.
// Sec-Fetch-Site: cross-site stays rejected. App-level.
func CSRFStrict() Option {
	return func(b *optionBag) {
		if b.app != nil {
			b.app.csrfStrict = true
		}
	}
}

// CSRFOrigins lists extra hosts allowed to send unsafe cookie requests.
// When Sec-Fetch-Site is absent, an Origin or Referer host must be this
// request's host or one of these hosts. A value may be a host or an
// absolute URL; only the host is used. App-level.
func CSRFOrigins(hosts ...string) Option {
	return func(b *optionBag) {
		if b.app == nil {
			return
		}
		if len(hosts) == 0 {
			panic("gfast: CSRFOrigins requires a host")
		}
		for _, host := range hosts {
			b.app.csrfOrigins = append(b.app.csrfOrigins, normalizeCSRFHost(host))
		}
	}
}

// CSRFToken requires a synchronizer token on unsafe cookie requests.
// The token is stored in the session under "csrf_token" and copied to a
// cookie of the same name that JavaScript can read. The request must send
// it in the X-CSRF-Token header or a csrf_token form field.
// It can be combined with the default checks and with CSRFStrict. App-level.
func CSRFToken() Option {
	return func(b *optionBag) {
		if b.app != nil {
			b.app.csrfToken = true
		}
	}
}

// SkipCSRF turns CSRF checks off for one route.
// A group passes the flag on to its routes.
func SkipCSRF() Option {
	return func(b *optionBag) {
		if b.route != nil {
			b.route.skipCSRF = true
		}
	}
}

// CSRFTokenFrom returns the synchronizer token for this request.
// It is empty when CSRFToken was not passed to New, or when the session
// has no token. It panics if ctx is not a gfast request.
func CSRFTokenFrom(ctx context.Context) string {
	st, err := stateFrom(ctx)
	if err != nil {
		panic(fmt.Errorf("gfast.CSRFTokenFrom: %w", err))
	}
	if st.app == nil || !st.app.cfg.csrfToken || st.session == nil {
		return ""
	}
	token, _ := st.session[csrfTokenName].(string)
	return token
}

func ensureCSRFToken(session map[string]any) {
	if token, ok := session[csrfTokenName].(string); ok && token != "" {
		return
	}
	session[csrfTokenName] = newCSRFToken()
}

func newCSRFToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("gfast: csrf token: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func csrfEqual(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	sumA := sha256.Sum256([]byte(a))
	sumB := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(sumA[:], sumB[:]) == 1
}

func enforceCSRF(r *http.Request, skip bool) error {
	st, err := stateFrom(r.Context())
	if err != nil {
		return err
	}
	if !csrfApplies(st.app, r, skip) {
		return nil
	}
	if err := checkCSRFSource(st.app, r); err != nil {
		return err
	}
	if st.app.cfg.csrfToken {
		return checkCSRFToken(r, st)
	}
	return nil
}

func csrfApplies(app *App, r *http.Request, skip bool) bool {
	if app == nil || app.cfg.sessions == nil || app.cfg.csrfOff || skip {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return false
	}
	c, err := r.Cookie(sessionCookieName)
	return err == nil && c.Value != ""
}

func checkCSRFSource(app *App, r *http.Request) error {
	site := strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))
	if site != "" {
		if strings.EqualFold(site, "cross-site") || (app.cfg.csrfStrict && strings.EqualFold(site, "same-site")) {
			return Forbidden(csrfFailed)
		}
		return nil
	}
	raw := strings.TrimSpace(r.Header.Get("Origin"))
	if raw == "" {
		raw = strings.TrimSpace(r.Header.Get("Referer"))
	}
	if raw == "" {
		return nil
	}
	host, ok := originHost(raw)
	if !ok || !csrfHostAllowed(app, r, host) {
		return Forbidden(csrfFailed)
	}
	return nil
}

func csrfHostAllowed(app *App, r *http.Request, host string) bool {
	if reqHost, ok := requestHostname(r.Host); ok && host == reqHost {
		return true
	}
	for _, allowed := range app.cfg.csrfOrigins {
		if host == allowed {
			return true
		}
	}
	return false
}

func originHost(raw string) (string, bool) {
	if raw == "" || strings.EqualFold(raw, "null") {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	return requestHostname(u.Host)
}

func normalizeCSRFHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		panic("gfast: empty CSRF origin")
	}
	if strings.Contains(raw, "://") {
		host, ok := originHost(raw)
		if !ok {
			panic("gfast: bad CSRF origin")
		}
		return host
	}
	host, ok := requestHostname(raw)
	if !ok {
		panic("gfast: bad CSRF origin")
	}
	return host
}

func checkCSRFToken(r *http.Request, st *requestState) error {
	token := ""
	if st.session != nil {
		token, _ = st.session[csrfTokenName].(string)
	}
	header := strings.TrimSpace(r.Header.Get(csrfHeader))
	if csrfEqual(token, header) {
		return nil
	}
	if csrfEqual(token, csrfFormToken(r)) {
		return nil
	}
	return Forbidden(csrfFailed)
}

func csrfFormToken(r *http.Request) string {
	if r.PostForm != nil {
		if v := strings.TrimSpace(r.PostForm.Get(csrfTokenName)); v != "" {
			return v
		}
	}
	media := ""
	if ct := r.Header.Get("Content-Type"); ct != "" {
		parsed, _, err := mime.ParseMediaType(ct)
		if err != nil {
			return ""
		}
		media = strings.ToLower(parsed)
	}
	switch {
	case media == "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return ""
		}
	case strings.HasPrefix(media, "multipart/"):
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return ""
		}
	default:
		return ""
	}
	return strings.TrimSpace(r.PostForm.Get(csrfTokenName))
}

func (s *sessionWriter) writeCSRFCookie() {
	if s == nil || !s.csrf || s.st == nil || s.st.req == nil {
		return
	}
	token := ""
	if s.st.session != nil {
		token, _ = s.st.session[csrfTokenName].(string)
	}
	if token == "" {
		http.SetCookie(s.ResponseWriter, &http.Cookie{
			Name:     csrfTokenName,
			Value:    "",
			Path:     sessionCookiePath,
			MaxAge:   -1,
			Secure:   s.cfg.secure,
			SameSite: s.cfg.sameSite,
		})
		return
	}
	if c, err := s.st.req.Cookie(csrfTokenName); err == nil && c.Value == token {
		return
	}
	http.SetCookie(s.ResponseWriter, &http.Cookie{
		Name:     csrfTokenName,
		Value:    token,
		Path:     sessionCookiePath,
		Secure:   s.cfg.secure,
		SameSite: s.cfg.sameSite,
		MaxAge:   s.cfg.maxAge,
	})
}
