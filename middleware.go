package gfast

import (
	"compress/gzip"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

type corsPolicy struct {
	allowAll    bool
	exact       map[string]struct{}
	patterns    []*regexp.Regexp
	credentials bool
	expose      string
	maxAgeSet   bool
	maxAge      int
}

func newCORSPolicy(cfg appConfig) corsPolicy {
	p := corsPolicy{
		exact:       map[string]struct{}{},
		credentials: cfg.credentials,
		expose:      joinHeaderList(cfg.exposeHeaders),
	}
	if cfg.maxAge != nil {
		p.maxAgeSet = true
		p.maxAge = *cfg.maxAge
	}
	if len(cfg.origins) == 0 {
		p.allowAll = true
	}
	for _, origin := range cfg.origins {
		if origin == "*" {
			p.allowAll = true
			continue
		}
		if strings.Contains(origin, "*") {
			p.patterns = append(p.patterns, originGlob(origin))
			continue
		}
		p.exact[origin] = struct{}{}
	}
	for _, pattern := range cfg.originPatterns {
		p.patterns = append(p.patterns, regexp.MustCompile(anchorOriginPattern(pattern)))
	}
	return p
}

func (p corsPolicy) allows(origin string) bool {
	if origin == "" {
		return false
	}
	if _, ok := p.exact[origin]; ok {
		return true
	}
	for _, re := range p.patterns {
		if re.MatchString(origin) {
			return true
		}
	}
	// An empty list, or "*", echoes any origin only when credentials are off.
	// Credentials must name an origin or a pattern, and must not reflect
	// an arbitrary Origin.
	return p.allowAll && !p.credentials
}

func withCORS(p corsPolicy, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if p.allows(origin) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Vary", "Origin")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			if p.credentials {
				h.Set("Access-Control-Allow-Credentials", "true")
			}
			if r.Method == http.MethodOptions {
				if p.maxAgeSet {
					h.Set("Access-Control-Max-Age", strconv.Itoa(p.maxAge))
				}
			} else if p.expose != "" {
				h.Set("Access-Control-Expose-Headers", p.expose)
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func originGlob(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString(`\A`)
	for _, r := range pattern {
		if r == '*' {
			b.WriteString(".*")
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	b.WriteString(`\z`)
	return regexp.MustCompile(b.String())
}

func joinHeaderList(values []string) string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return strings.Join(out, ", ")
}

func withGzip(level int, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead || isWebsocketUpgrade(r) || !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			next.ServeHTTP(w, r)
			return
		}
		gw := &gzipRW{ResponseWriter: w, level: level}
		defer gw.close()
		next.ServeHTTP(gw, r)
	})
}

func acceptsGzip(header string) bool {
	best := 0.0
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := part
		q := 1.0
		if i := strings.Index(part, ";"); i >= 0 {
			name = strings.TrimSpace(part[:i])
			q = codingQuality(part[i+1:])
		}
		name = strings.ToLower(name)
		if name != "gzip" && name != "*" {
			continue
		}
		if q > best {
			best = q
		}
	}
	return best > 0
}

func codingQuality(param string) float64 {
	for _, piece := range strings.Split(param, ";") {
		piece = strings.TrimSpace(piece)
		raw, ok := strings.CutPrefix(strings.ToLower(piece), "q=")
		if !ok {
			continue
		}
		q, err := strconv.ParseFloat(raw, 64)
		if err != nil || q < 0 {
			return 0
		}
		if q > 1 {
			return 1
		}
		return q
	}
	return 1
}

func isWebsocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

type gzipRW struct {
	http.ResponseWriter
	level      int
	gz         *gzip.Writer
	headerDone bool
	skip       bool
}

func (g *gzipRW) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func (g *gzipRW) WriteHeader(code int) {
	if g.headerDone {
		return
	}
	g.headerDone = true
	if gzipSkip(g.Header(), code) {
		g.skip = true
		g.ResponseWriter.WriteHeader(code)
		return
	}
	zw, err := gzip.NewWriterLevel(g.ResponseWriter, g.level)
	if err != nil {
		g.skip = true
		g.ResponseWriter.WriteHeader(code)
		return
	}
	h := g.Header()
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	addVary(h, "Accept-Encoding")
	g.ResponseWriter.WriteHeader(code)
	g.gz = zw
}

func (g *gzipRW) Write(p []byte) (int, error) {
	if !g.headerDone {
		g.WriteHeader(http.StatusOK)
	}
	if g.skip || g.gz == nil {
		return g.ResponseWriter.Write(p)
	}
	return g.gz.Write(p)
}

func (g *gzipRW) Flush() {
	if !g.headerDone {
		g.WriteHeader(http.StatusOK)
	}
	if g.gz != nil {
		_ = g.gz.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *gzipRW) close() {
	if g.gz != nil {
		_ = g.gz.Close()
		g.gz = nil
	}
}

func gzipSkip(h http.Header, status int) bool {
	if status < 200 || status == http.StatusNoContent || status == http.StatusNotModified || status == http.StatusSwitchingProtocols {
		return true
	}
	if enc := strings.TrimSpace(h.Get("Content-Encoding")); enc != "" && !strings.EqualFold(enc, "identity") {
		return true
	}
	ct := h.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "text/event-stream")
}

func addVary(h http.Header, value string) {
	var parts []string
	seen := map[string]struct{}{}
	for _, v := range h.Values("Vary") {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			key := strings.ToLower(part)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			parts = append(parts, part)
		}
	}
	key := strings.ToLower(value)
	if _, ok := seen[key]; !ok {
		parts = append(parts, value)
	}
	h.Set("Vary", strings.Join(parts, ", "))
}

func withTrustedHost(allowed []string, next http.Handler) http.Handler {
	list := append([]string(nil), allowed...)
	anyHost := false
	for _, host := range list {
		if host == "*" {
			anyHost = true
			break
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if anyHost {
			next.ServeHTTP(w, r)
			return
		}
		host, ok := requestHostname(r.Host)
		if !ok {
			http.Error(w, "Invalid host header", http.StatusBadRequest)
			return
		}
		if trustedHost(list, host) {
			next.ServeHTTP(w, r)
			return
		}
		if www := wwwTarget(list, host); www != "" {
			http.Redirect(w, r, redirectURL(r, www, requestScheme(r)), http.StatusTemporaryRedirect)
			return
		}
		http.Error(w, "Invalid host header", http.StatusBadRequest)
	})
}

func trustedHost(allowed []string, host string) bool {
	for _, pattern := range allowed {
		if host == pattern || (strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:])) {
			return true
		}
	}
	return false
}

func wwwTarget(allowed []string, host string) string {
	if strings.HasPrefix(host, "www.") {
		return ""
	}
	www := "www." + host
	for _, pattern := range allowed {
		if pattern == www {
			return www
		}
	}
	return ""
}

func withHTTPSRedirect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestIsHTTPS(r) {
			next.ServeHTTP(w, r)
			return
		}
		host, ok := requestHostname(r.Host)
		if !ok {
			http.Error(w, "Invalid host header", http.StatusBadRequest)
			return
		}
		scheme := "https"
		if strings.EqualFold(r.URL.Scheme, "ws") || strings.EqualFold(r.URL.Scheme, "wss") {
			scheme = "wss"
		}
		http.Redirect(w, r, redirectURL(r, host, scheme), http.StatusTemporaryRedirect)
	})
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	scheme := strings.ToLower(r.URL.Scheme)
	return scheme == "https" || scheme == "wss"
}

func requestScheme(r *http.Request) string {
	if strings.EqualFold(r.URL.Scheme, "ws") || strings.EqualFold(r.URL.Scheme, "wss") {
		if requestIsHTTPS(r) {
			return "wss"
		}
		return "ws"
	}
	if requestIsHTTPS(r) {
		return "https"
	}
	return "http"
}

func requestHostname(hostport string) (string, bool) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" || strings.ContainsAny(hostport, " /?#@\\") {
		return "", false
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	host = strings.TrimSuffix(host, ".")
	host = strings.ToLower(host)
	if host == "" || strings.ContainsAny(host, " /?#@\\") {
		return "", false
	}
	return host, true
}

func redirectURL(r *http.Request, host, scheme string) string {
	u := *r.URL
	u.Scheme = scheme
	_, port, err := net.SplitHostPort(strings.TrimSpace(r.Host))
	if err != nil || port == "" || port == "80" || port == "443" {
		port = ""
	}
	if strings.Contains(host, ":") {
		u.Host = net.JoinHostPort(host, port)
		if port == "" {
			u.Host = "[" + host + "]"
		}
	} else if port == "" {
		u.Host = host
	} else {
		u.Host = net.JoinHostPort(host, port)
	}
	return u.String()
}
