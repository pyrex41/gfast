package gfast

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strings"
)

// Mount serves h at prefix and every path under it.
// The prefix is removed before h runs, and the remaining path starts with a slash.
// The registration is a ServeMux subtree, a trailing slash, not a {name...} parameter.
// A request for the prefix without that slash is redirected by ServeMux before
// the route policy runs. gfast does not add a second redirect.
// Require, scopes, and CSRF from the app or group run before h. A rejection
// does not call h. SkipCSRF on the app or group is honored.
func (a *App) Mount(prefix string, h http.Handler) {
	mount(&a.state, prefix, h)
}

// Mount serves h under a group prefix.
func (g *Group) Mount(prefix string, h http.Handler) {
	mount(&g.state, prefix, h)
}

// Mount serves h at prefix on an App or a Group.
func Mount(r Router, prefix string, h http.Handler) {
	mount(r.isRouter(), prefix, h)
}

// Static serves files from directory at prefix with the standard file server.
// GET and HEAD are served. Any other method is 405, with Allow, when the path
// is inside the prefix. That 405 is ServeMux's, so the file server and the
// route policy do not run. GET and HEAD inherit Require, scopes, and CSRF
// from the app or group. See Mount for stripping and the trailing-slash redirect.
func (a *App) Static(prefix, directory string) {
	static(&a.state, prefix, directory)
}

// Static serves files under a group prefix.
func (g *Group) Static(prefix, directory string) {
	static(&g.state, prefix, directory)
}

// Static serves files at prefix on an App or a Group.
func Static(r Router, prefix, directory string) {
	static(r.isRouter(), prefix, directory)
}

func mount(st *routerState, prefix string, h http.Handler) {
	if h == nil {
		panic("gfast: Mount got a nil handler")
	}
	full := mountPath(st, prefix)
	st.app.mux.Handle(subtreePattern(full), policyFrom(&st.route).wrap(stripMountPrefix(full, h)))
}

func static(st *routerState, prefix, directory string) {
	if strings.TrimSpace(directory) == "" {
		panic("gfast: Static got an empty directory")
	}
	full := mountPath(st, prefix)
	// GET also matches HEAD. Other methods stay on ServeMux's 405 path,
	// outside the policy wrapper.
	handler := policyFrom(&st.route).wrap(stripMountPrefix(full, http.FileServer(http.Dir(directory))))
	st.app.mux.Handle("GET "+subtreePattern(full), handler)
}

func mountPath(st *routerState, prefix string) string {
	full := joinPath(st.prefix, prefix)
	if full == "" {
		full = "/"
	}
	if !strings.HasPrefix(full, "/") {
		full = "/" + full
	}
	if full != "/" {
		full = strings.TrimRight(full, "/")
	}
	return full
}

func subtreePattern(prefix string) string {
	if prefix == "/" {
		return "/"
	}
	return prefix + "/"
}

// stripMountPrefix leaves a rooted path. Stripping "/assets" from "/assets/"
// yields "/", and from "/assets/a" yields "/a". The root mount is unchanged.
func stripMountPrefix(prefix string, next http.Handler) http.Handler {
	if prefix == "" || prefix == "/" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, prefix)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if rest == "" {
			rest = "/"
		}
		r2 := r.Clone(r.Context())
		u := *r2.URL
		u.Path = rest
		u.RawPath = ""
		r2.URL = &u
		next.ServeHTTP(w, r2)
	})
}

// serve lets ServeMux route, then replaces its plain 404 and 405.
// http.Error, which ServeMux and the file server use, sets text/plain and
// X-Content-Type-Options: nosniff. Other responses are written through.
func (a *App) serve(w http.ResponseWriter, r *http.Request) {
	g := &stdlibErrorGate{ResponseWriter: w}
	defer g.finish()
	a.mux.ServeHTTP(g, r)
}

type stdlibErrorGate struct {
	http.ResponseWriter
	code     int
	wrote    bool
	hold     bool
	hijacked bool
	buf      bytes.Buffer
}

func (g *stdlibErrorGate) WriteHeader(code int) {
	if g.wrote || g.hold {
		return
	}
	g.code = code
	if (code == http.StatusNotFound || code == http.StatusMethodNotAllowed) && stdlibPlainError(g.Header()) {
		g.hold = true
		return
	}
	g.wrote = true
	g.ResponseWriter.WriteHeader(code)
}

func (g *stdlibErrorGate) Write(p []byte) (int, error) {
	if g.hold {
		return g.buf.Write(p)
	}
	if !g.wrote {
		g.WriteHeader(http.StatusOK)
	}
	return g.ResponseWriter.Write(p)
}

func (g *stdlibErrorGate) Flush() {
	if g.hold || g.hijacked {
		return
	}
	if !g.wrote {
		g.WriteHeader(http.StatusOK)
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *stdlibErrorGate) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := g.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	nc, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	g.hijacked = true
	return nc, rw, nil
}

func (g *stdlibErrorGate) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func (g *stdlibErrorGate) finish() {
	if g.hijacked || !g.hold {
		return
	}
	g.hold = false
	writeErr(g.ResponseWriter, statusErr(g.code, stdlibErrorDetail(g.code, g.buf.String())))
}

func stdlibPlainError(h http.Header) bool {
	if h.Get("X-Content-Type-Options") != "nosniff" {
		return false
	}
	ct := h.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "text/plain")
}

func stdlibErrorDetail(code int, body string) string {
	detail := strings.TrimSpace(body)
	if detail == "" || detail == "404 page not found" {
		return http.StatusText(code)
	}
	return detail
}
