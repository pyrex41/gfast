package gfast

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	jsonv2 "encoding/json/v2"
)

// Router is an App or a Group.
type Router interface {
	isRouter() *routerState
}

// App is the API. Build it with New, register routes, then call Run.
// Routes are served by net/http. OpenAPI is at /openapi.json. Swagger UI is at /docs.
type App struct {
	mux   *http.ServeMux
	root  http.Handler
	state routerState
	doc   apiDoc

	mu         sync.Mutex
	overrides  map[int]override
	started    bool
	cfg        appConfig
	middleware []func(http.Handler) http.Handler
	oauth      *oauthServer
	schemaIDs  map[schemaKey]string
	schemaUsed map[string]struct{}
	appState   map[string]any
}

// Group is a path prefix that shares route options, including Require.
type Group struct {
	state routerState
}

type routerState struct {
	app    *App
	route  routeConfig
	prefix string
}

func (s *routerState) isRouter() *routerState { return s }

type requestState struct {
	app         *App
	req         *http.Request
	memo        map[int]reflect.Value
	stack       map[int]bool
	closers     []ioCloser
	tasks       []func()
	scopes      []string
	resp        *Response
	socket      *Conn
	sessionOn   bool
	session     map[string]any
	sessionSnap []byte
}

type ioCloser interface{ Close() error }

type ctxKey struct{}

type appStateKey struct{}

// New builds an app.
func New(opts ...Option) *App {
	app := &App{
		overrides: map[int]override{},
		cfg:       appConfig{title: "API", version: "0.0.0"},
		mux:       http.NewServeMux(),
		appState:  map[string]any{},
	}
	bag := &optionBag{app: &app.cfg, route: &app.state.route}
	for _, opt := range opts {
		opt(bag)
	}
	app.doc = apiDoc{
		OpenAPI:      "3.1.0",
		Info:         docInfo{Title: app.cfg.title, Version: app.cfg.version},
		Servers:      append([]Server(nil), app.cfg.servers...),
		ExternalDocs: app.cfg.externalDocs,
		Tags:         append([]tagDoc(nil), app.cfg.tags...),
		Paths:        map[string]map[string]op{},
		Webhooks:     copyAnyMap(app.cfg.webhooks),
	}
	app.state.app = app
	// Built-in handlers are registered on the mux, not through routePolicy.
	// Require and SkipCSRF on New apply to routes, Mount, and Static only.
	if app.cfg.oauth != nil {
		app.oauth = newOAuthServer(app.cfg.oauth)
		app.oauth.maxBody = resolvedMaxBody(app.cfg.maxBody, nil)
		registerOAuth(app.mux, app.oauth)
	}
	if app.cfg.docsOn() {
		app.mux.HandleFunc("GET /openapi.json", app.serveSpec)
		registerDocs(app.mux, app)
	}
	app.root = app.assemble()
	return app
}

// Use registers middleware. It runs outside the router and inside CORS when
// CORS is set. The first middleware registered is the outermost.
// Gzip, when set, wraps this middleware so it sees the uncompressed response.
func (a *App) Use(mw func(http.Handler) http.Handler) {
	if mw == nil {
		panic("gfast: Use got nil middleware")
	}
	a.mu.Lock()
	a.middleware = append(a.middleware, mw)
	a.root = a.assemble()
	a.mu.Unlock()
}

// Handler returns the HTTP handler, including middleware and the docs routes.
func (a *App) Handler() http.Handler {
	a.mu.Lock()
	h := a.root
	a.mu.Unlock()
	return h
}

func (a *App) isRouter() *routerState { return &a.state }

// Group returns a router with a path prefix. Route options here, including
// Require and SkipCSRF, apply to routes, Mount, and Static registered on
// the group and on groups nested under it. They do not apply to /docs,
// /openapi.json, or the OAuth handlers.
func (a *App) Group(prefix string, opts ...Option) *Group {
	return a.state.group(prefix, opts...)
}

// Group returns a nested group.
func (g *Group) Group(prefix string, opts ...Option) *Group {
	return g.state.group(prefix, opts...)
}

func (g *Group) isRouter() *routerState { return &g.state }

func (s *routerState) group(prefix string, opts ...Option) *Group {
	route := s.route.clone()
	bag := &optionBag{route: &route}
	for _, opt := range opts {
		opt(bag)
	}
	return &Group{state: routerState{
		app:    s.app,
		route:  route,
		prefix: joinPath(s.prefix, prefix),
	}}
}

// Get registers a GET route.
func (a *App) Get[I, O any](path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(&a.state, http.MethodGet, path, handler, opts)
}

// Post registers a POST route.
func (a *App) Post[I, O any](path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(&a.state, http.MethodPost, path, handler, opts)
}

// Put registers a PUT route.
func (a *App) Put[I, O any](path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(&a.state, http.MethodPut, path, handler, opts)
}

// Patch registers a PATCH route.
func (a *App) Patch[I, O any](path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(&a.state, http.MethodPatch, path, handler, opts)
}

// Delete registers a DELETE route.
func (a *App) Delete[I, O any](path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(&a.state, http.MethodDelete, path, handler, opts)
}

// Get registers a GET route on a group.
func (g *Group) Get[I, O any](path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(&g.state, http.MethodGet, path, handler, opts)
}

// Post registers a POST route on a group.
func (g *Group) Post[I, O any](path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(&g.state, http.MethodPost, path, handler, opts)
}

// Put registers a PUT route on a group.
func (g *Group) Put[I, O any](path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(&g.state, http.MethodPut, path, handler, opts)
}

// Patch registers a PATCH route on a group.
func (g *Group) Patch[I, O any](path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(&g.state, http.MethodPatch, path, handler, opts)
}

// Delete registers a DELETE route on a group.
func (g *Group) Delete[I, O any](path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(&g.state, http.MethodDelete, path, handler, opts)
}

// Get registers a GET route. handler is func(context.Context, *In) (*Out, error).
func Get[I, O any](r Router, path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(r.isRouter(), http.MethodGet, path, handler, opts)
}

// Post registers a POST route.
func Post[I, O any](r Router, path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(r.isRouter(), http.MethodPost, path, handler, opts)
}

// Put registers a PUT route.
func Put[I, O any](r Router, path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(r.isRouter(), http.MethodPut, path, handler, opts)
}

// Patch registers a PATCH route.
func Patch[I, O any](r Router, path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(r.isRouter(), http.MethodPatch, path, handler, opts)
}

// Delete registers a DELETE route.
func Delete[I, O any](r Router, path string, handler func(context.Context, *I) (*O, error), opts ...Option) {
	register(r.isRouter(), http.MethodDelete, path, handler, opts)
}

func register[I, O any](st *routerState, method, path string, handler func(context.Context, *I) (*O, error), opts []Option) {
	if handler == nil {
		panic("gfast: nil handler")
	}
	route := st.route.clone()
	bag := &optionBag{route: &route}
	for _, opt := range opts {
		opt(bag)
	}

	inType := reflect.TypeOf((*I)(nil)).Elem()
	outType := reflect.TypeOf((*O)(nil)).Elem()
	fields := collectDepFields(inType)
	for _, field := range fields {
		field.dep.bind(nil)
	}
	policy := policyFrom(&route)

	schemes := map[string]*namedScheme{}
	seen := map[int]struct{}{}
	for _, field := range fields {
		field.dep.collectSchemes(seen, schemes)
	}
	for _, dep := range policy.requires {
		dep.collectSchemes(seen, schemes)
	}

	status := route.status
	if status == 0 {
		status = http.StatusOK
	}
	full := joinPath(st.prefix, path)
	plan := planInput(inType)
	st.app.addOperation(full, method, route, inType, outType, schemes, status)

	h := func(w http.ResponseWriter, r *http.Request) {
		rst, ok := policy.open(w, r)
		if !ok {
			return
		}
		in := new(I)
		inVal := reflect.ValueOf(in).Elem()
		if err := bindInput(r, inVal, plan); err != nil {
			writeErr(w, err)
			return
		}
		if !policy.authorize(w, r) {
			return
		}
		ctx := r.Context()
		for _, field := range fields {
			val, err := callDep(ctx, field.dep)
			if err != nil {
				writeErr(w, err)
				return
			}
			assignField(fieldByIndexAlloc(inVal, field.index), val)
		}
		out, err := handler(ctx, in)
		writeResult(w, r, rst.resp, status, out, err)
	}
	st.app.mux.HandleFunc(method+" "+full, h)
	if method == http.MethodGet {
		st.app.mux.HandleFunc(http.MethodHead+" "+full, h)
	}
}

// routePolicy is the inherited scope list, CSRF flag, body limit, and Require
// list for one registration. /docs, /openapi.json, and /oauth are not wrapped
// with it. OAuth uses the app limit on its own handlers.
type routePolicy struct {
	scopes   []string
	skipCSRF bool
	requires []*depEntry
	maxBody  *int64
}

func policyFrom(route *routeConfig) routePolicy {
	requires := make([]*depEntry, 0, len(route.requires))
	for _, dep := range route.requires {
		requires = append(requires, dep.dependency())
	}
	for _, dep := range requires {
		dep.bind(nil)
	}
	return routePolicy{
		scopes:   append([]string(nil), route.scopes...),
		skipCSRF: route.skipCSRF,
		requires: requires,
		maxBody:  route.maxBody,
	}
}

// open limits the body, sets scopes, and enforces CSRF. It writes the error
// and returns false when the request stops here, before Require and before
// the handler.
func (p routePolicy) open(w http.ResponseWriter, r *http.Request) (*requestState, bool) {
	rst, err := stateFrom(r.Context())
	if err != nil {
		writeErr(w, err)
		return nil, false
	}
	rst.scopes = p.scopes
	if err := installBodyLimit(w, r, resolvedMaxBody(rst.app.cfg.maxBody, p.maxBody)); err != nil {
		writeErr(w, err)
		return nil, false
	}
	if err := enforceCSRF(r, p.skipCSRF); err != nil {
		writeErr(w, err)
		return nil, false
	}
	return rst, true
}

// authorize runs Require. A rejecting dependency is written and returns false
// so the handler does not run. Dependencies already acquired stay on the
// request and close with it.
func (p routePolicy) authorize(w http.ResponseWriter, r *http.Request) bool {
	ctx := r.Context()
	for _, dep := range p.requires {
		if _, err := callDep(ctx, dep); err != nil {
			writeErr(w, err)
			return false
		}
	}
	return true
}

// wrap applies open and authorize before next. A rejection does not call next.
func (p routePolicy) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := p.open(w, r); !ok {
			return
		}
		if !p.authorize(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func securityRequirement(schemes map[string]*namedScheme, scopes []string) map[string][]string {
	names := make([]string, 0, len(schemes))
	for name := range schemes {
		names = append(names, name)
	}
	sort.Strings(names)
	req := make(map[string][]string, len(names))
	for _, name := range names {
		if name == "bearerAuth" {
			req[name] = append([]string{}, scopes...)
			continue
		}
		req[name] = []string{}
	}
	return req
}

func (a *App) serveSpec(w http.ResponseWriter, _ *http.Request) {
	a.mu.Lock()
	body, err := jsonv2.Marshal(a.doc)
	var hooks []func(map[string]any)
	hooks = append(hooks, a.cfg.specHooks...)
	a.mu.Unlock()
	if err != nil {
		writeErr(w, err)
		return
	}
	if len(hooks) > 0 {
		var doc map[string]any
		if err := jsonv2.Unmarshal(body, &doc); err != nil {
			writeErr(w, err)
			return
		}
		for _, hook := range hooks {
			hook(doc)
		}
		body, err = jsonv2.Marshal(doc)
		if err != nil {
			writeErr(w, err)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func copyAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func htmlText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func htmlAttr(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;").Replace(s)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	payload, err := jsonv2.Marshal(body)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

type problem struct {
	Title  string       `json:"title"`
	Status int          `json:"status"`
	Detail string       `json:"detail,omitempty"`
	Errors []fieldIssue `json:"errors,omitempty"`
}

func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	detail := "unexpected error occurred"
	var se StatusError
	if errors.As(err, &se) {
		status = se.GetStatus()
		detail = err.Error()
	}
	var headed interface{ Headers() http.Header }
	if errors.As(err, &headed) && headed.Headers() != nil {
		for key, values := range headed.Headers() {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
	}
	var issues []fieldIssue
	var listed interface{ validationErrors() []fieldIssue }
	if errors.As(err, &listed) {
		issues = listed.validationErrors()
	}
	payload, mErr := jsonv2.Marshal(problem{Title: http.StatusText(status), Status: status, Detail: detail, Errors: issues})
	if mErr != nil {
		http.Error(w, detail, status)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

// Override replaces a dependency for later requests. The function replaces
// the original, including which parameters run. A test double that takes only
// context does not require credentials.
func (a *App) Override(dep Dependency, fn any) {
	if dep == nil {
		panic("gfast: Override got a nil dependency")
	}
	entry := dep.dependency()
	ov := bindOverride(entry, fn)
	a.mu.Lock()
	a.overrides[entry.id] = ov
	a.mu.Unlock()
}

const defaultMaxBodyBytes int64 = 1 << 20

func resolvedMaxBody(appLimit int64, route *int64) int64 {
	n := appLimit
	if route != nil {
		n = *route
	}
	if n == 0 {
		return defaultMaxBodyBytes
	}
	return n
}

func installBodyLimit(w http.ResponseWriter, r *http.Request, limit int64) error {
	if r.Body == nil {
		r.Body = http.NoBody
	}
	r.Body = http.MaxBytesReader(unwrapWriter(w), r.Body, limit)
	if st, err := stateFrom(r.Context()); err == nil {
		st.closers = append(st.closers, multipartCleanup{r: r})
	}
	if r.ContentLength > limit {
		return requestTooLarge()
	}
	return nil
}

func unwrapWriter(w http.ResponseWriter) http.ResponseWriter {
	for range 8 {
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return w
		}
		next := u.Unwrap()
		if next == nil || next == w {
			return w
		}
		w = next
	}
	return w
}

type multipartCleanup struct{ r *http.Request }

func (c multipartCleanup) Close() error {
	if c.r == nil || c.r.MultipartForm == nil {
		return nil
	}
	return c.r.MultipartForm.RemoveAll()
}

func (a *App) override(id int) (override, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ov, ok := a.overrides[id]
	return ov, ok
}

func (a *App) withState(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ServeMux serves HEAD on a GET pattern, and ResponseRecorder keeps
		// whatever the handler writes. Drop the body here so App.Request
		// matches the empty HEAD body a net/http server would send, while
		// the headers stay the ones the GET handler produced.
		dst := w
		var head *headCapture
		if r.Method == http.MethodHead {
			head = &headCapture{header: make(http.Header)}
			dst = head
		}
		st := &requestState{
			app:   a,
			req:   r,
			memo:  map[int]reflect.Value{},
			stack: map[int]bool{},
		}
		var sw *sessionWriter
		if cfg := a.cfg.sessions; cfg != nil {
			st.sessionOn = true
			st.session, st.sessionSnap = loadSession(r, cfg)
			if a.cfg.csrfToken {
				ensureCSRFToken(st.session)
			}
			sw = &sessionWriter{ResponseWriter: dst, cfg: cfg, st: st, csrf: a.cfg.csrfToken}
			dst = sw
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, st)
		ctx = context.WithValue(ctx, appStateKey{}, a.appState)
		r = r.WithContext(ctx)
		st.req = r
		defer func() {
			// A faulty closer must not strand resources acquired before it.
			// Preserve panic visibility after attempting all remaining closes.
			var firstPanic any
			for i := len(st.closers) - 1; i >= 0; i-- {
				func() {
					defer func() {
						if value := recover(); value != nil && firstPanic == nil {
							firstPanic = value
						}
					}()
					_ = st.closers[i].Close()
				}()
			}
			if firstPanic != nil {
				panic(firstPanic)
			}
		}()
		defer func() {
			for _, task := range st.tasks {
				task()
			}
		}()
		if head != nil {
			defer head.finish(w)
		}
		if sw != nil {
			defer sw.finish()
		}
		next.ServeHTTP(dst, r)
	})
}

// assemble stacks handlers from the outside in: trusted host, HTTPS redirect,
// CORS, gzip, Use, then the router. Use stays outside the router and inside
// CORS. Gzip stays outside Use so middleware sees the uncompressed response.
func (a *App) assemble() http.Handler {
	var h http.Handler = http.HandlerFunc(a.serve)
	h = a.withState(h)
	for i := len(a.middleware) - 1; i >= 0; i-- {
		h = a.middleware[i](h)
	}
	if a.cfg.gzip {
		h = withGzip(a.cfg.gzipLevel, h)
	}
	if a.cfg.cors {
		h = withCORS(newCORSPolicy(a.cfg), h)
	}
	if a.cfg.httpsRedirect {
		h = withHTTPSRedirect(h)
	}
	if a.cfg.trustedOn {
		h = withTrustedHost(a.cfg.trustedHosts, h)
	}
	return h
}

func stateFrom(ctx context.Context) (*requestState, error) {
	st, _ := ctx.Value(ctxKey{}).(*requestState)
	if st == nil {
		return nil, errors.New("gfast: no request in context")
	}
	return st, nil
}

// RequestFrom returns the *http.Request for this handler context.
// It panics if ctx is not a gfast request.
func RequestFrom(ctx context.Context) *http.Request {
	st, err := stateFrom(ctx)
	if err != nil {
		panic("gfast.RequestFrom: " + err.Error())
	}
	return st.req
}

// StateFrom returns the mutable app state map.
// OnStart and OnStop receive it on their context. Handlers read the same map.
// It panics if ctx did not come from a gfast request or from those hooks.
// The map is not safe for concurrent writes.
func StateFrom(ctx context.Context) map[string]any {
	if ctx != nil {
		if m, ok := ctx.Value(appStateKey{}).(map[string]any); ok && m != nil {
			return m
		}
	}
	panic("gfast.StateFrom: no app state in context")
}

// State returns the mutable app state map.
// OnStart hooks and handlers share this map. See StateFrom.
// The map is not safe for concurrent writes.
func (a *App) State() map[string]any {
	return a.appState
}

func (a *App) hookContext() context.Context {
	return context.WithValue(context.Background(), appStateKey{}, a.appState)
}

// ListenAndServe starts the server. OnStart runs first. OnStop runs when
// the server returns.
func (a *App) ListenAndServe(addr string) error {
	if err := a.boot(); err != nil {
		return err
	}
	defer a.shutdown()
	srv := &http.Server{
		Addr:              addr,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Serve accepts connections on ln. OnStart runs first. OnStop runs when
// Serve returns.
func (a *App) Serve(ln net.Listener) error {
	if err := a.boot(); err != nil {
		return err
	}
	defer a.shutdown()
	srv := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second}
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Run starts the server and shuts it down on SIGINT or SIGTERM.
func (a *App) Run(addr string) error {
	if err := a.boot(); err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sig)

	var serveErr error
	select {
	case serveErr = <-errCh:
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		serveErr = srv.Shutdown(ctx)
	}
	if err := a.shutdown(); serveErr == nil {
		serveErr = err
	}
	return serveErr
}

func (a *App) boot() error {
	a.mu.Lock()
	if a.started {
		a.mu.Unlock()
		return errors.New("gfast: server already started")
	}
	a.started = true
	a.mu.Unlock()
	return a.runStartHooks()
}

func (a *App) runStartHooks() error {
	a.mu.Lock()
	hooks := append([]func(context.Context) error(nil), a.cfg.onStart...)
	a.mu.Unlock()
	ctx := a.hookContext()
	for _, hook := range hooks {
		if err := hook(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) shutdown() error {
	return a.stopHooks()
}

func (a *App) stopHooks() error {
	a.mu.Lock()
	hooks := append([]func(context.Context) error(nil), a.cfg.onStop...)
	a.mu.Unlock()
	ctx := a.hookContext()
	var errs []error
	for _, hook := range hooks {
		if err := hook(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func operationID(method, path string) string {
	var b strings.Builder
	b.WriteString(strings.ToLower(method))
	for _, r := range path {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	if s == "" {
		s = strings.ToLower(method)
	}
	return s
}

func joinPath(prefix, path string) string {
	if prefix == "" {
		return path
	}
	if path == "" {
		return prefix
	}
	return strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(path, "/")
}
