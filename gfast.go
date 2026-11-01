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

	mu        sync.Mutex
	overrides map[int]override
	started   bool
	cfg       appConfig
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
	app     *App
	req     *http.Request
	memo    map[int]reflect.Value
	stack   map[int]bool
	closers []ioCloser
	tasks   []func()
	scopes  []string
}

type ioCloser interface{ Close() error }

type ctxKey struct{}

// New builds an app.
func New(opts ...Option) *App {
	app := &App{
		overrides: map[int]override{},
		cfg:       appConfig{title: "API", version: "0.0.0"},
		mux:       http.NewServeMux(),
	}
	bag := &optionBag{app: &app.cfg, route: &app.state.route}
	for _, opt := range opts {
		opt(bag)
	}
	app.doc = apiDoc{
		OpenAPI: "3.1.0",
		Info:    docInfo{Title: app.cfg.title, Version: app.cfg.version},
		Paths:   map[string]map[string]op{},
	}
	app.state.app = app
	app.mux.HandleFunc("GET /openapi.json", app.serveSpec)
	registerDocs(app.mux, app)
	app.root = app.withState(app.mux)
	if app.cfg.cors {
		app.root = app.withCORS(app.root)
	}
	return app
}

// Handler returns the HTTP handler, including the docs routes.
func (a *App) Handler() http.Handler { return a.root }

func (a *App) isRouter() *routerState { return &a.state }

// Group returns a router with a path prefix. Route options here, including
// Require, apply to every route registered on the group.
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
	requires := make([]*depEntry, 0, len(route.requires))
	for _, dep := range route.requires {
		requires = append(requires, dep.dependency())
	}
	for _, field := range fields {
		field.dep.bind(nil)
	}
	for _, dep := range requires {
		dep.bind(nil)
	}

	schemes := map[string]*namedScheme{}
	seen := map[int]struct{}{}
	for _, field := range fields {
		field.dep.collectSchemes(seen, schemes)
	}
	for _, dep := range requires {
		dep.collectSchemes(seen, schemes)
	}

	status := route.status
	if status == 0 {
		status = http.StatusOK
	}
	full := joinPath(st.prefix, path)
	plan := planInput(inType)
	scopes := append([]string(nil), route.scopes...)
	st.app.addOperation(full, method, route, inType, outType, schemes, status)

	st.app.mux.HandleFunc(method+" "+full, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rst, err := stateFrom(ctx)
		if err != nil {
			writeErr(w, err)
			return
		}
		rst.scopes = scopes
		in := new(I)
		inVal := reflect.ValueOf(in).Elem()
		if err := bindInput(r, inVal, plan); err != nil {
			writeErr(w, err)
			return
		}
		for _, dep := range requires {
			if _, err := callDep(ctx, dep); err != nil {
				writeErr(w, err)
				return
			}
		}
		for _, field := range fields {
			val, err := callDep(ctx, field.dep)
			if err != nil {
				writeErr(w, err)
				return
			}
			assignField(fieldByIndexAlloc(inVal, field.index), val)
		}
		out, err := handler(ctx, in)
		if err != nil {
			writeErr(w, err)
			return
		}
		if out == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, status, out)
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
	a.mu.Unlock()
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func htmlText(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
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
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
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
	payload, mErr := jsonv2.Marshal(problem{Title: http.StatusText(status), Status: status, Detail: detail})
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

func (a *App) override(id int) (override, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ov, ok := a.overrides[id]
	return ov, ok
}

func (a *App) withState(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := &requestState{
			app:   a,
			req:   r,
			memo:  map[int]reflect.Value{},
			stack: map[int]bool{},
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, st))
		defer func() {
			for i := len(st.closers) - 1; i >= 0; i-- {
				_ = st.closers[i].Close()
			}
		}()
		defer func() {
			for _, task := range st.tasks {
				task()
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (a *App) withCORS(next http.Handler) http.Handler {
	allowed := map[string]struct{}{}
	star := len(a.cfg.origins) == 0
	for _, origin := range a.cfg.origins {
		if origin == "*" {
			star = true
		}
		allowed[origin] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && (star || has(allowed, origin)) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func has(set map[string]struct{}, key string) bool {
	_, ok := set[key]
	return ok
}

func stateFrom(ctx context.Context) (*requestState, error) {
	st, _ := ctx.Value(ctxKey{}).(*requestState)
	if st == nil {
		return nil, errors.New("gfast: no request in context")
	}
	return st, nil
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
	hooks := append([]func(context.Context) error(nil), a.cfg.onStart...)
	a.mu.Unlock()
	for _, hook := range hooks {
		if err := hook(context.Background()); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) shutdown() error {
	a.mu.Lock()
	hooks := append([]func(context.Context) error(nil), a.cfg.onStop...)
	a.mu.Unlock()
	var errs []error
	for _, hook := range hooks {
		if err := hook(context.Background()); err != nil {
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
