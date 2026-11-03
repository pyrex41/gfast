package gfast

import (
	"compress/gzip"
	"context"
	"regexp"
	"strings"
)

// Option configures an app, a group, or a single route.
// App-level options apply to New. Route-level options apply to Get and the
// other route helpers, and to Group, where they are inherited by the routes
// in that group.
type Option func(*optionBag)

type optionBag struct {
	app   *appConfig
	route *routeConfig
}

type appConfig struct {
	title          string
	version        string
	onStart        []func(context.Context) error
	onStop         []func(context.Context) error
	cors           bool
	origins        []string
	originPatterns []string
	credentials    bool
	exposeHeaders  []string
	maxAge         *int
	gzip           bool
	gzipLevel      int
	trustedHosts   []string
	trustedOn      bool
	httpsRedirect  bool
	oauth          *OAuthConfig
	sessions       *sessionConfig
	csrfOff        bool
	csrfStrict     bool
	csrfToken      bool
	csrfOrigins    []string
	wsOrigins      []string
	maxBody        int64
	docs           *bool
	servers        []Server
	externalDocs   *externalDoc
	tags           []tagDoc
	webhooks       map[string]any
	specHooks      []func(map[string]any)
}

type routeConfig struct {
	summary      string
	description  string
	tags         []string
	status       int
	scopes       []string
	requires     []Dependency
	responses    []extraResponse
	wsMax        int
	operationID  string
	deprecated   bool
	include      *bool
	externalDocs *externalDoc
	callbacks    map[string]any
	skipCSRF     bool
	maxBody      *int64
}

// extraResponse is one extra OpenAPI response collected from Responses.
type extraResponse struct {
	status      int
	description string
	model       any
	media       string
}

func (c routeConfig) clone() routeConfig {
	c.tags = append([]string(nil), c.tags...)
	c.scopes = append([]string(nil), c.scopes...)
	c.requires = append([]Dependency(nil), c.requires...)
	c.responses = append([]extraResponse(nil), c.responses...)
	if len(c.callbacks) > 0 {
		copied := make(map[string]any, len(c.callbacks))
		for key, value := range c.callbacks {
			copied[key] = value
		}
		c.callbacks = copied
	}
	return c
}

func (c routeConfig) inSchema() bool {
	return c.include == nil || *c.include
}

func (c appConfig) docsOn() bool {
	return c.docs == nil || *c.docs
}

// Example is the struct tag for an OpenAPI example value.
// `example:"coat"` publishes that value on the field schema.
const Example = "example"

// Title sets the OpenAPI document title. App-level.
func Title(title string) Option {
	return func(b *optionBag) {
		if b.app != nil {
			b.app.title = title
		}
	}
}

// Version sets the OpenAPI document version. App-level.
func Version(version string) Option {
	return func(b *optionBag) {
		if b.app != nil {
			b.app.version = version
		}
	}
}

// OnStart runs before the server accepts connections.
// The context carries the app state map. See StateFrom. App-level.
func OnStart(fn func(context.Context) error) Option {
	return func(b *optionBag) {
		if b.app != nil && fn != nil {
			b.app.onStart = append(b.app.onStart, fn)
		}
	}
}

// OnStop runs after the server stops.
// The context carries the app state map. See StateFrom. App-level.
func OnStop(fn func(context.Context) error) Option {
	return func(b *optionBag) {
		if b.app != nil && fn != nil {
			b.app.onStop = append(b.app.onStop, fn)
		}
	}
}

// OAuthServer mounts an in-process OAuth 2.1 authorization server.
// Nothing is mounted unless this option is set. See OAuthConfig.
// App-level.
func OAuthServer(cfg OAuthConfig) Option {
	return func(b *optionBag) {
		if b.app == nil {
			return
		}
		copied := cfg
		copied.Clients = append([]OAuthClient(nil), cfg.Clients...)
		if cfg.Scopes != nil {
			copied.Scopes = make(map[string]string, len(cfg.Scopes))
			for name, desc := range cfg.Scopes {
				copied.Scopes[name] = desc
			}
		}
		b.app.oauth = &copied
	}
}

// CORS enables cross-origin requests.
// With no origins, every origin is allowed unless AllowCredentials is set.
// "*" allows every origin. Any other origin that contains "*" is a pattern.
// App-level.
func CORS(origins ...string) Option {
	return func(b *optionBag) {
		if b.app != nil {
			b.app.cors = true
			b.app.origins = append(b.app.origins, origins...)
		}
	}
}

// AllowOriginPattern allows origins that match a regular expression.
// The expression is matched against the whole origin. App-level.
// It takes effect when CORS is enabled.
func AllowOriginPattern(patterns ...string) Option {
	return func(b *optionBag) {
		if b.app == nil {
			return
		}
		for _, pattern := range patterns {
			if pattern == "" {
				panic("gfast: empty origin pattern")
			}
			if _, err := regexp.Compile(anchorOriginPattern(pattern)); err != nil {
				panic("gfast: bad origin pattern: " + err.Error())
			}
			b.app.originPatterns = append(b.app.originPatterns, pattern)
		}
	}
}

// AllowCredentials sets Access-Control-Allow-Credentials on allowed origins.
// An empty origin list then does not echo an arbitrary origin. Credentials
// require a listed origin or a pattern. App-level. CORS must be enabled.
func AllowCredentials(on bool) Option {
	return func(b *optionBag) {
		if b.app != nil {
			b.app.credentials = on
		}
	}
}

// ExposeHeaders sets Access-Control-Expose-Headers on allowed origins.
// App-level. CORS must be enabled.
func ExposeHeaders(headers ...string) Option {
	return func(b *optionBag) {
		if b.app != nil {
			b.app.exposeHeaders = append(b.app.exposeHeaders, headers...)
		}
	}
}

// MaxAge sets Access-Control-Max-Age, in seconds, on a CORS preflight.
// App-level. CORS must be enabled.
func MaxAge(seconds int) Option {
	return func(b *optionBag) {
		if b.app == nil {
			return
		}
		if seconds < 0 {
			panic("gfast: MaxAge must not be negative")
		}
		n := seconds
		b.app.maxAge = &n
	}
}

// Gzip compresses responses when the client accepts gzip.
// An explicit gzip coding wins over "*": gzip;q=0 does not compress even
// when the wildcard quality is higher, and a lone "*" may still select gzip.
// Duplicate gzip tokens select gzip when any of them has a positive quality.
// A missing q means 1. The first q on a coding wins. A q above 1 counts as 1.
// A negative q, or a q that is not a number, counts as 0 and still marks an
// explicit gzip coding. Names and q are case-insensitive. A missing
// Accept-Encoding header does not select gzip.
// A response that already has a content encoding is not compressed again,
// and event streams are not compressed. The optional level is a compress/gzip
// level. App-level.
func Gzip(level ...int) Option {
	return func(b *optionBag) {
		if b.app == nil {
			return
		}
		lv := gzip.DefaultCompression
		if len(level) > 0 {
			lv = level[0]
			if lv < gzip.HuffmanOnly || lv > gzip.BestCompression {
				panic("gfast: gzip level out of range")
			}
		}
		b.app.gzip = true
		b.app.gzipLevel = lv
	}
}

// TrustedHost rejects requests whose host is not listed.
// "*" allows any host. "*.example.com" allows that suffix.
// A listed "www.example.com" redirects the apex host to www.
// App-level.
func TrustedHost(hosts ...string) Option {
	return func(b *optionBag) {
		if b.app == nil {
			return
		}
		if len(hosts) == 0 {
			panic("gfast: TrustedHost requires a host")
		}
		for _, host := range hosts {
			host = strings.ToLower(strings.TrimSpace(host))
			if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
				host = host[1 : len(host)-1]
			}
			host = strings.TrimSuffix(host, ".")
			if host == "" {
				panic("gfast: empty trusted host")
			}
			if strings.Contains(host, "*") && host != "*" && !strings.HasPrefix(host, "*.") {
				panic("gfast: trusted host wildcard must be * or *.example.com")
			}
			if strings.HasPrefix(host, "*.") && strings.Contains(host[1:], "*") {
				panic("gfast: trusted host wildcard must be * or *.example.com")
			}
			b.app.trustedHosts = append(b.app.trustedHosts, host)
		}
		b.app.trustedOn = true
	}
}

// HTTPSRedirect sends http requests to the same URL with https.
// A request that is already https, including one with TLS set, is left alone.
// App-level.
func HTTPSRedirect() Option {
	return func(b *optionBag) {
		if b.app != nil {
			b.app.httpsRedirect = true
		}
	}
}

func anchorOriginPattern(pattern string) string {
	return `\A(?:` + pattern + `)\z`
}

// Summary sets the OpenAPI operation summary.
func Summary(summary string) Option {
	return func(b *optionBag) {
		if b.route != nil {
			b.route.summary = summary
		}
	}
}

// Description sets the OpenAPI operation description.
func Description(description string) Option {
	return func(b *optionBag) {
		if b.route != nil {
			b.route.description = description
		}
	}
}

// Tags sets the OpenAPI tags for a route, or the tags inherited by a group.
func Tags(tags ...string) Option {
	return func(b *optionBag) {
		if b.route != nil {
			b.route.tags = append([]string(nil), tags...)
		}
	}
}

// Status sets the success status code. The default is 200.
// A nil handler result is still 204. ResponseFrom can override the status
// for a single request that returns a body.
func Status(code int) Option {
	return func(b *optionBag) {
		if b.route != nil {
			b.route.status = code
		}
	}
}

// ResponseDoc is an extra OpenAPI response.
// Model is a value or a typed nil; its type is the response schema.
// ContentType defaults to application/json when Model is set.
type ResponseDoc struct {
	Status      int
	Description string
	Model       any
	ContentType string
}

// Responses documents OpenAPI responses other than the success body.
// A group passes them on to the routes registered on it.
func Responses(docs ...ResponseDoc) Option {
	return func(b *optionBag) {
		if b.route == nil {
			return
		}
		for _, doc := range docs {
			if doc.Status <= 0 {
				panic("gfast: response status must be set")
			}
			b.route.responses = append(b.route.responses, extraResponse{
				status:      doc.Status,
				description: doc.Description,
				model:       doc.Model,
				media:       doc.ContentType,
			})
		}
	}
}

// Scopes documents the bearer scopes a route requires.
// The Bearer value passed to providers lists the same scopes.
func Scopes(scopes ...string) Option {
	return func(b *optionBag) {
		if b.route != nil {
			b.route.scopes = append([]string(nil), scopes...)
		}
	}
}

// Docs controls /docs and /openapi.json. The default is on.
// Docs(false) does not register those routes. App-level.
func Docs(on bool) Option {
	return func(b *optionBag) {
		if b.app != nil {
			flag := on
			b.app.docs = &flag
		}
	}
}

// Server is one OpenAPI server entry.
type Server struct {
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}

// Servers sets the OpenAPI servers array. A later call replaces an earlier one.
// App-level.
func Servers(servers ...Server) Option {
	return func(b *optionBag) {
		if b.app != nil {
			b.app.servers = append([]Server(nil), servers...)
		}
	}
}

// ExternalDocs sets external documentation.
// On New, it is the document externalDocs. On a group or a route, it is the
// operation externalDocs. The URL is the link target. The description may be empty.
func ExternalDocs(url, description string) Option {
	return func(b *optionBag) {
		doc := &externalDoc{URL: url, Description: description}
		if b.app != nil {
			b.app.externalDocs = doc
			return
		}
		if b.route != nil {
			b.route.externalDocs = doc
		}
	}
}

// TagDescription sets the OpenAPI description of a tag name.
// The tag is listed on the document. A later call for the same name replaces the description.
// App-level.
func TagDescription(name, description string) Option {
	return func(b *optionBag) {
		if b.app == nil || name == "" {
			return
		}
		for i := range b.app.tags {
			if b.app.tags[i].Name == name {
				b.app.tags[i].Description = description
				return
			}
		}
		b.app.tags = append(b.app.tags, tagDoc{Name: name, Description: description})
	}
}

// Deprecated marks an operation deprecated. A group passes the flag on.
// Deprecated(false) clears a flag inherited from a group.
func Deprecated(on bool) Option {
	return func(b *optionBag) {
		if b.route != nil {
			b.route.deprecated = on
		}
	}
}

// OperationID sets the OpenAPI operationId. The generated id is used when this is empty.
// A group passes it on to routes that do not set their own.
func OperationID(id string) Option {
	return func(b *optionBag) {
		if b.route != nil {
			b.route.operationID = id
		}
	}
}

// IncludeInSchema reports whether a route is written into the OpenAPI document.
// The default is true. The route is still served when this is false.
// A group passes the flag on. IncludeInSchema(true) shows a route in a hidden group.
func IncludeInSchema(on bool) Option {
	return func(b *optionBag) {
		if b.route == nil {
			return
		}
		flag := on
		b.route.include = &flag
	}
}

// Webhooks adds OpenAPI webhook path items, keyed by webhook name.
// The values are placed on the document and are not called. App-level.
func Webhooks(hooks map[string]any) Option {
	return func(b *optionBag) {
		if b.app == nil || len(hooks) == 0 {
			return
		}
		if b.app.webhooks == nil {
			b.app.webhooks = map[string]any{}
		}
		for key, value := range hooks {
			b.app.webhooks[key] = value
		}
	}
}

// Callbacks adds OpenAPI callback objects to one operation, keyed by callback name.
// The values are placed on the operation and are not called.
// A group passes them on.
func Callbacks(callbacks map[string]any) Option {
	return func(b *optionBag) {
		if b.route == nil || len(callbacks) == 0 {
			return
		}
		if b.route.callbacks == nil {
			b.route.callbacks = map[string]any{}
		}
		for key, value := range callbacks {
			b.route.callbacks[key] = value
		}
	}
}

// OpenAPIHook edits the OpenAPI document after routes are registered and before
// /openapi.json is written. Each hook sees the document as a JSON object.
// App-level. Hooks run in registration order.
func OpenAPIHook(fn func(doc map[string]any)) Option {
	return func(b *optionBag) {
		if b.app != nil && fn != nil {
			b.app.specHooks = append(b.app.specHooks, fn)
		}
	}
}

// WebSocketOrigins lists extra hosts that may open a browser WebSocket.
// A browser Origin is accepted when its host is the request host or one of
// these hosts. Comparison is case-insensitive, and an explicit port 80 or
// 443 is the same host as the name with that port omitted. A value may be a
// host or an absolute http or https URL; only that host is kept. A missing
// Origin is allowed. null, a malformed Origin, and any other host are
// rejected with 403 before the connection is hijacked. App-level.
func WebSocketOrigins(hosts ...string) Option {
	return func(b *optionBag) {
		if b.app == nil {
			return
		}
		if len(hosts) == 0 {
			panic("gfast: WebSocketOrigins requires a host")
		}
		for _, host := range hosts {
			b.app.wsOrigins = append(b.app.wsOrigins, normalizeWSOrigin(host))
		}
	}
}

// MaxBodyBytes limits the request body, in bytes.
// Zero means 1 MiB. A negative value panics.
// On New it is the default. On a group or a route it replaces that default,
// and a group passes the replacement on.
//
// A body over the limit is 413 problem+json before the handler runs.
// Content-Length above the limit is rejected without reading the rest.
// A shorter non-zero length and a chunked body still stop at the limit:
// the read ends after at most one extra byte and that body is not parsed.
// Content-Length 0 stays an empty body and is not read.
//
// The cap is applied before JSON binding, form parsing, multipart parsing,
// CSRF token extraction, and the OAuth authorize and token forms.
// Multipart's memory argument stays a spill threshold, not this cap.
// Spill files are removed when the request finishes.
// Require, including a bearer check that does not read the body, runs only
// after a body that fits, so an oversized body is 413 rather than a later
// auth error. One rejected request does not affect the next.
func MaxBodyBytes(n int) Option {
	return func(b *optionBag) {
		if n < 0 {
			panic("gfast: MaxBodyBytes must not be negative")
		}
		if b.app != nil {
			b.app.maxBody = int64(n)
			return
		}
		if b.route != nil {
			v := int64(n)
			b.route.maxBody = &v
		}
	}
}

// MaxMessageSize limits one WebSocket message, in bytes.
// It applies to WebSocket routes. The default is 1 MiB.
// A larger frame is closed with code 1009.
func MaxMessageSize(n int) Option {
	return func(b *optionBag) {
		if b.route == nil {
			return
		}
		if n <= 0 {
			panic("gfast: MaxMessageSize must be positive")
		}
		b.route.wsMax = n
	}
}

// Require runs dependencies before the handler. The values are discarded.
// A failure aborts the request and does not call the handler. Use this for
// routes that must be authenticated but do not read the user. On New or a
// group it also covers Mount and Static registered there. It does not cover
// /docs, /openapi.json, or the OAuth endpoints.
func Require(deps ...Dependency) Option {
	return func(b *optionBag) {
		if b.route == nil {
			return
		}
		for _, d := range deps {
			if d == nil {
				panic("gfast: Require got a nil dependency")
			}
			b.route.requires = append(b.route.requires, d)
		}
	}
}
