package gfast

import "context"

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
	title   string
	version string
	onStart []func(context.Context) error
	onStop  []func(context.Context) error
	cors    bool
	origins []string
}

type routeConfig struct {
	summary     string
	description string
	tags        []string
	status      int
	scopes      []string
	requires    []Dependency
}

func (c routeConfig) clone() routeConfig {
	c.tags = append([]string(nil), c.tags...)
	c.scopes = append([]string(nil), c.scopes...)
	c.requires = append([]Dependency(nil), c.requires...)
	return c
}

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

// OnStart runs before the server accepts connections. App-level.
func OnStart(fn func(context.Context) error) Option {
	return func(b *optionBag) {
		if b.app != nil && fn != nil {
			b.app.onStart = append(b.app.onStart, fn)
		}
	}
}

// OnStop runs after the server stops. App-level.
func OnStop(fn func(context.Context) error) Option {
	return func(b *optionBag) {
		if b.app != nil && fn != nil {
			b.app.onStop = append(b.app.onStop, fn)
		}
	}
}

// CORS enables cross-origin requests. With no origins, every origin is allowed.
// App-level.
func CORS(origins ...string) Option {
	return func(b *optionBag) {
		if b.app != nil {
			b.app.cors = true
			b.app.origins = append(b.app.origins, origins...)
		}
	}
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
// A nil handler result is still 204.
func Status(code int) Option {
	return func(b *optionBag) {
		if b.route != nil {
			b.route.status = code
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

// Require runs dependencies before the handler. The values are discarded.
// A failure aborts the request. Use this for routes that must be authenticated
// but do not read the user.
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
