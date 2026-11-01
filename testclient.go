package gfast

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
)

// ClientRedirectLimit is the most redirects a Client follows.
// The response that would pass the limit is returned as-is.
const ClientRedirectLimit = 10

// Client sends requests through an App without listening on a port.
// One client keeps a cookie jar across calls and follows redirects on the
// same host, up to ClientRedirectLimit. The first request runs OnStart.
// Close runs OnStop when Start succeeded.
// App.Request stays a single shot: no jar, no redirects, and no hooks.
type Client struct {
	// FollowRedirects follows 301, 302, 303, 307, and 308 responses.
	// Client turns it on. Set it false to return the redirect response.
	// A redirect to another host is not followed.
	FollowRedirects bool

	app       *App
	jar       http.CookieJar
	mu        sync.Mutex
	startOnce sync.Once
	stopOnce  sync.Once
	started   bool
	closed    bool
	startErr  error
	stopErr   error
}

// Result is a recorded response from App.Request.
type Result struct {
	Status int
	Header http.Header
	Body   []byte
}

// JSON decodes the response body into dest.
func (r *Result) JSON(dest any) error {
	return json.Unmarshal(r.Body, dest)
}

// Request sends one request through the app without listening on a port.
// Pass one header map when the call needs headers.
func (a *App) Request(method, path string, body []byte, headers ...http.Header) *Result {
	var header http.Header
	if len(headers) > 0 {
		header = headers[0]
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	for key, values := range header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if len(body) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	payload, _ := io.ReadAll(res.Body)
	return &Result{Status: res.StatusCode, Header: res.Header.Clone(), Body: payload}
}

// Client returns a test client for this app.
// The client keeps cookies and follows same-host redirects.
func (a *App) Client() *Client {
	if a == nil {
		panic("gfast: nil app")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic("gfast: cookie jar: " + err.Error())
	}
	return &Client{app: a, jar: jar, FollowRedirects: true}
}

// Start runs OnStart once, before requests.
// The first Request calls Start. A failed start is remembered.
func (c *Client) Start() error {
	c.startOnce.Do(func() {
		c.mu.Lock()
		closed := c.closed
		c.mu.Unlock()
		if closed {
			c.startErr = errors.New("gfast: client closed")
			return
		}
		c.startErr = c.app.runStartHooks()
		if c.startErr != nil {
			return
		}
		c.mu.Lock()
		c.started = true
		c.mu.Unlock()
	})
	return c.startErr
}

// Close runs OnStop once when Start succeeded.
// A second call does nothing. Close without a successful Start does not
// run OnStop.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		err := c.stopErr
		c.mu.Unlock()
		return err
	}
	c.closed = true
	started := c.started
	c.mu.Unlock()
	if !started {
		return nil
	}
	c.stopOnce.Do(func() {
		c.stopErr = c.app.stopHooks()
	})
	return c.stopErr
}

// Request sends one request, then follows same-host redirects when
// FollowRedirects is set. Cookies from earlier responses are sent.
// Start runs on the first call. It panics if Start fails or the client is closed.
func (c *Client) Request(method, path string, body []byte, headers ...http.Header) *Result {
	if err := c.Start(); err != nil {
		panic(err)
	}
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		panic(errors.New("gfast: client closed"))
	}
	header := http.Header{}
	if len(headers) > 0 && headers[0] != nil {
		header = headers[0].Clone()
	}
	follow := c.FollowRedirects
	includeCookie := true
	var res *Result
	for hop := 0; ; hop++ {
		var page *url.URL
		res, page = c.roundTrip(method, path, body, header, includeCookie)
		includeCookie = false
		if !follow || !redirectStatus(res.Status) {
			return res
		}
		loc := res.Header.Get("Location")
		if loc == "" || hop >= ClientRedirectLimit {
			return res
		}
		next, ok := resolveClientRedirect(page, loc)
		if !ok {
			return res
		}
		if dropRedirectBody(res.Status) {
			if method != http.MethodGet && method != http.MethodHead {
				method = http.MethodGet
			}
			body = nil
			header.Del("Content-Type")
		}
		path = next.String()
	}
}

func (c *Client) roundTrip(method, path string, body []byte, header http.Header, includeCookie bool) (*Result, *url.URL) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	for key, values := range header {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		if !includeCookie && strings.EqualFold(key, "Cookie") {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if len(body) > 0 && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	page := requestPage(req)
	if c.jar != nil {
		have := map[string]struct{}{}
		for _, ck := range req.Cookies() {
			have[ck.Name] = struct{}{}
		}
		for _, ck := range c.jar.Cookies(page) {
			if _, ok := have[ck.Name]; ok {
				continue
			}
			req.AddCookie(ck)
		}
	}
	rec := httptest.NewRecorder()
	c.app.Handler().ServeHTTP(rec, req)
	res := rec.Result()
	defer res.Body.Close()
	payload, _ := io.ReadAll(res.Body)
	if c.jar != nil {
		c.jar.SetCookies(page, res.Cookies())
	}
	return &Result{Status: res.StatusCode, Header: res.Header.Clone(), Body: payload}, page
}

func requestPage(req *http.Request) *url.URL {
	u := *req.URL
	if u.Host == "" {
		u.Host = req.Host
	}
	if u.Scheme == "" {
		if req.TLS != nil {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	return &u
}

func redirectStatus(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func dropRedirectBody(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
		return true
	default:
		return false
	}
}

func resolveClientRedirect(from *url.URL, location string) (*url.URL, bool) {
	if from == nil {
		return nil, false
	}
	loc, err := url.Parse(location)
	if err != nil {
		return nil, false
	}
	next := from.ResolveReference(loc)
	next.Fragment = ""
	if next.Scheme != "http" && next.Scheme != "https" {
		return nil, false
	}
	if next.Host == "" || !strings.EqualFold(next.Hostname(), from.Hostname()) {
		return nil, false
	}
	return next, true
}
