package gfast

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
)

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
