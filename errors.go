package gfast

import "net/http"

// StatusError is an error that sets the HTTP response status.
// The helpers in this file return RFC 9457 problem details.
type StatusError interface {
	error
	GetStatus() int
}

type httpError struct {
	status int
	detail string
	header http.Header
	errors []fieldIssue
}

// fieldIssue is one object in a 422 problem's errors array.
type fieldIssue struct {
	Loc  []string `json:"loc"`
	Type string   `json:"type"`
	Msg  string   `json:"msg"`
}

func (e *httpError) Error() string { return e.detail }

func (e *httpError) GetStatus() int { return e.status }

func (e *httpError) Headers() http.Header { return e.header }

func (e *httpError) validationErrors() []fieldIssue { return e.errors }

func statusErr(code int, msg string) error {
	return &httpError{status: code, detail: msg}
}

// BadRequest is a 400.
func BadRequest(msg string) error { return statusErr(http.StatusBadRequest, msg) }

// Unauthorized is a 401.
func Unauthorized(msg string) error { return statusErr(http.StatusUnauthorized, msg) }

// Forbidden is a 403.
func Forbidden(msg string) error { return statusErr(http.StatusForbidden, msg) }

// NotFound is a 404.
func NotFound(msg string) error { return statusErr(http.StatusNotFound, msg) }

func unauth(msg, challenge string) error {
	return &httpError{
		status: http.StatusUnauthorized,
		detail: msg,
		header: http.Header{"WWW-Authenticate": []string{challenge}},
	}
}
