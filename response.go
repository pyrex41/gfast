package gfast

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Response is the success response for the current request.
// Status, headers, and cookies set here are applied when the response is written.
// The status from registration is the default. A nil handler result is still 204.
type Response struct {
	status      int
	header      http.Header
	cookies     []*http.Cookie
	contentType string
}

// ResponseFrom returns the Response stored on the request context.
// It panics if ctx did not come from a gfast request.
func ResponseFrom(ctx context.Context) *Response {
	st, err := stateFrom(ctx)
	if err != nil {
		panic(fmt.Errorf("gfast.ResponseFrom: %w", err))
	}
	if st.resp == nil {
		st.resp = &Response{header: make(http.Header)}
	}
	return st.resp
}

// SetStatus overrides the success status for this request.
// A nil handler result is still 204.
func (r *Response) SetStatus(code int) {
	if r != nil {
		r.status = code
	}
}

// Header returns the header map applied to the success response.
func (r *Response) Header() http.Header {
	if r.header == nil {
		r.header = make(http.Header)
	}
	return r.header
}

// SetCookie adds a Set-Cookie header.
func (r *Response) SetCookie(cookie *http.Cookie) {
	if r == nil || cookie == nil {
		return
	}
	r.cookies = append(r.cookies, cookie)
}

// SetContentType sets the success Content-Type.
// A string or []byte body is then written as-is, so text/html is a raw document.
// JSON struct responses stay application/json.
func (r *Response) SetContentType(v string) {
	if r != nil {
		r.contentType = v
	}
}

// Redirect sends the client to URL.
// Code 0 uses a 3xx status set with SetStatus or Status, and 307 otherwise.
type Redirect struct {
	URL  string
	Code int
}

// RedirectTo builds a redirect response. code 0 selects the default.
func RedirectTo(url string, code int) *Redirect {
	return &Redirect{URL: url, Code: code}
}

// FileResponse is a body served with http.ServeContent.
// Name's extension supplies Content-Type when the handler did not set one.
// ModTime may be zero. Content is closed after the response when it implements io.Closer.
type FileResponse struct {
	Name    string
	ModTime time.Time
	Content io.ReadSeeker
}

// OpenFile opens path and returns a FileResponse served with http.ServeContent.
// A missing file is 404. The file is closed after the response is written.
func OpenFile(path string) (*FileResponse, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, NotFound("file not found")
		}
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &FileResponse{Name: info.Name(), ModTime: info.ModTime(), Content: f}, nil
}

// Event is one server-sent event.
// Retry is milliseconds. Zero omits the retry field.
type Event struct {
	ID    string
	Event string
	Data  string
	Retry int
}

// Events is a server-sent event stream. Return it from a handler.
type Events struct {
	produce func(context.Context, func(Event) error) error
}

// SSE streams events while the response is written.
// Each send writes one event and flushes when the client supports http.Flusher.
// produce nil panics.
func SSE(produce func(context.Context, func(Event) error) error) *Events {
	if produce == nil {
		panic("gfast: nil SSE producer")
	}
	return &Events{produce: produce}
}

func writeResult(w http.ResponseWriter, r *http.Request, resp *Response, regStatus int, out any, err error) {
	applyResponse(w, resp)
	if err != nil {
		writeErr(w, err)
		return
	}
	// out arrives as any. A typed nil pointer is not a nil interface.
	if isNilOut(out) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// A bad response is a server bug. Keep the fixed 500 detail, not 422.
	if verr := callValidate(reflect.ValueOf(out)); verr != nil {
		writeErr(w, errors.New("response"))
		return
	}
	switch body := out.(type) {
	case *Redirect:
		http.Redirect(w, r, body.URL, redirectCode(regStatus, resp, body.Code))
		return
	case *FileResponse:
		writeFile(w, r, resp, body)
		return
	case *Events:
		writeEvents(w, r, chosenStatus(regStatus, resp), mediaType(resp), body)
		return
	}
	status := chosenStatus(regStatus, resp)
	if ct := mediaType(resp); ct != "" {
		if raw, ok := rawBytes(out); ok {
			writeRaw(w, status, ct, raw)
			return
		}
	}
	if rd, ok := out.(io.Reader); ok {
		ct := mediaType(resp)
		if ct == "" {
			ct = "application/octet-stream"
		}
		writeStream(w, status, ct, rd)
		return
	}
	writeJSON(w, status, out)
}

func applyResponse(w http.ResponseWriter, resp *Response) {
	if resp == nil {
		return
	}
	dst := w.Header()
	for key, values := range resp.header {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	for _, cookie := range resp.cookies {
		if cookie != nil {
			http.SetCookie(w, cookie)
		}
	}
}

func chosenStatus(reg int, resp *Response) int {
	if resp != nil && resp.status != 0 {
		return resp.status
	}
	if reg != 0 {
		return reg
	}
	return http.StatusOK
}

func redirectCode(reg int, resp *Response, explicit int) int {
	if explicit != 0 {
		return explicit
	}
	code := chosenStatus(reg, resp)
	if code < 300 || code > 399 {
		return http.StatusTemporaryRedirect
	}
	return code
}

func mediaType(resp *Response) string {
	if resp == nil {
		return ""
	}
	if resp.contentType != "" {
		return resp.contentType
	}
	if resp.header != nil {
		return resp.header.Get("Content-Type")
	}
	return ""
}

func writeRaw(w http.ResponseWriter, status int, contentType string, body []byte) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func writeStream(w http.ResponseWriter, status int, contentType string, body io.Reader) {
	if c, ok := body.(io.Closer); ok {
		defer c.Close()
	}
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.WriteHeader(status)
	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if werr := writeChunk(w, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func writeChunk(w http.ResponseWriter, p []byte) error {
	if len(p) == 0 {
		return nil
	}
	if _, err := w.Write(p); err != nil {
		return err
	}
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	return nil
}

func writeFile(w http.ResponseWriter, r *http.Request, resp *Response, f *FileResponse) {
	if f == nil || f.Content == nil {
		writeErr(w, errors.New("empty file"))
		return
	}
	if c, ok := f.Content.(io.Closer); ok {
		defer c.Close()
	}
	if ct := mediaType(resp); ct != "" && w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", ct)
	}
	http.ServeContent(w, r, f.Name, f.ModTime, f.Content)
}

func writeEvents(w http.ResponseWriter, r *http.Request, status int, contentType string, ev *Events) {
	if ev == nil || ev.produce == nil {
		writeErr(w, errors.New("nil event stream"))
		return
	}
	if contentType == "" {
		contentType = "text/event-stream"
	}
	w.Header().Set("Content-Type", contentType)
	if w.Header().Get("Cache-Control") == "" {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.WriteHeader(status)
	_ = ev.produce(r.Context(), func(e Event) error {
		return writeChunk(w, formatEvent(e))
	})
}

func formatEvent(e Event) []byte {
	var b bytes.Buffer
	if id := oneLine(e.ID); id != "" {
		b.WriteString("id: ")
		b.WriteString(id)
		b.WriteByte('\n')
	}
	if name := oneLine(e.Event); name != "" {
		b.WriteString("event: ")
		b.WriteString(name)
		b.WriteByte('\n')
	}
	data := strings.ReplaceAll(e.Data, "\r\n", "\n")
	data = strings.ReplaceAll(data, "\r", "\n")
	if data == "" {
		b.WriteString("data: \n")
	} else {
		for _, line := range strings.Split(data, "\n") {
			b.WriteString("data: ")
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if e.Retry > 0 {
		b.WriteString("retry: ")
		b.WriteString(strconv.Itoa(e.Retry))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	return b.Bytes()
}

func isNilOut(out any) bool {
	if out == nil {
		return true
	}
	v := reflect.ValueOf(out)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

func rawBytes(out any) ([]byte, bool) {
	v := reflect.ValueOf(out)
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return nil, false
	}
	v = v.Elem()
	switch v.Kind() {
	case reflect.String:
		return []byte(v.String()), true
	case reflect.Slice:
		elem := v.Type().Elem()
		if elem.Kind() != reflect.Uint8 || elem.PkgPath() != "" {
			return nil, false
		}
		if v.IsNil() {
			return []byte{}, true
		}
		b := make([]byte, v.Len())
		reflect.Copy(reflect.ValueOf(b), v)
		return b, true
	default:
		return nil, false
	}
}

// headCapture records a HEAD response and discards the body.
type headCapture struct {
	header http.Header
	code   int
}

func (h *headCapture) Header() http.Header { return h.header }

func (h *headCapture) WriteHeader(code int) {
	if h.code == 0 {
		h.code = code
	}
}

func (h *headCapture) Write(p []byte) (int, error) {
	if h.code == 0 {
		h.code = http.StatusOK
	}
	return len(p), nil
}

func (h *headCapture) Flush() {}

func (h *headCapture) finish(w http.ResponseWriter) {
	dst := w.Header()
	for key, values := range h.header {
		dst.Del(key)
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	code := h.code
	if code == 0 {
		code = http.StatusOK
	}
	w.WriteHeader(code)
}
