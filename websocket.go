package gfast

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	wsGUID            = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	defaultMaxMessage = 1 << 20
	wsVersion         = "13"

	opCont   = 0x0
	opText   = 0x1
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA
)

// Close codes from RFC 6455. 1005, 1006, and 1015 are never sent on the wire.
const (
	CloseNormalClosure      = 1000
	CloseGoingAway          = 1001
	CloseProtocolError      = 1002
	CloseUnsupportedData    = 1003
	CloseNoStatus           = 1005
	CloseAbnormalClosure    = 1006
	CloseInvalidPayload     = 1007
	ClosePolicyViolation    = 1008
	CloseMessageTooBig      = 1009
	CloseMandatoryExtension = 1010
	CloseInternalError      = 1011
	CloseServiceRestart     = 1012
	CloseTryAgainLater      = 1013
	CloseBadGateway         = 1014
	CloseTLSHandshake       = 1015
)

// MessageType is a WebSocket data frame type.
type MessageType int

const (
	Text   MessageType = opText
	Binary MessageType = opBinary
)

// CloseError is a close frame from the peer.
type CloseError struct {
	Code   int
	Reason string
}

func (e *CloseError) Error() string {
	if e == nil {
		return "websocket closed"
	}
	if e.Reason == "" {
		return fmt.Sprintf("websocket closed: %d", e.Code)
	}
	return fmt.Sprintf("websocket closed: %d %s", e.Code, e.Reason)
}

// Conn is one WebSocket connection.
// The server stores it on the request context before the handler runs.
// Close sends a close frame and closes the TCP connection.
type Conn struct {
	nc   net.Conn
	br   *bufio.Reader
	bw   *bufio.Writer
	role wsRole
	max  int

	readMu  sync.Mutex
	writeMu sync.Mutex

	closeSent bool
	failed    bool

	closeOnce sync.Once
}

type wsRole int

const (
	roleServer wsRole = iota
	roleClient
)

type wsHijacked struct{ err error }

func (e *wsHijacked) Error() string { return e.err.Error() }
func (e *wsHijacked) Unwrap() error { return e.err }

var errFrameTooLarge = errors.New("websocket frame is too large to discard")

type wsCodeError struct {
	code int
	err  error
}

func (e *wsCodeError) Error() string { return e.err.Error() }
func (e *wsCodeError) Unwrap() error { return e.err }

// WebSocket registers a WebSocket route.
// The handler reads and writes with ConnFrom.
// Path parameters and dependencies run before the upgrade.
// A failed upgrade is an HTTP error and does not hijack the connection.
func (a *App) WebSocket[I any](path string, handler func(context.Context, *I) error, opts ...Option) {
	registerSocket(&a.state, path, handler, opts)
}

// WebSocket registers a WebSocket route on a group.
func (g *Group) WebSocket[I any](path string, handler func(context.Context, *I) error, opts ...Option) {
	registerSocket(&g.state, path, handler, opts)
}

// WebSocket registers a WebSocket route.
func WebSocket[I any](r Router, path string, handler func(context.Context, *I) error, opts ...Option) {
	registerSocket(r.isRouter(), path, handler, opts)
}

// ConnFrom returns the WebSocket connection for this request.
// It panics if ctx is not a WebSocket handler context.
func ConnFrom(ctx context.Context) *Conn {
	st, err := stateFrom(ctx)
	if err != nil || st.socket == nil {
		panic("gfast: ConnFrom is only valid in a WebSocket handler")
	}
	return st.socket
}

// Dial opens a WebSocket client connection.
// rawURL is ws:// or wss://. header is copied onto the handshake, except
// the headers this client sets itself. Extensions are not offered.
func Dial(ctx context.Context, rawURL string, header http.Header) (*Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	scheme := strings.ToLower(u.Scheme)
	addr := u.Host
	if addr == "" {
		return nil, errors.New("gfast: websocket url has no host")
	}
	if !hasPort(addr) {
		if scheme == "wss" {
			addr += ":443"
		} else {
			addr += ":80"
		}
	}
	var d net.Dialer
	var nc net.Conn
	switch scheme {
	case "ws":
		nc, err = d.DialContext(ctx, "tcp", addr)
	case "wss":
		nc, err = (&tls.Dialer{NetDialer: &d}).DialContext(ctx, "tcp", addr)
	default:
		return nil, fmt.Errorf("gfast: websocket url scheme %q", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	conn, err := clientHandshake(ctx, nc, u, header)
	if err != nil {
		_ = nc.Close()
		return nil, err
	}
	return conn, nil
}

func hasPort(host string) bool {
	if strings.HasPrefix(host, "[") {
		end := strings.LastIndex(host, "]")
		return end >= 0 && strings.Contains(host[end:], ":")
	}
	return strings.Contains(host, ":")
}

func clientHandshake(ctx context.Context, nc net.Conn, u *url.URL, header http.Header) (*Conn, error) {
	keyRaw := make([]byte, 16)
	if _, err := rand.Read(keyRaw); err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyRaw)
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	var buf strings.Builder
	fmt.Fprintf(&buf, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&buf, "Host: %s\r\n", u.Host)
	buf.WriteString("Upgrade: websocket\r\n")
	buf.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&buf, "Sec-WebSocket-Key: %s\r\n", key)
	buf.WriteString("Sec-WebSocket-Version: 13\r\n")
	for name, values := range header {
		if skipClientHeader(name) {
			continue
		}
		for _, value := range values {
			fmt.Fprintf(&buf, "%s: %s\r\n", name, value)
		}
	}
	buf.WriteString("\r\n")

	if err := nc.SetDeadline(timeFrom(ctx)); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(nc, buf.String()); err != nil {
		return nil, err
	}
	br := bufio.NewReader(nc)
	status, hdr, err := readHandshake(br)
	_ = nc.SetDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	if status != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("gfast: websocket handshake status %d", status)
	}
	if !headerHasToken(hdr, "Upgrade", "websocket") || !headerHasToken(hdr, "Connection", "Upgrade") {
		return nil, errors.New("gfast: websocket handshake missing upgrade")
	}
	if hdr.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		return nil, errors.New("gfast: websocket accept mismatch")
	}
	if headerHasValue(hdr, "Sec-WebSocket-Extensions") {
		return nil, errors.New("gfast: websocket extensions are not supported")
	}
	return &Conn{
		nc:   nc,
		br:   br,
		bw:   bufio.NewWriter(nc),
		role: roleClient,
		max:  defaultMaxMessage,
	}, nil
}

func timeFrom(ctx context.Context) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Time{}
}

func skipClientHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Host", "Upgrade", "Connection", "Sec-Websocket-Key", "Sec-Websocket-Version", "Sec-Websocket-Extensions":
		return true
	default:
		return false
	}
}

func registerSocket[I any](st *routerState, path string, handler func(context.Context, *I) error, opts []Option) {
	if handler == nil {
		panic("gfast: nil handler")
	}
	route := st.route.clone()
	bag := &optionBag{route: &route}
	for _, opt := range opts {
		opt(bag)
	}
	inType := reflect.TypeOf((*I)(nil)).Elem()
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
	scopes := append([]string(nil), route.scopes...)
	full := joinPath(st.prefix, path)
	plan := planInput(inType)
	max := route.wsMax
	if max == 0 {
		max = defaultMaxMessage
	}
	st.app.addWebSocket(full, route, inType, schemes)

	h := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeErr(w, statusErr(http.StatusMethodNotAllowed, "websocket handshake must be GET"))
			return
		}
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
		conn, err := acceptWebSocket(w, r, max)
		if err != nil {
			var hijacked *wsHijacked
			if errors.As(err, &hijacked) {
				return
			}
			writeErr(w, err)
			return
		}
		rst.socket = conn
		var herr error
		defer func() { conn.end(herr) }()
		herr = handler(ctx, in)
	}
	st.app.mux.HandleFunc(http.MethodGet+" "+full, h)
}

func (a *App) addWebSocket(path string, route routeConfig, in reflect.Type, schemes map[string]*namedScheme) {
	if !route.inSchema() {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	desc := route.description
	if desc == "" {
		desc = "WebSocket"
	}
	operation := newOperation(route, http.MethodGet, path)
	operation.Description = desc
	operation.Responses = map[string]opResp{
		"101": {Description: "Switching Protocols"},
	}
	a.addExtraResponses(operation.Responses, route.responses)
	plan := planInput(in)
	for _, p := range plan.params {
		if p.loc == "form" || p.loc == "file" {
			continue
		}
		operation.Parameters = append(operation.Parameters, opParam{
			Name:        p.name,
			In:          p.loc,
			Description: p.tag.Get("doc"),
			Required:    p.loc == "path" || p.tag.Get("required") == "true",
			Schema:      a.paramSchema(p),
		})
	}
	a.putOperation(path, http.MethodGet, operation, schemes, route.scopes)
}

func acceptWebSocket(w http.ResponseWriter, r *http.Request, max int) (*Conn, error) {
	if r.ProtoMajor < 1 || (r.ProtoMajor == 1 && r.ProtoMinor < 1) {
		return nil, BadRequest("websocket requires HTTP/1.1")
	}
	if r.Host == "" {
		return nil, BadRequest("websocket handshake missing host")
	}
	if !headerHasToken(r.Header, "Upgrade", "websocket") || !headerHasToken(r.Header, "Connection", "Upgrade") {
		return nil, BadRequest("websocket handshake missing upgrade")
	}
	versions := r.Header.Values("Sec-WebSocket-Version")
	if len(versions) != 1 || strings.TrimSpace(versions[0]) != wsVersion {
		return nil, BadRequest("unsupported Sec-WebSocket-Version")
	}
	if headerHasValue(r.Header, "Sec-WebSocket-Extensions") {
		return nil, BadRequest("websocket extensions are not supported")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 16 {
		return nil, BadRequest("invalid Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("gfast: websocket upgrade requires http.Hijacker")
	}
	nc, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + wsAccept(key) + "\r\n\r\n"); err != nil {
		_ = nc.Close()
		return nil, &wsHijacked{err: err}
	}
	if err := rw.Flush(); err != nil {
		_ = nc.Close()
		return nil, &wsHijacked{err: err}
	}
	return &Conn{nc: nc, br: rw.Reader, bw: rw.Writer, role: roleServer, max: max}, nil
}

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func headerHasToken(h http.Header, name, want string) bool {
	for _, value := range h.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), want) {
				return true
			}
		}
	}
	return false
}

func headerHasValue(h http.Header, name string) bool {
	for _, value := range h.Values(name) {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func readHandshake(br *bufio.Reader) (int, http.Header, error) {
	line, err := readLimitedLine(br)
	if err != nil {
		return 0, nil, err
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, nil, errors.New("gfast: malformed websocket handshake")
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, nil, errors.New("gfast: malformed websocket handshake")
	}
	hdr := make(http.Header)
	for {
		line, err = readLimitedLine(br)
		if err != nil {
			return 0, nil, err
		}
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return 0, nil, errors.New("gfast: malformed websocket handshake")
		}
		hdr.Add(name, strings.TrimSpace(value))
	}
	return status, hdr, nil
}

func readLimitedLine(br *bufio.Reader) (string, error) {
	var buf []byte
	for {
		part, err := br.ReadSlice('\n')
		buf = append(buf, part...)
		if len(buf) > 8192 {
			return "", errors.New("gfast: websocket handshake header too large")
		}
		if err == nil {
			return strings.TrimRight(string(buf), "\r\n"), nil
		}
		if err != bufio.ErrBufferFull {
			if err == io.EOF && len(buf) == 0 {
				return "", io.ErrUnexpectedEOF
			}
			return "", err
		}
	}
}

// Read returns the next data message.
// Ping frames are answered with pong. Pong frames are ignored.
// A close from the peer returns *CloseError.
func (c *Conn) Read(ctx context.Context) (MessageType, []byte, error) {
	if c == nil {
		return 0, nil, errors.New("gfast: nil websocket")
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.failed {
		return 0, nil, errors.New("gfast: websocket is closed")
	}
	var (
		msg     []byte
		kind    byte
		started bool
	)
	for {
		fin, op, payload, err := c.readFrame(ctx)
		if err != nil {
			return 0, nil, c.failRead(err)
		}
		switch op {
		case opPing:
			if err := c.writeFrame(ctx, opPong, payload); err != nil {
				return 0, nil, c.failRead(err)
			}
		case opPong:
		case opClose:
			ce, perr := parseClose(payload)
			if perr != nil {
				return 0, nil, c.failRead(perr)
			}
			if !c.sentClose() {
				reply := ce.Code
				if reply == CloseNoStatus || !sendableCloseCode(reply) {
					reply = CloseNormalClosure
				}
				_ = c.writeClose(ctx, reply, "")
			}
			c.failed = true
			return 0, nil, ce
		case opText, opBinary:
			if started {
				return 0, nil, c.failRead(codeErr(CloseProtocolError, "unexpected data frame"))
			}
			started = true
			kind = op
			msg = payload
			if fin {
				if err := c.finishData(kind, msg); err != nil {
					return 0, nil, err
				}
				return MessageType(kind), msg, nil
			}
		case opCont:
			if !started {
				return 0, nil, c.failRead(codeErr(CloseProtocolError, "continuation without a message"))
			}
			if len(msg) > c.max-len(payload) {
				return 0, nil, c.failRead(codeErr(CloseMessageTooBig, "message too big"))
			}
			msg = append(msg, payload...)
			if fin {
				if err := c.finishData(kind, msg); err != nil {
					return 0, nil, err
				}
				return MessageType(kind), msg, nil
			}
		default:
			return 0, nil, c.failRead(codeErr(CloseProtocolError, "unknown opcode"))
		}
	}
}

func (c *Conn) finishData(kind byte, msg []byte) error {
	if kind == opText && !utf8.Valid(msg) {
		return c.failRead(codeErr(CloseInvalidPayload, "text is not utf-8"))
	}
	return nil
}

func (c *Conn) failRead(err error) error {
	c.failed = true
	var coded *wsCodeError
	if errors.As(err, &coded) && !c.sentClose() {
		_ = c.writeClose(context.Background(), coded.code, "")
	}
	return err
}

// Write sends one data message as a single frame.
func (c *Conn) Write(ctx context.Context, typ MessageType, p []byte) error {
	if c == nil {
		return errors.New("gfast: nil websocket")
	}
	switch typ {
	case Text:
		if !utf8.Valid(p) {
			return errors.New("gfast: text is not utf-8")
		}
	case Binary:
	default:
		return errors.New("gfast: unknown websocket message type")
	}
	if len(p) > c.max {
		return codeErr(CloseMessageTooBig, "message too big")
	}
	return c.writeFrame(ctx, byte(typ), p)
}

// WriteText sends a text message.
func (c *Conn) WriteText(ctx context.Context, p string) error {
	return c.Write(ctx, Text, []byte(p))
}

// WriteBinary sends a binary message.
func (c *Conn) WriteBinary(ctx context.Context, p []byte) error {
	return c.Write(ctx, Binary, p)
}

// Ping sends a ping. Payload is at most 125 bytes.
// The peer's pong is consumed by Read.
func (c *Conn) Ping(ctx context.Context, payload []byte) error {
	if len(payload) > 125 {
		return errors.New("gfast: ping payload longer than 125")
	}
	return c.writeFrame(ctx, opPing, payload)
}

// Close sends a close frame and closes the TCP connection.
func (c *Conn) Close(code int, reason string) error {
	if c == nil {
		return errors.New("gfast: nil websocket")
	}
	if !sendableCloseCode(code) {
		return fmt.Errorf("gfast: invalid close code %d", code)
	}
	if !utf8.ValidString(reason) || len(reason) > 123 {
		return errors.New("gfast: invalid close reason")
	}
	err := c.writeClose(context.Background(), code, reason)
	c.closeNet()
	return err
}

func (c *Conn) end(err error) {
	if !c.sentClose() {
		code := CloseNormalClosure
		if err != nil {
			var closed *CloseError
			var coded *wsCodeError
			switch {
			case errors.As(err, &closed):
				code = 0
			case errors.As(err, &coded):
				code = coded.code
			default:
				code = CloseInternalError
			}
		}
		if code != 0 {
			_ = c.writeClose(context.Background(), code, "")
		}
	}
	c.closeNet()
}

func (c *Conn) closeNet() {
	c.closeOnce.Do(func() { _ = c.nc.Close() })
}

func (c *Conn) sentClose() bool {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.closeSent
}

func (c *Conn) writeClose(ctx context.Context, code int, reason string) error {
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload[:2], uint16(code))
	copy(payload[2:], reason)
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closeSent {
		return nil
	}
	c.closeSent = true
	return c.writeFrameLocked(ctx, opClose, payload)
}

func (c *Conn) writeFrame(ctx context.Context, op byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closeSent && op != opClose {
		return errors.New("gfast: websocket is closed")
	}
	return c.writeFrameLocked(ctx, op, payload)
}

func (c *Conn) writeFrameLocked(ctx context.Context, op byte, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	mask := c.role == roleClient
	var key [4]byte
	body := payload
	if mask {
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		body = make([]byte, len(payload))
		for i := range payload {
			body[i] = payload[i] ^ key[i&3]
		}
	}
	hdr := []byte{0x80 | op, 0}
	if mask {
		hdr[1] |= 0x80
	}
	n := len(payload)
	switch {
	case n <= 125:
		hdr[1] |= byte(n)
	case n <= 65535:
		hdr[1] |= 126
		hdr = append(hdr, byte(n>>8), byte(n))
	default:
		hdr[1] |= 127
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		hdr = append(hdr, ext[:]...)
	}
	if mask {
		hdr = append(hdr, key[:]...)
	}
	stop := c.armDeadline(ctx, false)
	_, err := c.bw.Write(hdr)
	if err == nil && len(body) > 0 {
		_, err = c.bw.Write(body)
	}
	if err == nil {
		err = c.bw.Flush()
	}
	stop()
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (c *Conn) readFrame(ctx context.Context) (fin bool, op byte, payload []byte, err error) {
	if err = ctx.Err(); err != nil {
		return false, 0, nil, err
	}
	stop := c.armDeadline(ctx, true)
	defer func() {
		stop()
		if err != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	var hdr [2]byte
	if _, err = io.ReadFull(c.br, hdr[:]); err != nil {
		return false, 0, nil, err
	}
	fin = hdr[0]&0x80 != 0
	op = hdr[0] & 0x0f
	masked := hdr[1]&0x80 != 0
	length := uint64(hdr[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
		if length < 126 {
			_ = discardFrame(c.br, masked, length)
			return false, 0, nil, codeErr(CloseProtocolError, "non-minimal length")
		}
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(c.br, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
		if length&(1<<63) != 0 || length <= 65535 {
			if length&(1<<63) == 0 {
				_ = discardFrame(c.br, masked, length)
			}
			return false, 0, nil, codeErr(CloseProtocolError, "non-minimal length")
		}
	}
	reject := func(msg string) (bool, byte, []byte, error) {
		_ = discardFrame(c.br, masked, length)
		return false, 0, nil, codeErr(CloseProtocolError, msg)
	}
	if hdr[0]&0x70 != 0 {
		return reject("reserved bits are set")
	}
	switch op {
	case opCont, opText, opBinary, opClose, opPing, opPong:
	default:
		return reject("unknown opcode")
	}
	control := op&0x8 != 0
	if control && (!fin || length > 125) {
		return reject("bad control frame")
	}
	if c.role == roleServer && !masked {
		return reject("client frame is not masked")
	}
	if c.role == roleClient && masked {
		return reject("server frame is masked")
	}
	if !control && length > uint64(c.max) {
		_ = discardFrame(c.br, masked, length)
		return false, 0, nil, codeErr(CloseMessageTooBig, "message too big")
	}
	var key [4]byte
	if masked {
		if _, err = io.ReadFull(c.br, key[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(c.br, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i&3]
		}
	}
	return fin, op, payload, nil
}

// discardFrame drops a frame body so a later close is not turned into a TCP reset.
// A declared length past 4 MiB is left unread; the connection is closed instead.
func discardFrame(r io.Reader, masked bool, length uint64) error {
	n := length
	if masked {
		n += 4
	}
	if n > 4<<20 {
		return errFrameTooLarge
	}
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}

func (c *Conn) armDeadline(ctx context.Context, read bool) func() {
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			if read {
				_ = c.nc.SetReadDeadline(time.Unix(0, 1))
			} else {
				_ = c.nc.SetWriteDeadline(time.Unix(0, 1))
			}
		case <-stop:
		}
	}()
	return func() {
		close(stop)
		wg.Wait()
		if read {
			_ = c.nc.SetReadDeadline(time.Time{})
		} else {
			_ = c.nc.SetWriteDeadline(time.Time{})
		}
	}
}

func parseClose(p []byte) (*CloseError, error) {
	if len(p) == 0 {
		return &CloseError{Code: CloseNoStatus}, nil
	}
	if len(p) == 1 {
		return nil, codeErr(CloseProtocolError, "truncated close")
	}
	code := int(binary.BigEndian.Uint16(p[:2]))
	reason := string(p[2:])
	if !utf8.ValidString(reason) {
		return nil, codeErr(CloseInvalidPayload, "close reason is not utf-8")
	}
	if !receivedCloseCode(code) {
		return nil, codeErr(CloseProtocolError, "invalid close code")
	}
	return &CloseError{Code: code, Reason: reason}, nil
}

func codeErr(code int, msg string) error {
	return &wsCodeError{code: code, err: errors.New(msg)}
}

func sendableCloseCode(code int) bool {
	switch code {
	case CloseNoStatus, CloseAbnormalClosure, CloseTLSHandshake, CloseMandatoryExtension:
		return false
	}
	if code >= 1000 && code <= 1014 {
		return code != 1004
	}
	return code >= 3000 && code <= 4999
}

func receivedCloseCode(code int) bool {
	if code == 1004 || code == CloseNoStatus || code == CloseAbnormalClosure || code == CloseTLSHandshake {
		return false
	}
	if code >= 1000 && code <= 1014 {
		return true
	}
	return code >= 3000 && code <= 4999
}
