package gfast_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"github.com/pyrex41/gfast"
)

var wsUser = gfast.Dep("WSUser", func(ctx context.Context, cred gfast.Bearer) (principal, error) {
	if cred.Token != "secret" {
		return principal{}, gfast.Unauthorized("invalid token")
	}
	return principal{ID: "u1"}, nil
})

func TestWebSocketEchoPathAndDep(t *testing.T) {
	app := gfast.New()
	type in struct {
		Room string    `path:"room" doc:"Room name"`
		User principal `gfast:"dep=WSUser"`
	}
	app.WebSocket("/rooms/{room}", func(ctx context.Context, in *in) error {
		conn := gfast.ConnFrom(ctx)
		if err := conn.WriteText(ctx, in.Room+" "+in.User.ID); err != nil {
			return err
		}
		for range 2 {
			typ, data, err := conn.Read(ctx)
			if err != nil {
				return err
			}
			if err := conn.Write(ctx, typ, data); err != nil {
				return err
			}
		}
		return nil
	}, gfast.Summary("Room socket"), gfast.Scopes("items:read"))

	spec := app.Request(http.MethodGet, "/openapi.json", nil)
	if spec.Status != http.StatusOK || !strings.Contains(string(spec.Body), `"101"`) || !strings.Contains(string(spec.Body), `"room"`) {
		t.Fatalf("spec %d %s", spec.Status, spec.Body)
	}
	if strings.Contains(string(spec.Body), `"WSUser"`) || !strings.Contains(string(spec.Body), "bearerAuth") {
		t.Fatalf("spec security %s", spec.Body)
	}

	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := gfast.Dial(ctx, wsURL(srv.URL, "/rooms/kitchen"), http.Header{"Authorization": []string{"Bearer secret"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(gfast.CloseNormalClosure, "")

	typ, data, err := conn.Read(ctx)
	if err != nil || typ != gfast.Text || string(data) != "kitchen u1" {
		t.Fatalf("intro typ %d data %q err %v", typ, data, err)
	}
	if err := conn.WriteText(ctx, "héllo"); err != nil {
		t.Fatal(err)
	}
	typ, data, err = conn.Read(ctx)
	if err != nil || typ != gfast.Text || string(data) != "héllo" {
		t.Fatalf("text typ %d data %q err %v", typ, data, err)
	}
	payload := []byte{0, 1, 2, 255}
	if err := conn.WriteBinary(ctx, payload); err != nil {
		t.Fatal(err)
	}
	typ, data, err = conn.Read(ctx)
	if err != nil || typ != gfast.Binary || !bytes.Equal(data, payload) {
		t.Fatalf("binary typ %d data %v err %v", typ, data, err)
	}
}

func TestWebSocketFailedUpgradeIsHTTP(t *testing.T) {
	app := gfast.New()
	type in struct {
		Q string `query:"q" required:"true"`
	}
	ran := false
	gfast.WebSocket(app, "/ws", func(ctx context.Context, in *in) error {
		ran = true
		_, _, err := gfast.ConnFrom(ctx).Read(ctx)
		return err
	}, gfast.Require(wsUser))
	group := app.Group("/v1")
	group.WebSocket("/chat", func(ctx context.Context, in *struct{}) error {
		return gfast.ConnFrom(ctx).WriteText(ctx, "group")
	})

	missing := app.Request(http.MethodGet, "/ws?q=1", nil)
	if missing.Status != http.StatusUnauthorized || !strings.Contains(string(missing.Body), "bearer") {
		t.Fatalf("auth %d %s", missing.Status, missing.Body)
	}
	if ct := missing.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("auth type %s", ct)
	}
	badQuery := app.Request(http.MethodGet, "/ws", nil, upgradeHeaders("dGhlIHNhbXBsZSBub25jZQ=="))
	if badQuery.Status != http.StatusUnprocessableEntity || ran {
		t.Fatalf("query %d ran %v body %s", badQuery.Status, ran, badQuery.Body)
	}
	plain := app.Request(http.MethodGet, "/ws?q=1", nil, http.Header{"Authorization": []string{"Bearer secret"}})
	if plain.Status != http.StatusBadRequest || !strings.Contains(string(plain.Body), "missing upgrade") {
		t.Fatalf("plain %d %s", plain.Status, plain.Body)
	}
	ext := upgradeHeaders("dGhlIHNhbXBsZSBub25jZQ==")
	ext.Set("Sec-WebSocket-Extensions", "permessage-deflate")
	ext.Set("Authorization", "Bearer secret")
	rejected := app.Request(http.MethodGet, "/ws?q=1", nil, ext)
	if rejected.Status != http.StatusBadRequest || !strings.Contains(string(rejected.Body), "extensions") || rejected.Status == http.StatusSwitchingProtocols {
		t.Fatalf("ext %d %s", rejected.Status, rejected.Body)
	}
	badVer := upgradeHeaders("dGhlIHNhbXBsZSBub25jZQ==")
	badVer.Set("Sec-WebSocket-Version", "12")
	badVer.Set("Authorization", "Bearer secret")
	if res := app.Request(http.MethodGet, "/ws?q=1", nil, badVer); res.Status != http.StatusBadRequest {
		t.Fatalf("version %d %s", res.Status, res.Body)
	}
	recorder := app.Request(http.MethodGet, "/ws?q=1", nil, func() http.Header {
		h := upgradeHeaders("dGhlIHNhbXBsZSBub25jZQ==")
		h.Set("Authorization", "Bearer secret")
		return h
	}())
	if recorder.Status == http.StatusSwitchingProtocols || recorder.Header.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("recorder %d %s body %s", recorder.Status, recorder.Header.Get("Content-Type"), recorder.Body)
	}
	if !json.Valid(recorder.Body) {
		t.Fatalf("recorder body %s", recorder.Body)
	}
	head := app.Request(http.MethodHead, "/ws?q=1", nil)
	if head.Status != http.StatusMethodNotAllowed || len(head.Body) != 0 {
		t.Fatalf("head %d %q", head.Status, head.Body)
	}

	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	res, err := http.Get(srv.URL + "/ws?q=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized || !strings.Contains(string(body), "bearer") {
		t.Fatalf("live auth %d %s", res.StatusCode, body)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := gfast.Dial(ctx, wsURL(srv.URL, "/v1/chat"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(gfast.CloseNormalClosure, "")
	typ, data, err := conn.Read(ctx)
	if err != nil || typ != gfast.Text || string(data) != "group" {
		t.Fatalf("group typ %d data %q err %v", typ, data, err)
	}
	if ran {
		t.Fatal("handler ran on a failed upgrade")
	}
}

func TestWebSocketFrames(t *testing.T) {
	app := gfast.New()
	app.WebSocket("/ws", func(ctx context.Context, in *struct{}) error {
		conn := gfast.ConnFrom(ctx)
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		return conn.Write(ctx, typ, data)
	}, gfast.MaxMessageSize(8))
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	t.Run("accept and ping", func(t *testing.T) {
		conn := dialRaw(t, srv.URL, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", nil)
		defer conn.Close()
		writeMasked(t, conn, false, 0x1, []byte("hel"), true)
		writeMasked(t, conn, true, 0x9, []byte("z"), true)
		writeMasked(t, conn, true, 0x0, []byte("lo"), true)
		fin, op, payload := readUnmasked(t, conn)
		if !fin || op != 0xA || string(payload) != "z" {
			t.Fatalf("pong fin %v op %d %q", fin, op, payload)
		}
		fin, op, payload = readUnmasked(t, conn)
		if !fin || op != 0x1 || string(payload) != "hello" {
			t.Fatalf("echo fin %v op %d %q", fin, op, payload)
		}
	})

	t.Run("close code", func(t *testing.T) {
		conn := dialRaw(t, srv.URL, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", nil)
		defer conn.Close()
		writeMasked(t, conn, true, 0x8, closePayload(1000, "bye"), true)
		_, op, payload := readUnmasked(t, conn)
		if op != 0x8 || len(payload) < 2 || binary.BigEndian.Uint16(payload[:2]) != 1000 {
			t.Fatalf("close op %d %q", op, payload)
		}
	})

	t.Run("too big", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := gfast.Dial(ctx, wsURL(srv.URL, "/ws"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(gfast.CloseNormalClosure, "")
		if err := conn.WriteBinary(ctx, bytes.Repeat([]byte{'x'}, 9)); err != nil {
			t.Fatal(err)
		}
		_, _, err = conn.Read(ctx)
		var closed *gfast.CloseError
		if !errors.As(err, &closed) || closed.Code != gfast.CloseMessageTooBig {
			t.Fatalf("err %v", err)
		}
	})

	t.Run("fragment over limit", func(t *testing.T) {
		conn := dialRaw(t, srv.URL, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", nil)
		defer conn.Close()
		writeMasked(t, conn, false, 0x2, bytes.Repeat([]byte{'a'}, 6), true)
		writeMasked(t, conn, true, 0x0, bytes.Repeat([]byte{'b'}, 6), true)
		_, op, payload := readUnmasked(t, conn)
		if op != 0x8 || binary.BigEndian.Uint16(payload[:2]) != gfast.CloseMessageTooBig {
			t.Fatalf("close op %d %v", op, payload)
		}
	})

	t.Run("bad utf-8", func(t *testing.T) {
		conn := dialRaw(t, srv.URL, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", nil)
		defer conn.Close()
		writeMasked(t, conn, true, 0x1, []byte{0xff}, true)
		_, op, payload := readUnmasked(t, conn)
		if op != 0x8 || binary.BigEndian.Uint16(payload[:2]) != gfast.CloseInvalidPayload {
			t.Fatalf("close op %d %v", op, payload)
		}
	})

	t.Run("unmasked", func(t *testing.T) {
		conn := dialRaw(t, srv.URL, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", nil)
		defer conn.Close()
		writeMasked(t, conn, true, 0x1, []byte("hi"), false)
		_, op, payload := readUnmasked(t, conn)
		if op != 0x8 || binary.BigEndian.Uint16(payload[:2]) != gfast.CloseProtocolError {
			t.Fatalf("close op %d %v", op, payload)
		}
	})

	t.Run("reserved bit", func(t *testing.T) {
		conn := dialRaw(t, srv.URL, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", nil)
		defer conn.Close()
		writeRaw(t, conn, 0x90, 0x81, []byte("a"), []byte{1, 2, 3, 4})
		_, op, payload := readUnmasked(t, conn)
		if op != 0x8 || binary.BigEndian.Uint16(payload[:2]) != gfast.CloseProtocolError {
			t.Fatalf("close op %d %v", op, payload)
		}
	})
}

func TestWebSocketClientRejectsBadServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		key := readRawRequestKey(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+acceptOf(key)+"\r\n\r\n")
		_, _ = conn.Write([]byte{0x81, 0x81, 9, 9, 9, 9, 'x' ^ 9})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := gfast.Dial(ctx, "ws://"+ln.Addr().String()+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(gfast.CloseNormalClosure, "")
	if _, _, err := conn.Read(ctx); err == nil {
		t.Fatal("masked server frame was accepted")
	}

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	go func() {
		conn, err := ln2.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		key := readRawRequestKey(br)
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+acceptOf(key)+"\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
	}()
	if _, err := gfast.Dial(ctx, "ws://"+ln2.Addr().String()+"/ws", nil); err == nil || !strings.Contains(err.Error(), "extensions") {
		t.Fatalf("extensions err %v", err)
	}
}

func TestWebSocketConnFromPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	gfast.ConnFrom(context.Background())
}

func TestPropWebSocketPayloads(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		text := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301").MaxSize(24))
		raw := hegel.Draw(ht, hegel.Binary(0, 24))
		limit := len(text)
		if len(raw) > limit {
			limit = len(raw)
		}
		if limit < 1 {
			limit = 1
		}
		app := gfast.New()
		app.WebSocket("/ws", func(ctx context.Context, in *struct{}) error {
			conn := gfast.ConnFrom(ctx)
			for range 2 {
				typ, data, err := conn.Read(ctx)
				if err != nil {
					return err
				}
				if err := conn.Write(ctx, typ, data); err != nil {
					return err
				}
			}
			_, _, err := conn.Read(ctx)
			return err
		}, gfast.MaxMessageSize(limit))
		srv := httptest.NewServer(app.Handler())
		defer srv.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := gfast.Dial(ctx, wsURL(srv.URL, "/ws"), nil)
		if err != nil {
			ht.Fatal(err)
		}
		defer conn.Close(gfast.CloseNormalClosure, "")
		if err := conn.WriteText(ctx, text); err != nil {
			ht.Fatal(err)
		}
		typ, data, err := conn.Read(ctx)
		if err != nil || typ != gfast.Text || string(data) != text {
			ht.Fatalf("text typ %d data %q want %q err %v", typ, data, text, err)
		}
		if err := conn.WriteBinary(ctx, raw); err != nil {
			ht.Fatal(err)
		}
		typ, data, err = conn.Read(ctx)
		if err != nil || typ != gfast.Binary || !bytes.Equal(data, raw) {
			ht.Fatalf("binary typ %d data %v want %v err %v", typ, data, raw, err)
		}
		if err := conn.WriteBinary(ctx, bytes.Repeat([]byte{'x'}, limit+1)); err != nil {
			ht.Fatal(err)
		}
		_, _, err = conn.Read(ctx)
		var closed *gfast.CloseError
		if !errors.As(err, &closed) || closed.Code != gfast.CloseMessageTooBig {
			ht.Fatalf("oversize err %v", err)
		}
	})
}

func wsURL(base, path string) string {
	return "ws" + strings.TrimPrefix(base, "http") + path
}

func upgradeHeaders(key string) http.Header {
	h := make(http.Header)
	h.Set("Connection", "keep-alive, Upgrade")
	h.Set("Upgrade", "websocket")
	h.Set("Sec-WebSocket-Key", key)
	h.Set("Sec-WebSocket-Version", "13")
	return h
}

func acceptOf(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

type testFail interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

func dialRaw(t testFail, base, path, key string, extra http.Header) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", hostPort(base))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	fmtHeader(&b, "GET "+path+" HTTP/1.1")
	fmtHeader(&b, "Host: "+hostPort(base))
	fmtHeader(&b, "Upgrade: websocket")
	fmtHeader(&b, "Connection: Upgrade")
	fmtHeader(&b, "Sec-WebSocket-Key: "+key)
	fmtHeader(&b, "Sec-WebSocket-Version: 13")
	for name, values := range extra {
		for _, value := range values {
			fmtHeader(&b, name+": "+value)
		}
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	status, hdr, err := readHTTPHead(br)
	if err != nil {
		conn.Close()
		t.Fatal(err)
	}
	if status != http.StatusSwitchingProtocols {
		conn.Close()
		t.Fatalf("status %d", status)
	}
	if hdr.Get("Sec-WebSocket-Accept") != acceptOf(key) {
		conn.Close()
		t.Fatalf("accept %q", hdr.Get("Sec-WebSocket-Accept"))
	}
	if hdr.Get("Sec-WebSocket-Extensions") != "" {
		conn.Close()
		t.Fatal("server accepted an extension")
	}
	return &prefixConn{Conn: conn, r: br}
}

func fmtHeader(b *strings.Builder, line string) {
	b.WriteString(line)
	b.WriteString("\r\n")
}

func hostPort(base string) string {
	return strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://")
}

func readHTTPHead(br *bufio.Reader) (int, http.Header, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, nil, err
	}
	var status int
	if _, err := parseStatus(line, &status); err != nil {
		return 0, nil, err
	}
	hdr := make(http.Header)
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			return 0, nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		name, value, _ := strings.Cut(line, ":")
		hdr.Add(name, strings.TrimSpace(value))
	}
	return status, hdr, nil
}

func parseStatus(line string, status *int) (int, error) {
	parts := strings.SplitN(strings.TrimRight(line, "\r\n"), " ", 3)
	if len(parts) < 2 {
		return 0, errors.New("status")
	}
	n := 0
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return 0, errors.New("status")
		}
		n = n*10 + int(c-'0')
	}
	*status = n
	return n, nil
}

type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func writeMasked(t testFail, conn net.Conn, fin bool, op byte, payload []byte, mask bool) {
	t.Helper()
	var key []byte
	b1 := byte(len(payload))
	if mask {
		key = []byte{1, 2, 3, 4}
		b1 |= 0x80
	}
	b0 := op
	if fin {
		b0 |= 0x80
	}
	writeRaw(t, conn, b0, b1, payload, key)
}

func writeRaw(t testFail, conn net.Conn, b0, b1 byte, payload, key []byte) {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteByte(b0)
	buf.WriteByte(b1)
	if len(key) > 0 {
		buf.Write(key)
		masked := make([]byte, len(payload))
		for i := range payload {
			masked[i] = payload[i] ^ key[i&3]
		}
		buf.Write(masked)
	} else {
		buf.Write(payload)
	}
	if _, err := conn.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func readUnmasked(t testFail, conn net.Conn) (bool, byte, []byte) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatal(err)
	}
	length := int(hdr[1] & 0x7f)
	if hdr[1]&0x80 != 0 {
		t.Fatal("server frame was masked")
	}
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(conn, ext[:]); err != nil {
			t.Fatal(err)
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		t.Fatal("unexpected 64-bit length")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatal(err)
	}
	return hdr[0]&0x80 != 0, hdr[0] & 0x0f, payload
}

func closePayload(code int, reason string) []byte {
	buf := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(buf[:2], uint16(code))
	copy(buf[2:], reason)
	return buf
}

func readRawRequestKey(br *bufio.Reader) string {
	var key string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return key
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return key
		}
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "Sec-WebSocket-Key") {
			key = strings.TrimSpace(value)
		}
	}
}
