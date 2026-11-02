package gfast_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"github.com/pyrex41/gfast"
)

func TestPropHTTPSRedirect(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		label := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		q := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301XYZ019").MaxSize(8))
		useTLS := hegel.Draw(ht, hegel.Booleans())
		withPort := hegel.Draw(ht, hegel.Booleans())

		host := label + ".good.test"
		wantHost := host
		if withPort {
			wantHost = host + ":8443"
		}
		path := "/ping?q=" + url.QueryEscape(q)
		var hits int
		app := gfast.New(gfast.TrustedHost("*.good.test"), gfast.HTTPSRedirect())
		app.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
			hits++
			return &struct{ OK bool }{OK: true}, nil
		})

		foreign := httptest.NewRequest(http.MethodGet, path, nil)
		foreign.Host = "evil.example"
		foreignRec := httptest.NewRecorder()
		app.Handler().ServeHTTP(foreignRec, foreign)
		if foreignRec.Code != http.StatusBadRequest || hits != 0 || !strings.Contains(foreignRec.Body.String(), "Invalid host header") {
			ht.Fatalf("foreign %d hits %d body %s", foreignRec.Code, hits, foreignRec.Body.String())
		}

		plain := httptest.NewRequest(http.MethodGet, path, nil)
		plain.Host = wantHost
		plainRec := httptest.NewRecorder()
		app.Handler().ServeHTTP(plainRec, plain)
		loc, err := url.Parse(plainRec.Header().Get("Location"))
		if err != nil {
			ht.Fatal(err)
		}
		if plainRec.Code != http.StatusTemporaryRedirect || hits != 0 || loc.Scheme != "https" || loc.Host != wantHost || loc.Path != "/ping" || loc.Query().Get("q") != q {
			ht.Fatalf("redirect %d loc %q hits %d", plainRec.Code, plainRec.Header().Get("Location"), hits)
		}

		var secure *http.Request
		if useTLS {
			secure = httptest.NewRequest(http.MethodGet, path, nil)
			secure.Host = wantHost
			secure.TLS = &tls.ConnectionState{}
		} else {
			secure = httptest.NewRequest(http.MethodGet, "https://"+wantHost+path, nil)
		}
		secureRec := httptest.NewRecorder()
		app.Handler().ServeHTTP(secureRec, secure)
		if secureRec.Code != http.StatusOK || hits != 1 || secureRec.Header().Get("Location") != "" {
			ht.Fatalf("https %d loc %q hits %d body %s", secureRec.Code, secureRec.Header().Get("Location"), hits, secureRec.Body.String())
		}
	})
}

func TestPropDocumentOptions(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		tag := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		tagDesc := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301 ").MinSize(1).MaxSize(12))
		hookName := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		cbName := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		opID := "op" + hegel.Draw(ht, hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(6))
		hooked := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301 ").MinSize(1).MaxSize(12))
		if tag == "used" {
			tag += "x"
		}

		bare := gfast.New(gfast.Title("Stay"), gfast.OpenAPIHook(nil))
		bare.Get("/ping", func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
			return &struct{ OK bool }{OK: true}, nil
		})
		bareDoc := hpDoc(ht, bare)
		bareInfo := hpObj(ht, bareDoc["info"])
		if bareInfo["title"] != "Stay" || bareInfo["description"] != nil {
			ht.Fatalf("nil hook info %#v", bareInfo)
		}

		var saw bool
		app := gfast.New(
			gfast.Title("Items"),
			gfast.OpenAPIHook(nil),
			gfast.TagDescription(tag, tagDesc),
			gfast.Webhooks(map[string]any{
				hookName: map[string]any{"post": map[string]any{"operationId": "hook-" + hookName}},
			}),
			gfast.OpenAPIHook(func(doc map[string]any) {
				paths, _ := doc["paths"].(map[string]any)
				if paths != nil {
					_, saw = paths["/left"]
				}
				info, _ := doc["info"].(map[string]any)
				if info != nil {
					info["title"] = hooked
				}
			}),
		)
		ok := func(ctx context.Context, in *struct{}) (*struct{ OK bool }, error) {
			return &struct{ OK bool }{OK: true}, nil
		}
		app.Get("/left", ok, gfast.OperationID(opID), gfast.Tags("used"), gfast.Callbacks(map[string]any{
			cbName: map[string]any{"post": map[string]any{"operationId": "cb-" + cbName}},
		}))
		app.Get("/right", ok, gfast.OperationID(opID))
		app.Get("/plain", ok)

		if res := app.Request(http.MethodPost, "/hooks/"+hookName, []byte(`{}`)); res.Status != http.StatusNotFound {
			ht.Fatalf("webhook invoked %d %s", res.Status, res.Body)
		}
		if res := app.Request(http.MethodGet, "/callbacks/"+cbName, nil); res.Status != http.StatusNotFound {
			ht.Fatalf("callback invoked %d %s", res.Status, res.Body)
		}

		doc := hpDoc(ht, app)
		if !saw {
			ht.Fatal("hook ran before paths were registered")
		}
		info := hpObj(ht, doc["info"])
		if info["title"] != hooked {
			ht.Fatalf("hook title %#v", info)
		}
		foundTag := false
		for _, item := range doc["tags"].([]any) {
			one := hpObj(ht, item)
			if one["name"] == tag && one["description"] == tagDesc {
				foundTag = true
			}
		}
		if !foundTag {
			ht.Fatalf("tags %#v want %s %q", doc["tags"], tag, tagDesc)
		}
		wh := hpObj(ht, hpObj(ht, hpObj(ht, doc["webhooks"])[hookName])["post"])
		if wh["operationId"] != "hook-"+hookName {
			ht.Fatalf("webhook %#v", doc["webhooks"])
		}
		left := hpOp(ht, doc, "/left", "get")
		right := hpOp(ht, doc, "/right", "get")
		plain := hpOp(ht, doc, "/plain", "get")
		if left["operationId"] != opID || right["operationId"] != opID {
			ht.Fatalf("operation ids %v %v want %s", left["operationId"], right["operationId"], opID)
		}
		if plain["operationId"] != "get-plain" {
			ht.Fatalf("generated id %#v", plain["operationId"])
		}
		if _, ok := hpObj(ht, left["callbacks"])[cbName]; !ok {
			ht.Fatalf("callbacks %#v", left["callbacks"])
		}
	})
}

func TestPropStateFrom(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		boot := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301XYZ019").MaxSize(12))
		next := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301XYZ019").MaxSize(12))
		app := gfast.New(gfast.OnStart(func(ctx context.Context) error {
			gfast.StateFrom(ctx)["boot"] = boot
			return nil
		}))
		app.Post("/state", func(ctx context.Context, in *struct{}) (*struct {
			Boot string `json:"boot"`
			Prev string `json:"prev"`
		}, error) {
			st := gfast.StateFrom(ctx)
			prev, _ := st["n"].(string)
			st["n"] = next
			got, _ := st["boot"].(string)
			return &struct {
				Boot string `json:"boot"`
				Prev string `json:"prev"`
			}{Boot: got, Prev: prev}, nil
		})
		client := app.Client()
		defer client.Close()
		if err := client.Start(); err != nil {
			ht.Fatal(err)
		}
		if app.State()["boot"] != boot {
			ht.Fatalf("state after start %#v", app.State())
		}
		first := hpState(ht, client.Request(http.MethodPost, "/state", nil))
		if first.Boot != boot || first.Prev != "" {
			ht.Fatalf("first %+v boot %q", first, boot)
		}
		second := hpState(ht, client.Request(http.MethodPost, "/state", nil))
		if second.Boot != boot || second.Prev != next || app.State()["n"] != next {
			ht.Fatalf("second %+v state %#v", second, app.State())
		}
	})
}

func TestPropWebSocketFrames(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		// 0 ping between fragments, 1 ignore pong, 2 continuation without a
		// start, 3 data frame mid-message, 4 bad UTF-8, 5 split that stays
		// invalid, 6 split that becomes valid, 7 unmasked, 8 reserved bit,
		// 9 handler close, 10 rejected close and overlong ping, 11 peer close.
		mode := hegel.Draw(ht, hegel.Integers(0, 11))
		ping := hegel.Draw(ht, hegel.Binary(0, 125))
		partA := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301").MaxSize(8))
		partB := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301").MaxSize(8))
		cut := 1 + hegel.Draw(ht, hegel.Integers(0, 2))
		badIdx := hegel.Draw(ht, hegel.Integers(0, 3))
		rsv := hegel.Draw(ht, hegel.Integers(0, 2))
		sendIdx := hegel.Draw(ht, hegel.Integers(0, len(hpSendableClose)-1))
		reason := hegel.Draw(ht, hegel.Text().Alphabet("ab👍").MaxSize(8))
		rejectIdx := hegel.Draw(ht, hegel.Integers(0, 2))
		peerKind := hegel.Draw(ht, hegel.Integers(0, 2))

		sendCode := hpSendableClose[sendIdx]
		rejectCode := []int{gfast.CloseNoStatus, gfast.CloseAbnormalClosure, gfast.CloseTLSHandshake}[rejectIdx]
		thumb := []byte("👍")
		app := gfast.New()
		app.WebSocket("/ws", func(ctx context.Context, in *struct{}) error {
			conn := gfast.ConnFrom(ctx)
			switch mode {
			case 9:
				return conn.Close(sendCode, reason)
			case 10:
				if err := conn.Close(rejectCode, ""); err == nil {
					return fmt.Errorf("close %d accepted", rejectCode)
				}
				if err := conn.Ping(ctx, bytes.Repeat([]byte{'p'}, 126)); err == nil || !strings.Contains(err.Error(), "125") {
					return fmt.Errorf("ping 126: %v", err)
				}
				return conn.WriteText(ctx, "open")
			default:
				typ, data, err := conn.Read(ctx)
				if err != nil {
					return err
				}
				return conn.Write(ctx, typ, data)
			}
		})
		srv := httptest.NewServer(app.Handler())
		defer srv.Close()
		conn := dialRaw(ht, srv.URL, "/ws", "dGhlIHNhbXBsZSBub25jZQ==", nil)
		defer conn.Close()

		switch mode {
		case 0:
			writeMasked(ht, conn, false, 0x1, []byte(partA), true)
			writeMasked(ht, conn, true, 0x9, ping, true)
			writeMasked(ht, conn, true, 0x0, []byte(partB), true)
			fin, op, payload := readUnmasked(ht, conn)
			if !fin || op != 0xA || !bytes.Equal(payload, ping) {
				ht.Fatalf("pong fin %v op %d %q", fin, op, payload)
			}
			fin, op, payload = readUnmasked(ht, conn)
			if !fin || op != 0x1 || string(payload) != partA+partB {
				ht.Fatalf("joined fin %v op %d %q", fin, op, payload)
			}
		case 1:
			writeMasked(ht, conn, true, 0xA, ping, true)
			writeMasked(ht, conn, true, 0x1, []byte(partA), true)
			fin, op, payload := readUnmasked(ht, conn)
			if !fin || op != 0x1 || string(payload) != partA {
				ht.Fatalf("after pong fin %v op %d %q", fin, op, payload)
			}
		case 2:
			writeMasked(ht, conn, true, 0x0, []byte(partA), true)
			hpExpectClose(ht, conn, gfast.CloseProtocolError)
		case 3:
			writeMasked(ht, conn, false, 0x1, []byte("ab"), true)
			writeMasked(ht, conn, true, 0x1, []byte("cd"), true)
			hpExpectClose(ht, conn, gfast.CloseProtocolError)
		case 4:
			bad := [][]byte{{0xff}, {0x80}, {0xc0}, {0xc1}}[badIdx]
			writeMasked(ht, conn, true, 0x1, bad, true)
			hpExpectClose(ht, conn, gfast.CloseInvalidPayload)
		case 5:
			writeMasked(ht, conn, false, 0x1, []byte{0xc3}, true)
			writeMasked(ht, conn, true, 0x0, []byte{0x20}, true)
			hpExpectClose(ht, conn, gfast.CloseInvalidPayload)
		case 6:
			writeMasked(ht, conn, false, 0x1, thumb[:cut], true)
			writeMasked(ht, conn, true, 0x0, thumb[cut:], true)
			fin, op, payload := readUnmasked(ht, conn)
			if !fin || op != 0x1 || string(payload) != "👍" {
				ht.Fatalf("rejoined fin %v op %d %q", fin, op, payload)
			}
		case 7:
			writeMasked(ht, conn, true, 0x1, []byte("hi"), false)
			hpExpectClose(ht, conn, gfast.CloseProtocolError)
		case 8:
			payload := []byte("a")
			key := []byte{1, 2, 3, 4}
			b0 := byte(0x81 | (0x40 >> rsv))
			writeRaw(ht, conn, b0, 0x80|byte(len(payload)), payload, key)
			hpExpectClose(ht, conn, gfast.CloseProtocolError)
		case 9:
			fin, op, payload := readUnmasked(ht, conn)
			if !fin || op != 0x8 || len(payload) < 2 {
				ht.Fatalf("handler close fin %v op %d %q", fin, op, payload)
			}
			code := int(int(payload[0])<<8 | int(payload[1]))
			if code != sendCode || string(payload[2:]) != reason {
				ht.Fatalf("handler close %d %q want %d %q", code, payload[2:], sendCode, reason)
			}
		case 10:
			fin, op, payload := readUnmasked(ht, conn)
			if !fin || op != 0x1 || string(payload) != "open" {
				ht.Fatalf("rejected close fin %v op %d %q", fin, op, payload)
			}
		case 11:
			switch peerKind {
			case 0:
				writeMasked(ht, conn, true, 0x8, closePayload(sendCode, "bye"), true)
				hpExpectClose(ht, conn, sendCode)
			case 1:
				writeMasked(ht, conn, true, 0x8, closePayload(gfast.CloseMandatoryExtension, ""), true)
				hpExpectClose(ht, conn, gfast.CloseNormalClosure)
			default:
				writeMasked(ht, conn, true, 0x8, nil, true)
				hpExpectClose(ht, conn, gfast.CloseNormalClosure)
			}
		}
	})
}

func TestPropOAuthBrowser(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		clientID := hegel.Draw(ht, hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(8))
		subject := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(8))
		password := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		state := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ012").MinSize(1).MaxSize(8))
		verifier := hegel.Draw(ht, hegel.Text().Alphabet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~").MinSize(43).MaxSize(48))
		badType := hegel.Draw(ht, hegel.SampledFrom([]string{"token", "code token", ""}))
		scope := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		const redirect = "https://app.example/cb"
		const other = "https://app.example/other"
		wrong := password + "x"

		app := gfast.New(gfast.OAuthServer(gfast.OAuthConfig{
			Clients: []gfast.OAuthClient{{
				ID:           clientID,
				RedirectURIs: []string{redirect, other},
				Scopes:       []string{scope},
			}},
			Scopes: map[string]string{scope: scope},
			Password: func(ctx context.Context, username, pass string) (string, error) {
				if username == "ada" && pass == password {
					return subject, nil
				}
				return "", nil
			},
			Session: func(ctx context.Context, r *http.Request) (string, error) {
				if r.Header.Get("X-User") == "in" {
					return subject, nil
				}
				return "", nil
			},
		}))
		path := hpAuthorizePath(clientID, redirect, state, challenge, "code", scope)
		form := app.Request(http.MethodGet, path, nil)
		hpLoginPage(ht, form, http.StatusOK, "")

		denied := hpLoginPost(app, path, "ada", wrong)
		hpLoginPage(ht, denied, http.StatusUnauthorized, "The username or password is not valid.")

		signed := app.Request(http.MethodGet, path, nil, http.Header{"X-User": []string{"in"}})
		if signed.Status != http.StatusFound || strings.Contains(string(signed.Body), "<form") {
			ht.Fatalf("session %d %s", signed.Status, signed.Body)
		}
		sessionCode := hpRedirectCode(ht, signed, state)
		if hpExchange(app, clientID, sessionCode, redirect, verifier).Status != http.StatusOK {
			ht.Fatal("session code did not exchange")
		}

		issued := hpLoginPost(app, path, "ada", password)
		if issued.Status != http.StatusSeeOther {
			ht.Fatalf("login %d %s", issued.Status, issued.Body)
		}
		code := hpRedirectCode(ht, issued, state)
		mismatch := hpExchange(app, clientID, code, other, verifier)
		hpOAuthErr(ht, mismatch, http.StatusBadRequest, "invalid_grant", "invalid authorization code")
		good := hpExchange(app, clientID, code, redirect, verifier)
		if good.Status != http.StatusOK || !strings.Contains(string(good.Body), "access_token") {
			ht.Fatalf("exchange %d %s", good.Status, good.Body)
		}
		replay := hpExchange(app, clientID, code, redirect, verifier)
		hpOAuthErr(ht, replay, http.StatusBadRequest, "invalid_grant", "invalid authorization code")

		unknown := app.Request(http.MethodGet, hpAuthorizePath(clientID, "https://evil.example/cb", state, challenge, "code", scope), nil)
		if unknown.Status != http.StatusBadRequest || unknown.Header.Get("Location") != "" || !strings.Contains(string(unknown.Body), "redirect") {
			ht.Fatalf("unknown redirect %d loc %q body %s", unknown.Status, unknown.Header.Get("Location"), unknown.Body)
		}
		bad := app.Request(http.MethodGet, hpAuthorizePath(clientID, redirect, state, challenge, badType, scope), nil)
		hpRedirectOAuthErr(ht, bad, state, "unsupported_response_type")
	})
}

func TestPropOAuthTTL(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		// A positive nanosecond can still fall inside the current tick.
		// Zero keeps the default lifetime. A negative duration is already expired.
		clientID := hegel.Draw(ht, hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(8))
		subject := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(8))
		state := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ012").MinSize(1).MaxSize(8))
		verifier := hegel.Draw(ht, hegel.Text().Alphabet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~").MinSize(43).MaxSize(48))
		neg := -time.Nanosecond
		if hegel.Draw(ht, hegel.Booleans()) {
			neg = -time.Second
		}
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		const redirect = "https://app.example/cb"

		expiredCode := hpOAuthTTLApp(clientID, subject, gfast.OAuthConfig{CodeTTL: neg})
		code := hpSessionCode(ht, expiredCode, clientID, redirect, state, challenge)
		hpOAuthErr(ht, hpExchange(expiredCode, clientID, code, redirect, verifier), http.StatusBadRequest, "invalid_grant", "invalid authorization code")

		expiredRefresh := hpOAuthTTLApp(clientID, subject, gfast.OAuthConfig{RefreshTTL: neg})
		refreshCode := hpSessionCode(ht, expiredRefresh, clientID, redirect, state, challenge)
		issued := hpExchange(expiredRefresh, clientID, refreshCode, redirect, verifier)
		if issued.Status != http.StatusOK {
			ht.Fatalf("refresh setup %d %s", issued.Status, issued.Body)
		}
		var tok struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := issued.JSON(&tok); err != nil || tok.RefreshToken == "" {
			ht.Fatalf("refresh body %s err %v", issued.Body, err)
		}
		hpOAuthErr(ht, hpRefreshGrant(expiredRefresh, clientID, tok.RefreshToken), http.StatusBadRequest, "invalid_grant", "invalid refresh token")

		live := hpOAuthTTLApp(clientID, subject, gfast.OAuthConfig{})
		liveCode := hpSessionCode(ht, live, clientID, redirect, state, challenge)
		liveTok := hpExchange(live, clientID, liveCode, redirect, verifier)
		if liveTok.Status != http.StatusOK {
			ht.Fatalf("default ttl %d %s", liveTok.Status, liveTok.Body)
		}
		var access struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			ExpiresIn    int    `json:"expires_in"`
		}
		if err := liveTok.JSON(&access); err != nil {
			ht.Fatal(err)
		}
		if access.ExpiresIn != int(time.Hour/time.Second) || access.AccessToken == "" || access.RefreshToken == "" {
			ht.Fatalf("default token %+v", access)
		}
		me := live.Request(http.MethodGet, "/me", nil, http.Header{"Authorization": []string{"Bearer " + access.AccessToken}})
		if me.Status != http.StatusOK || !strings.Contains(string(me.Body), subject) {
			ht.Fatalf("me %d %s", me.Status, me.Body)
		}
		if again := hpRefreshGrant(live, clientID, access.RefreshToken); again.Status != http.StatusOK {
			ht.Fatalf("refresh %d %s", again.Status, again.Body)
		}

		shortAccess := hpOAuthTTLApp(clientID, subject, gfast.OAuthConfig{AccessTTL: neg})
		shortCode := hpSessionCode(ht, shortAccess, clientID, redirect, state, challenge)
		shortTok := hpExchange(shortAccess, clientID, shortCode, redirect, verifier)
		if shortTok.Status != http.StatusOK {
			ht.Fatalf("short access %d %s", shortTok.Status, shortTok.Body)
		}
		var short struct {
			AccessToken string `json:"access_token"`
		}
		if err := shortTok.JSON(&short); err != nil || short.AccessToken == "" {
			ht.Fatalf("short body %s", shortTok.Body)
		}
		rejected := shortAccess.Request(http.MethodGet, "/me", nil, http.Header{"Authorization": []string{"Bearer " + short.AccessToken}})
		if rejected.Status != http.StatusUnauthorized {
			ht.Fatalf("expired access %d %s", rejected.Status, rejected.Body)
		}
	})
}

func TestPropUnicodeQueryPath(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		seg := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301XYZ019").MinSize(1).MaxSize(8))
		q := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301XYZ019").MaxSize(8))
		var hits int
		app := gfast.New()
		app.Get("/u/{id}", func(ctx context.Context, in *struct {
			ID string `path:"id"`
			Q  string `query:"q"`
		}) (*struct {
			ID string `json:"id"`
			Q  string `json:"q"`
		}, error) {
			hits++
			return &struct {
				ID string `json:"id"`
				Q  string `json:"q"`
			}{ID: in.ID, Q: in.Q}, nil
		})
		res := app.Request(http.MethodGet, "/u/"+url.PathEscape(seg)+"?q="+url.QueryEscape(q), nil)
		if res.Status != http.StatusOK || hits != 1 {
			ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
		}
		var got struct {
			ID string `json:"id"`
			Q  string `json:"q"`
		}
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.ID != seg || got.Q != q {
			ht.Fatalf("got %+v want %q %q", got, seg, q)
		}
		slash := app.Request(http.MethodGet, "/u/a/b", nil)
		if slash.Status != http.StatusNotFound || hits != 1 {
			ht.Fatalf("slash %d hits %d body %s", slash.Status, hits, slash.Body)
		}
	})
}

func TestPropHeaderAndCookieControls(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		octet := hegel.Text().Alphabet("abcXYZ019_-.~!#$%&'*+=?@^_|")
		prefix := hegel.Draw(ht, octet.MaxSize(4))
		suffix := hegel.Draw(ht, octet.MaxSize(4))
		clean := hegel.Draw(ht, octet.MaxSize(6))
		kind := hegel.Draw(ht, hegel.Integers(0, 2))
		value := prefix + string([]byte{0, '\r', '\n'}[kind]) + suffix
		var hits int
		app := gfast.New()
		app.Get("/h", func(ctx context.Context, in *struct {
			H string `header:"X-Mark"`
			C string `cookie:"sid"`
		}) (*struct {
			H string `json:"h"`
			C string `json:"c"`
		}, error) {
			hits++
			return &struct {
				H string `json:"h"`
				C string `json:"c"`
			}{H: in.H, C: in.C}, nil
		})

		rejected := app.Request(http.MethodGet, "/h", nil, http.Header{"X-Mark": []string{clean, value}})
		hpProblem(ht, rejected, http.StatusBadRequest, "invalid header value")
		if hits != 0 {
			ht.Fatalf("handler ran for a broken header")
		}
		kept := app.Request(http.MethodGet, "/h", nil, http.Header{
			"X-Mark": []string{clean},
			"Cookie": []string{"sid=" + value},
		})
		if kept.Status != http.StatusOK || hits != 1 {
			ht.Fatalf("cookie %d hits %d body %s", kept.Status, hits, kept.Body)
		}
		var got struct {
			H string `json:"h"`
			C string `json:"c"`
		}
		if err := kept.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.H != clean || strings.ContainsAny(got.C, "\x00\r\n") || got.C == value {
			ht.Fatalf("control bytes round-tripped %+v value %q", got, value)
		}
	})
}

var hpSendableClose = []int{
	gfast.CloseNormalClosure,
	gfast.CloseGoingAway,
	gfast.CloseProtocolError,
	gfast.CloseUnsupportedData,
	gfast.CloseInvalidPayload,
	gfast.ClosePolicyViolation,
	gfast.CloseMessageTooBig,
	gfast.CloseInternalError,
	gfast.CloseServiceRestart,
	gfast.CloseTryAgainLater,
	gfast.CloseBadGateway,
	3000,
	3999,
	4999,
}

func hpDoc(ht *hegel.T, app *gfast.App) map[string]any {
	ht.Helper()
	res := app.Request(http.MethodGet, "/openapi.json", nil)
	if res.Status != http.StatusOK {
		ht.Fatalf("spec %d %s", res.Status, res.Body)
	}
	var doc map[string]any
	if err := res.JSON(&doc); err != nil {
		ht.Fatal(err)
	}
	return doc
}

func hpObj(ht *hegel.T, v any) map[string]any {
	ht.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		ht.Fatalf("object %T", v)
	}
	return m
}

func hpOp(ht *hegel.T, doc map[string]any, path, method string) map[string]any {
	ht.Helper()
	return hpObj(ht, hpObj(ht, hpObj(ht, doc["paths"])[path])[method])
}

func hpState(ht *hegel.T, res *gfast.Result) struct {
	Boot string `json:"boot"`
	Prev string `json:"prev"`
} {
	ht.Helper()
	if res.Status != http.StatusOK {
		ht.Fatalf("state %d %s", res.Status, res.Body)
	}
	var got struct {
		Boot string `json:"boot"`
		Prev string `json:"prev"`
	}
	if err := res.JSON(&got); err != nil {
		ht.Fatal(err)
	}
	return got
}

func hpExpectClose(ht *hegel.T, conn net.Conn, code int) {
	ht.Helper()
	fin, op, payload := readUnmasked(ht, conn)
	if !fin || op != 0x8 || len(payload) < 2 {
		ht.Fatalf("close fin %v op %d len %d", fin, op, len(payload))
	}
	got := int(payload[0])<<8 | int(payload[1])
	if got != code {
		ht.Fatalf("close %d want %d", got, code)
	}
}

func hpAuthorizePath(clientID, redirect, state, challenge, responseType, scope string) string {
	q := url.Values{}
	q.Set("response_type", responseType)
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirect)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("scope", scope)
	return "/oauth/authorize?" + q.Encode()
}

func hpLoginPage(ht *hegel.T, res *gfast.Result, status int, message string) {
	ht.Helper()
	body := string(res.Body)
	if res.Status != status || res.Header.Get("Location") != "" || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		ht.Fatalf("login %d type %q loc %q body %s", res.Status, res.Header.Get("Content-Type"), res.Header.Get("Location"), body)
	}
	if !strings.Contains(body, "<form") || !strings.Contains(body, "Sign in") || strings.Contains(body, "csrf_token") {
		ht.Fatalf("login body %s", body)
	}
	if message != "" && !strings.Contains(body, message) {
		ht.Fatalf("login body %s", body)
	}
}

func hpLoginPost(app *gfast.App, path, username, password string) *gfast.Result {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	return app.Request(http.MethodPost, path, []byte(form.Encode()), http.Header{
		"Content-Type": []string{"application/x-www-form-urlencoded"},
	})
}

func hpRedirectCode(ht *hegel.T, res *gfast.Result, state string) string {
	ht.Helper()
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		ht.Fatal(err)
	}
	if loc.Query().Get("state") != state || loc.Query().Get("code") == "" || loc.Query().Get("error") != "" {
		ht.Fatalf("location %q", res.Header.Get("Location"))
	}
	return loc.Query().Get("code")
}

func hpRedirectOAuthErr(ht *hegel.T, res *gfast.Result, state, code string) {
	ht.Helper()
	if res.Status != http.StatusFound {
		ht.Fatalf("oauth redirect %d %s", res.Status, res.Body)
	}
	loc, err := url.Parse(res.Header.Get("Location"))
	if err != nil {
		ht.Fatal(err)
	}
	if loc.Host != "app.example" || loc.Path != "/cb" || loc.Query().Get("error") != code || loc.Query().Get("state") != state || loc.Query().Get("code") != "" {
		ht.Fatalf("location %q", res.Header.Get("Location"))
	}
}

func hpExchange(app *gfast.App, clientID, code, redirect, verifier string) *gfast.Result {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirect)
	form.Set("client_id", clientID)
	form.Set("code_verifier", verifier)
	return app.Request(http.MethodPost, "/oauth/token", []byte(form.Encode()), http.Header{
		"Content-Type": []string{"application/x-www-form-urlencoded"},
	})
}

func hpRefreshGrant(app *gfast.App, clientID, refresh string) *gfast.Result {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refresh)
	form.Set("client_id", clientID)
	return app.Request(http.MethodPost, "/oauth/token", []byte(form.Encode()), http.Header{
		"Content-Type": []string{"application/x-www-form-urlencoded"},
	})
}

func hpOAuthTTLApp(clientID, subject string, cfg gfast.OAuthConfig) *gfast.App {
	const redirect = "https://app.example/cb"
	cfg.Clients = []gfast.OAuthClient{{
		ID:           clientID,
		RedirectURIs: []string{redirect},
	}}
	cfg.Session = func(ctx context.Context, r *http.Request) (string, error) {
		return subject, nil
	}
	app := gfast.New(gfast.OAuthServer(cfg))
	app.Get("/me", func(ctx context.Context, in *struct {
		Cred gfast.Bearer `gfast:"dep=bearerAuth"`
	}) (*struct {
		Sub string `json:"sub"`
	}, error) {
		return &struct {
			Sub string `json:"sub"`
		}{Sub: in.Cred.Subject}, nil
	})
	return app
}

func hpSessionCode(ht *hegel.T, app *gfast.App, clientID, redirect, state, challenge string) string {
	ht.Helper()
	res := app.Request(http.MethodGet, hpAuthorizePath(clientID, redirect, state, challenge, "code", ""), nil)
	if res.Status != http.StatusFound {
		ht.Fatalf("authorize %d %s", res.Status, res.Body)
	}
	return hpRedirectCode(ht, res, state)
}
