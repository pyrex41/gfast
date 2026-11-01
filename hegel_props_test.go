package gfast_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"hegel.dev/go/hegel"

	"github.com/pyrex41/gfast"
)

type hpLeaf struct{ N int }
type hpMid struct{ N int }
type hpAlt struct{ N int }
type hpSelf struct{ N int }
type hpToken struct{ ID int64 }

type hpNOut struct {
	N int `json:"n"`
}

type hpFan1 struct {
	A hpMid `gfast:"dep=hpMid"`
}

type hpFan2 struct {
	A hpMid  `gfast:"dep=hpMid"`
	B hpMid  `gfast:"dep=hpMid"`
	C hpLeaf `gfast:"dep=hpLeaf"`
}

type hpFan3 struct {
	A hpMid  `gfast:"dep=hpMid"`
	B hpMid  `gfast:"dep=hpMid"`
	C hpMid  `gfast:"dep=hpMid"`
	D hpLeaf `gfast:"dep=hpLeaf"`
	E hpLeaf `gfast:"dep=hpLeaf"`
}

type hpMidIn struct {
	A hpMid `gfast:"dep=hpMid"`
	B hpMid `gfast:"dep=hpMid"`
}

type hpFailIn struct {
	ID    int64 `path:"id"`
	N     int64 `query:"n"`
	Body  hpTitle
	Leaf  hpLeaf `gfast:"dep=hpLeaf"`
	Also  hpLeaf `gfast:"dep=hpLeaf"`
	Alt   hpAlt  `gfast:"dep=hpAlt"`
	Extra hpAlt  `gfast:"dep=hpAlt"`
}

type hpFailOut struct {
	ID    int64  `json:"id"`
	N     int64  `json:"n"`
	Title string `json:"title"`
	Leaf  int    `json:"leaf"`
	Alt   int    `json:"alt"`
}

type hpQIn struct {
	ID int    `path:"id" default:"7"`
	N  int64  `query:"n"`
	Q  string `query:"q" minLength:"2" maxLength:"4"`
}

type hpQOut struct {
	ID int    `json:"id"`
	N  int64  `json:"n"`
	Q  string `json:"q"`
}

type hpFlatIn struct {
	ID    string      `path:"id"`
	Title string      `json:"title" minLength:"2" maxLength:"5"`
	User  hpPrincipal `json:"user" query:"user" gfast:"dep=hpUser"`
	Also  hpPrincipal `gfast:"dep=hpUser"`
}

type hpBodySecIn struct {
	ID     string      `path:"id"`
	Hidden hpPrincipal `json:"user" query:"user" gfast:"dep=hpUser"`
	Nest   struct {
		Also hpPrincipal `gfast:"dep=hpUser"`
	}
	Body hpTitle
}

type hpSecOut struct {
	ID     string   `json:"id"`
	Path   string   `json:"path"`
	Title  string   `json:"title"`
	Scopes []string `json:"scopes"`
}

var (
	hpLeafCalls atomic.Int32
	hpMidCalls  atomic.Int32
	hpAltCalls  atomic.Int32
	hpOverCalls atomic.Int32
	hpLeafStamp atomic.Int64
	hpAltStamp  atomic.Int64

	hpOverlapCalls atomic.Int32
	hpOverlapSeq   atomic.Int64
	hpGateP        atomic.Pointer[hpGate]
)

var hpLeafDep = gfast.Dep("hpLeaf", func(ctx context.Context) (hpLeaf, error) {
	hpLeafCalls.Add(1)
	return hpLeaf{N: int(hpLeafStamp.Load())}, nil
})

var hpMidDep = gfast.Dep("hpMid", func(ctx context.Context, leaf hpLeaf) (hpMid, error) {
	hpMidCalls.Add(1)
	return hpMid{N: leaf.N}, nil
})

var hpAltDep = gfast.Dep("hpAlt", func(ctx context.Context) (hpAlt, error) {
	hpAltCalls.Add(1)
	return hpAlt{N: int(hpAltStamp.Load())}, nil
})

var hpSelfDep = gfast.Dep("hpSelf", func(ctx context.Context, v hpSelf) (hpSelf, error) {
	return v, nil
})

var hpOverlapDep = gfast.Dep("hpOverlap", func(ctx context.Context) (hpToken, error) {
	hpOverlapCalls.Add(1)
	id := hpOverlapSeq.Add(1)
	hpGateP.Load().arrive()
	return hpToken{ID: id}, nil
})

type hpGate struct {
	mu      sync.Mutex
	entered int
	ch      chan struct{}
	once    sync.Once
}

func (g *hpGate) arrive() {
	g.mu.Lock()
	g.entered++
	n := g.entered
	g.mu.Unlock()
	if n >= 2 {
		g.release()
	}
	<-g.ch
}

func (g *hpGate) release() {
	g.once.Do(func() { close(g.ch) })
}

func hpZeroDeps() {
	hpLeafCalls.Store(0)
	hpMidCalls.Store(0)
	hpAltCalls.Store(0)
	hpOverCalls.Store(0)
}

func hpCatch(fn func()) (rec any) {
	defer func() { rec = recover() }()
	fn()
	return nil
}

func hpSame(ht *hegel.T, vals ...int) int {
	ht.Helper()
	for _, v := range vals[1:] {
		if v != vals[0] {
			ht.Fatalf("dependency values differ: %v", vals)
		}
	}
	return vals[0]
}

func hpParse(name, raw string) (int64, string, bool) {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, name + ": " + err.Error(), false
	}
	return n, "", true
}

func TestPropAcyclicDepsAndCyclePanic(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		fan := hegel.Draw(ht, hegel.Integers(1, 3))
		reqMid := hegel.Draw(ht, hegel.Booleans())
		reqLeaf := hegel.Draw(ht, hegel.Booleans())
		reps := hegel.Draw(ht, hegel.Integers(1, 3))
		kind := hegel.Draw(ht, hegel.Integers(0, 2))
		stamp := hegel.Draw(ht, hegel.Integers(1, 10000))
		hpLeafStamp.Store(int64(stamp))
		hpZeroDeps()

		var opts []gfast.Option
		if reqMid {
			opts = append(opts, gfast.Require(hpMidDep))
		}
		if reqLeaf {
			opts = append(opts, gfast.Require(hpLeafDep))
		}
		app := gfast.New()
		switch fan {
		case 1:
			app.Get("/g", func(ctx context.Context, in *hpFan1) (*hpNOut, error) {
				return &hpNOut{N: hpSame(ht, in.A.N)}, nil
			}, opts...)
		case 2:
			app.Get("/g", func(ctx context.Context, in *hpFan2) (*hpNOut, error) {
				return &hpNOut{N: hpSame(ht, in.A.N, in.B.N, in.C.N)}, nil
			}, opts...)
		default:
			app.Get("/g", func(ctx context.Context, in *hpFan3) (*hpNOut, error) {
				return &hpNOut{N: hpSame(ht, in.A.N, in.B.N, in.C.N, in.D.N, in.E.N)}, nil
			}, opts...)
		}

		for i := 0; i < reps; i++ {
			beforeL, beforeM := hpLeafCalls.Load(), hpMidCalls.Load()
			res := app.Request(http.MethodGet, "/g", nil)
			if res.Status != http.StatusOK {
				ht.Fatalf("status %d body %s", res.Status, res.Body)
			}
			var got hpNOut
			if err := res.JSON(&got); err != nil {
				ht.Fatal(err)
			}
			if got.N != stamp || hpLeafCalls.Load() != beforeL+1 || hpMidCalls.Load() != beforeM+1 || hpAltCalls.Load() != 0 {
				ht.Fatalf("got %d stamp %d leaf %d mid %d alt %d", got.N, stamp, hpLeafCalls.Load(), hpMidCalls.Load(), hpAltCalls.Load())
			}
		}

		spec := hpSpec(ht, app)
		op := spec.op("/g", "get")
		if len(op.Parameters) != 0 || op.RequestBody != nil || op.Security != nil {
			ht.Fatalf("dep fields leaked into the spec: params %#v body %#v security %v", op.Parameters, op.RequestBody, op.Security)
		}

		want := "gfast: dependency cycle: cycleA -> cycleB -> cycleA"
		register := func() {
			gfast.Get(app, "/cycle", func(ctx context.Context, in *struct {
				A cycleA `gfast:"dep=cycleA"`
			}) (*hpNOut, error) {
				return &hpNOut{}, nil
			})
		}
		switch kind {
		case 1:
			want = "gfast: dependency cycle: cycleB -> cycleA -> cycleB"
			register = func() {
				gfast.Get(app, "/cycle", func(ctx context.Context, in *struct {
					B cycleB `gfast:"dep=cycleB"`
				}) (*hpNOut, error) {
					return &hpNOut{}, nil
				})
			}
		case 2:
			want = "gfast: dependency cycle: hpSelf -> hpSelf"
			register = func() {
				_ = hpSelfDep
				gfast.Get(app, "/cycle", func(ctx context.Context, in *struct {
					S hpSelf `gfast:"dep=hpSelf"`
				}) (*hpNOut, error) {
					return &hpNOut{}, nil
				})
			}
		}
		beforeL, beforeM := hpLeafCalls.Load(), hpMidCalls.Load()
		rec := hpCatch(register)
		if fmt.Sprint(rec) != want {
			ht.Fatalf("panic %v want %s", rec, want)
		}
		if hpLeafCalls.Load() != beforeL || hpMidCalls.Load() != beforeM {
			ht.Fatal("cycle registration ran a provider")
		}
		missing := app.Request(http.MethodGet, "/cycle", nil)
		if missing.Status != http.StatusNotFound {
			ht.Fatalf("cycle route status %d", missing.Status)
		}
		again := app.Request(http.MethodGet, "/g", nil)
		if again.Status != http.StatusOK || hpLeafCalls.Load() != beforeL+1 || hpMidCalls.Load() != beforeM+1 {
			ht.Fatalf("route after cycle status %d leaf %d mid %d", again.Status, hpLeafCalls.Load(), hpMidCalls.Load())
		}
	})
}

func TestPropOverrideReplacesRequestedProviders(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		mode := hegel.Draw(ht, hegel.Integers(0, 2))
		early := hegel.Draw(ht, hegel.Booleans())
		firstOver := hegel.Draw(ht, hegel.Booleans())
		reps := hegel.Draw(ht, hegel.Integers(1, 2))
		leafN := hegel.Draw(ht, hegel.Integers(0, 400))
		altN := 600 + hegel.Draw(ht, hegel.Integers(0, 400))
		constN := 1200 + hegel.Draw(ht, hegel.Integers(0, 400))
		hpLeafStamp.Store(int64(leafN))
		hpAltStamp.Store(int64(altN))

		overApp := gfast.New()
		origApp := gfast.New()
		install := func() {
			switch mode {
			case 0:
				overApp.Override(hpMidDep, func(ctx context.Context) (hpMid, error) {
					hpOverCalls.Add(1)
					return hpMid{N: constN}, nil
				})
			case 1:
				overApp.Override(hpMidDep, func(ctx context.Context, alt hpAlt) (hpMid, error) {
					hpOverCalls.Add(1)
					return hpMid{N: alt.N}, nil
				})
			default:
				overApp.Override(hpMidDep, func(ctx context.Context, leaf hpLeaf) (hpMid, error) {
					hpOverCalls.Add(1)
					return hpMid{N: leaf.N + 1}, nil
				})
			}
		}
		handler := func(ctx context.Context, in *hpMidIn) (*hpNOut, error) {
			if in.A.N != in.B.N {
				ht.Fatalf("mid fields %d %d", in.A.N, in.B.N)
			}
			return &hpNOut{N: in.A.N}, nil
		}
		if early {
			install()
		}
		overApp.Get("/m", handler)
		origApp.Get("/m", handler)
		if !early {
			install()
		}

		type hit struct {
			app  *gfast.App
			over bool
		}
		hits := []hit{{origApp, false}, {overApp, true}}
		if firstOver {
			hits[0], hits[1] = hits[1], hits[0]
		}
		for i := 0; i < reps; i++ {
			for _, item := range hits {
				hpZeroDeps()
				res := item.app.Request(http.MethodGet, "/m", nil)
				if res.Status != http.StatusOK {
					ht.Fatalf("status %d body %s", res.Status, res.Body)
				}
				var got hpNOut
				if err := res.JSON(&got); err != nil {
					ht.Fatal(err)
				}
				var wantN, wantLeaf, wantMid, wantAlt, wantOver int
				if item.over {
					switch mode {
					case 0:
						wantN, wantOver = constN, 1
					case 1:
						wantN, wantAlt, wantOver = altN, 1, 1
					default:
						wantN, wantLeaf, wantOver = leafN+1, 1, 1
					}
				} else {
					wantN, wantLeaf, wantMid = leafN, 1, 1
				}
				if got.N != wantN || int(hpLeafCalls.Load()) != wantLeaf || int(hpMidCalls.Load()) != wantMid || int(hpAltCalls.Load()) != wantAlt || int(hpOverCalls.Load()) != wantOver {
					ht.Fatalf("mode %d over %v got %d want %d leaf %d mid %d alt %d over %d", mode, item.over, got.N, wantN, hpLeafCalls.Load(), hpMidCalls.Load(), hpAltCalls.Load(), hpOverCalls.Load())
				}
			}
		}
	})
}

func TestPropBindFailureSkipsWork(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		idRaw := hegel.Draw(ht, hegel.Text().Alphabet("0123456789-+x").MinSize(1).MaxSize(8))
		nRaw := hegel.Draw(ht, hegel.Text().Alphabet("0123456789-+x").MinSize(1).MaxSize(8))
		title := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301").MaxSize(8))
		bodyMode := hegel.Draw(ht, hegel.Integers(0, 5))
		extra := hegel.Draw(ht, hegel.Text().Alphabet("xyz").MinSize(1).MaxSize(4))
		leafN := hegel.Draw(ht, hegel.Integers(1, 500))
		altN := 1000 + hegel.Draw(ht, hegel.Integers(1, 500))
		hpLeafStamp.Store(int64(leafN))
		hpAltStamp.Store(int64(altN))
		hpZeroDeps()

		var hits int
		app := gfast.New()
		app.Post("/fail/{id}", func(ctx context.Context, in *hpFailIn) (*hpFailOut, error) {
			hits++
			if in.Leaf.N != in.Also.N || in.Alt.N != in.Extra.N {
				ht.Fatalf("fields leaf %d/%d alt %d/%d", in.Leaf.N, in.Also.N, in.Alt.N, in.Extra.N)
			}
			return &hpFailOut{ID: in.ID, N: in.N, Title: in.Body.Title, Leaf: in.Leaf.N, Alt: in.Alt.N}, nil
		}, gfast.Require(hpLeafDep, hpAltDep))

		var body []byte
		forceCL := false
		switch bodyMode {
		case 1:
			body = []byte("{\"title\":\"\xff\"}")
		case 2:
			quoted, _ := json.Marshal(title)
			body = []byte(`{"title":` + string(quoted) + `,"title":` + string(quoted) + `}`)
		case 3:
			body, _ = json.Marshal(map[string]any{"title": title, extra: true})
		case 4:
			body = []byte(`{"title":1}`)
		case 5:
			body = []byte(`{"title":"abcd"}`)
			forceCL = true
		default:
			body, _ = json.Marshal(hpTitle{Title: title})
		}
		target := "/fail/" + url.PathEscape(idRaw) + "?" + url.Values{"n": {nRaw}}.Encode()
		res := hpDo(app, http.MethodPost, target, body, nil, forceCL, 0)

		id, idErr, idOK := hpParse("id", idRaw)
		n, nErr, nOK := hpParse("n", nRaw)
		switch {
		case !idOK:
			hpProblem(ht, res, http.StatusBadRequest, idErr)
		case !nOK:
			hpProblem(ht, res, http.StatusBadRequest, nErr)
		case bodyMode != 0 && bodyMode != 5:
			hpStatus(ht, res, http.StatusBadRequest)
			if strings.Contains(string(res.Body), "must be at least") || strings.Contains(string(res.Body), "must be at most") {
				ht.Fatalf("validation ran on a rejected document: %s", res.Body)
			}
		default:
			issues := hpStringIssues(title, "title", []string{"body", "title"}, 2, 5)
			if bodyMode == 5 {
				issues = hpStringIssues("", "title", []string{"body", "title"}, 2, 5)
			}
			if len(issues) > 0 {
				hpIssues(ht, res, http.StatusUnprocessableEntity, issues)
				break
			}
			if res.Status != http.StatusOK {
				ht.Fatalf("status %d body %s", res.Status, res.Body)
			}
			var got hpFailOut
			if err := res.JSON(&got); err != nil {
				ht.Fatal(err)
			}
			if got.ID != id || got.N != n || got.Title != title || got.Leaf != leafN || got.Alt != altN || hits != 1 {
				ht.Fatalf("got %+v hits %d", got, hits)
			}
			if hpLeafCalls.Load() != 1 || hpAltCalls.Load() != 1 {
				ht.Fatalf("leaf %d alt %d", hpLeafCalls.Load(), hpAltCalls.Load())
			}
			return
		}
		if hits != 0 || hpLeafCalls.Load() != 0 || hpAltCalls.Load() != 0 {
			ht.Fatalf("ran handler %d leaf %d alt %d mode %d", hits, hpLeafCalls.Load(), hpAltCalls.Load(), bodyMode)
		}
	})
}

func TestPropOverlapDoesNotShareMemo(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		alsoRequire := hegel.Draw(ht, hegel.Booleans())
		q1 := hegel.Draw(ht, hegel.Text().Alphabet("abc").MaxSize(6))
		q2 := q1 + "x"
		hpOverlapCalls.Store(0)
		hpOverlapSeq.Store(0)
		gate := &hpGate{ch: make(chan struct{})}
		hpGateP.Store(gate)

		app := gfast.New()
		type inT struct {
			Q string  `query:"q"`
			A hpToken `gfast:"dep=hpOverlap"`
			B hpToken `gfast:"dep=hpOverlap"`
		}
		type outT struct {
			A int64  `json:"a"`
			B int64  `json:"b"`
			Q string `json:"q"`
		}
		handler := func(ctx context.Context, in *inT) (*outT, error) {
			return &outT{A: in.A.ID, B: in.B.ID, Q: in.Q}, nil
		}
		if alsoRequire {
			app.Get("/o", handler, gfast.Require(hpOverlapDep))
		} else {
			app.Get("/o", handler)
		}

		results := make(chan *gfast.Result, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		defer func() {
			gate.release()
			wg.Wait()
		}()
		for _, q := range []string{q1, q2} {
			q := q
			go func() {
				defer wg.Done()
				results <- app.Request(http.MethodGet, "/o?"+url.Values{"q": {q}}.Encode(), nil)
			}()
		}
		got := make([]*gfast.Result, 0, 2)
		timeout := time.After(2 * time.Second)
		for len(got) < 2 {
			select {
			case res := <-results:
				got = append(got, res)
			case <-timeout:
				ht.Fatal("overlapping requests did not finish")
			}
		}
		ids := map[int64]string{}
		for _, res := range got {
			if res.Status != http.StatusOK {
				ht.Fatalf("status %d body %s", res.Status, res.Body)
			}
			var body outT
			if err := res.JSON(&body); err != nil {
				ht.Fatal(err)
			}
			if body.A != body.B || body.A == 0 {
				ht.Fatalf("memo inside the request: %+v", body)
			}
			if body.Q != q1 && body.Q != q2 {
				ht.Fatalf("query %q", body.Q)
			}
			if prev, ok := ids[body.A]; ok {
				ht.Fatalf("id %d shared by %q and %q", body.A, prev, body.Q)
			}
			ids[body.A] = body.Q
		}
		if len(ids) != 2 || hpOverlapCalls.Load() != 2 {
			ht.Fatalf("ids %v calls %d", ids, hpOverlapCalls.Load())
		}
		if _, ok := ids[1]; !ok {
			ht.Fatalf("ids %v", ids)
		}
		if _, ok := ids[2]; !ok {
			ht.Fatalf("ids %v", ids)
		}
	})
}

func TestPropRunesQueryFirstAndPathRequired(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		id := hegel.Draw(ht, hegel.Integers(0, 50))
		nFirst := hegel.Draw(ht, hegel.Text().Alphabet("0123456789-+x").MinSize(1).MaxSize(8))
		otherN := hegel.Draw(ht, hegel.Text().Alphabet("0123456789-+x").MinSize(1).MaxSize(8))
		qFirst := hegel.Draw(ht, hegel.Text().Alphabet("ab👍\u0301").MaxSize(6))
		if otherN == nFirst {
			otherN += "z"
		}
		if a, errA := strconv.ParseInt(nFirst, 10, 64); errA == nil {
			if b, errB := strconv.ParseInt(otherN, 10, 64); errB == nil && a == b {
				otherN = strconv.FormatInt(a+1, 10)
			}
		}
		var otherQ string
		switch nRunes := utf8.RuneCountInString(qFirst); {
		case nRunes < 2:
			otherQ = "abcd"
		case nRunes > 4:
			otherQ = "ab"
		default:
			otherQ = "👍"
		}

		var hits int
		app := gfast.New()
		app.Get("/q/{id}", func(ctx context.Context, in *hpQIn) (*hpQOut, error) {
			hits++
			return &hpQOut{ID: in.ID, N: in.N, Q: in.Q}, nil
		})

		spec := hpSpec(ht, app)
		op := spec.op("/q/{id}", "get")
		if op.RequestBody != nil || len(op.Parameters) != 3 {
			ht.Fatalf("params %#v body %#v", op.Parameters, op.RequestBody)
		}
		for i, want := range []struct {
			name, in, typ string
			required      bool
		}{
			{"id", "path", "integer", true},
			{"n", "query", "integer", false},
			{"q", "query", "string", false},
		} {
			p := op.Parameters[i]
			if p.Name != want.name || p.In != want.in || p.Required != want.required || p.Schema.Type != want.typ {
				ht.Fatalf("param %#v", p)
			}
		}

		q := url.Values{}
		q["n"] = []string{nFirst, otherN, "nope"}
		q["q"] = []string{qFirst, otherQ}
		res := app.Request(http.MethodGet, "/q/"+strconv.Itoa(id)+"?"+q.Encode(), nil)
		n, nErr, nOK := hpParse("n", nFirst)
		if !nOK {
			hpProblem(ht, res, http.StatusBadRequest, nErr)
			if hits != 0 {
				ht.Fatal("handler ran")
			}
			return
		}
		if issues := hpStringIssues(qFirst, "q", []string{"query", "q"}, 2, 4); len(issues) > 0 {
			hpIssues(ht, res, http.StatusUnprocessableEntity, issues)
			if hits != 0 {
				ht.Fatal("handler ran")
			}
			return
		}
		if res.Status != http.StatusOK {
			ht.Fatalf("status %d body %s", res.Status, res.Body)
		}
		var got hpQOut
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.ID != id || got.N != n || got.Q != qFirst || hits != 1 {
			ht.Fatalf("got %+v want id %d n %d q %q hits %d", got, id, n, qFirst, hits)
		}
	})
}

func TestPropDepFieldsAndSecurity(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		hpReset()
		flat := hegel.Draw(ht, hegel.Booleans())
		useBasic := hegel.Draw(ht, hegel.Booleans())
		scopes := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abc:").MinSize(1).MaxSize(6)).MaxSize(4))
		token := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		title := hegel.Draw(ht, hegel.Text().Alphabet("abcd").MinSize(2).MaxSize(5))
		id := hegel.Draw(ht, hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(6))

		var opts []gfast.Option
		opts = append(opts, gfast.Scopes(scopes...))
		if useBasic {
			opts = append(opts, gfast.Require(gfast.BasicAuth()))
		}
		var hits int
		app := gfast.New()
		app.Post("/flat/{id}", func(ctx context.Context, in *hpFlatIn) (*hpSecOut, error) {
			hits++
			if in.User.ID != in.Also.ID || !sameStringList(in.User.Scopes, in.Also.Scopes) {
				ht.Fatalf("fields %#v %#v", in.User, in.Also)
			}
			return &hpSecOut{ID: in.User.ID, Path: in.ID, Title: in.Title, Scopes: append([]string(nil), in.User.Scopes...)}, nil
		}, opts...)
		app.Post("/body/{id}", func(ctx context.Context, in *hpBodySecIn) (*hpSecOut, error) {
			hits++
			if in.Hidden.ID != in.Nest.Also.ID || !sameStringList(in.Hidden.Scopes, in.Nest.Also.Scopes) {
				ht.Fatalf("fields %#v %#v", in.Hidden, in.Nest.Also)
			}
			return &hpSecOut{ID: in.Hidden.ID, Path: in.ID, Title: in.Body.Title, Scopes: append([]string(nil), in.Hidden.Scopes...)}, nil
		}, opts...)

		spec := hpSpec(ht, app)
		for _, path := range []string{"/flat/{id}", "/body/{id}"} {
			op := spec.op(path, "post")
			sec := spec.security(path, "post")
			if len(sec) != 1 || !sameStringList(sec[0]["bearerAuth"], scopes) {
				ht.Fatalf("%s security %v scopes %v", path, sec, scopes)
			}
			if useBasic {
				if !sameStringList(sec[0]["basicAuth"], nil) || len(sec[0]) != 2 {
					ht.Fatalf("%s security %v", path, sec)
				}
			} else if len(sec[0]) != 1 {
				ht.Fatalf("%s security %v", path, sec)
			}
			if len(op.Parameters) != 1 || op.Parameters[0].Name != "id" || op.Parameters[0].In != "path" || !op.Parameters[0].Required {
				ht.Fatalf("%s params %#v", path, op.Parameters)
			}
			schema := spec.expand(op.RequestBody.Content["application/json"].Schema)
			if !op.RequestBody.Required || len(schema.Properties) != 1 || schema.Properties["title"] == nil {
				ht.Fatalf("%s body %#v", path, schema)
			}
			if _, ok := schema.Properties["user"]; ok {
				ht.Fatalf("%s documented the dep field", path)
			}
			if !intPtrIs(schema.Properties["title"].MinLength, 2) || !intPtrIs(schema.Properties["title"].MaxLength, 5) {
				ht.Fatalf("%s title schema %#v", path, schema.Properties["title"])
			}
		}
		schemes := spec.doc.Components.SecuritySchemes
		bearer := schemes["bearerAuth"]
		if bearer.Type != "http" || bearer.Scheme != "bearer" {
			ht.Fatalf("bearer %#v", bearer)
		}
		if useBasic {
			basic := schemes["basicAuth"]
			if basic.Type != "http" || basic.Scheme != "basic" || len(schemes) != 2 {
				ht.Fatalf("schemes %#v", schemes)
			}
		} else if len(schemes) != 1 {
			ht.Fatalf("schemes %#v", schemes)
		}

		header := http.Header{"Authorization": []string{"Bearer " + token}}
		q := url.Values{"user": {"hacker"}}
		var res *gfast.Result
		if flat {
			payload, _ := json.Marshal(map[string]any{
				"title": title,
				"user":  map[string]any{"id": "hacker", "scopes": []string{"zz-nope"}},
			})
			res = app.Request(http.MethodPost, "/flat/"+url.PathEscape(id)+"?"+q.Encode(), payload, header)
		} else {
			payload, _ := json.Marshal(hpTitle{Title: title})
			res = app.Request(http.MethodPost, "/body/"+url.PathEscape(id)+"?"+q.Encode(), payload, header)
		}
		if useBasic {
			hpProblem(ht, res, http.StatusUnauthorized, "missing basic credentials")
			hpChallenge(ht, res, `Basic realm="api"`)
			if hits != 0 || hpUserCalls.Load() != 0 {
				ht.Fatalf("basic failure ran handler %d provider %d", hits, hpUserCalls.Load())
			}
			return
		}
		if res.Status != http.StatusOK {
			ht.Fatalf("status %d body %s", res.Status, res.Body)
		}
		var got hpSecOut
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.ID != token || got.Path != id || got.Title != title || !sameStringList(got.Scopes, scopes) || hits != 1 || hpUserCalls.Load() != 1 {
			ht.Fatalf("got %+v hits %d calls %d token %q scopes %v", got, hits, hpUserCalls.Load(), token, scopes)
		}
	})
}

func TestPropPlainAndStatusErrors(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		kind := hegel.Draw(ht, hegel.Integers(0, 4))
		wrap := hegel.Draw(ht, hegel.Booleans())
		msg := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ ").MaxSize(24))
		mark := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		secret := "zz:" + msg

		var err error
		status := http.StatusInternalServerError
		detail := "unexpected error occurred"
		switch kind {
		case 0:
			err = errors.New(secret)
		case 1:
			err = gfast.BadRequest(msg)
			status = http.StatusBadRequest
			detail = msg
		case 2:
			err = gfast.Unauthorized(msg)
			status = http.StatusUnauthorized
			detail = msg
		case 3:
			err = gfast.Forbidden(msg)
			status = http.StatusForbidden
			detail = msg
		default:
			err = gfast.NotFound(msg)
			status = http.StatusNotFound
			detail = msg
		}
		if wrap {
			err = fmt.Errorf("wrap-%s: %w", mark, err)
			if kind != 0 {
				detail = err.Error()
			}
		}

		app := gfast.New()
		app.Get("/e", func(ctx context.Context, in *struct{}) (*struct{}, error) {
			return nil, err
		})
		res := app.Request(http.MethodGet, "/e", nil)
		hpProblem(ht, res, status, detail)
		if kind == 0 {
			body := string(res.Body)
			if strings.Contains(body, secret) || strings.Contains(body, "wrap-") {
				ht.Fatalf("plain error leaked: %s", body)
			}
		} else if !strings.Contains(detail, msg) {
			ht.Fatalf("status detail %q dropped %q", detail, msg)
		}
	})
}

func TestPropBackgroundOrder(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		hpReset()
		tasks := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abc").MinSize(1).MaxSize(4)).MaxSize(4))
		mode := hegel.Draw(ht, hegel.Integers(0, 2))
		secret := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(4))
		reps := hegel.Draw(ht, hegel.Integers(1, 2))

		app := gfast.New()
		app.Post("/work", func(ctx context.Context, in *struct {
			B *hpBox `gfast:"dep=hpBoxB"`
		}) (*struct{ OK bool }, error) {
			gfast.Background(ctx, nil)
			for _, task := range tasks {
				task := task
				gfast.Background(ctx, func() { hpEvents = append(hpEvents, task) })
			}
			hpEvents = append(hpEvents, "handler")
			switch mode {
			case 0:
				return nil, nil
			case 1:
				return nil, errors.New("zz:" + secret)
			default:
				return &struct{ OK bool }{OK: true}, nil
			}
		}, gfast.Require(hpBoxA))

		want := append([]string{"handler"}, tasks...)
		want = append(want, "close-B", "close-A")
		for i := 0; i < reps; i++ {
			before := len(hpEvents)
			res := app.Request(http.MethodPost, "/work", nil)
			switch mode {
			case 0:
				if res.Status != http.StatusNoContent || len(res.Body) != 0 {
					ht.Fatalf("nil %d %s", res.Status, res.Body)
				}
			case 1:
				hpProblem(ht, res, http.StatusInternalServerError, "unexpected error occurred")
				if strings.Contains(string(res.Body), "zz:") || strings.Contains(string(res.Body), "close ") {
					ht.Fatalf("body leaked %s", res.Body)
				}
			default:
				if res.Status != http.StatusOK {
					ht.Fatalf("status %d %s", res.Status, res.Body)
				}
			}
			if !reflect.DeepEqual(hpEvents[before:], want) {
				ht.Fatalf("events %v want %v", hpEvents[before:], want)
			}
		}
		if hpBoxACalls.Load() != int32(reps) || hpBoxBCalls.Load() != int32(reps) {
			ht.Fatalf("calls A %d B %d reps %d", hpBoxACalls.Load(), hpBoxBCalls.Load(), reps)
		}
	})
}
