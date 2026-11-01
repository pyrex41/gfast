package gfast_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"github.com/pyrex41/gfast"
)

func TestPropRequiredQueryHeaderCookie(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		text := hegel.Text().Alphabet("abcXYZ019")
		rqMode := hegel.Draw(ht, hegel.Integers(0, 2))
		rhMode := hegel.Draw(ht, hegel.Integers(0, 2))
		rcMode := hegel.Draw(ht, hegel.Integers(0, 2))
		oqMode := hegel.Draw(ht, hegel.Integers(0, 2))
		ohMode := hegel.Draw(ht, hegel.Integers(0, 2))
		ocMode := hegel.Draw(ht, hegel.Integers(0, 2))
		rq := hegel.Draw(ht, text.MinSize(1).MaxSize(6))
		rh := hegel.Draw(ht, text.MinSize(1).MaxSize(6))
		rc := hegel.Draw(ht, text.MinSize(1).MaxSize(6))
		oq := hegel.Draw(ht, text.MaxSize(6))
		oh := hegel.Draw(ht, text.MaxSize(6))
		oc := hegel.Draw(ht, text.MaxSize(6))
		nPresent := hegel.Draw(ht, hegel.Booleans())
		n := hegel.Draw(ht, hegel.Integers(-20, 20))
		lower := hegel.Draw(ht, hegel.Booleans())

		var hits int
		app := gfast.New()
		app.Get("/need", func(ctx context.Context, in *hpNeed) (*hpNeed, error) {
			hits++
			return in, nil
		})

		q := url.Values{}
		if rqMode != 0 {
			if rqMode == 1 {
				q.Set("rq", "")
			} else {
				q.Set("rq", rq)
			}
		}
		if oqMode != 0 {
			if oqMode == 1 {
				q.Set("oq", "")
			} else {
				q.Set("oq", oq)
			}
		}
		if nPresent {
			q.Set("n", strconv.Itoa(n))
		}
		target := "/need"
		if encoded := q.Encode(); encoded != "" {
			target += "?" + encoded
		}
		header := http.Header{}
		reqName, optName := "X-Req", "X-Opt"
		if lower {
			reqName, optName = "x-req", "x-opt"
		}
		switch rhMode {
		case 1:
			header.Add(reqName, "")
		case 2:
			header.Add(reqName, rh)
		}
		switch ohMode {
		case 1:
			header.Add(optName, "")
		case 2:
			header.Add(optName, oh)
		}
		var cookies []string
		switch rcMode {
		case 1:
			cookies = append(cookies, "rc=")
		case 2:
			cookies = append(cookies, "rc="+rc)
		}
		switch ocMode {
		case 1:
			cookies = append(cookies, "oc=")
		case 2:
			cookies = append(cookies, "oc="+oc)
		}
		if len(cookies) > 0 {
			header.Set("Cookie", strings.Join(cookies, "; "))
		}

		res := app.Request(http.MethodGet, target, nil, header)
		var issues []hpIssue
		if rqMode == 0 {
			issues = append(issues, hpIssue{[]string{"query", "rq"}, "missing", "rq is required"})
		}
		if rhMode == 0 {
			issues = append(issues, hpIssue{[]string{"header", "X-Req"}, "missing", "X-Req is required"})
		}
		if rcMode == 0 {
			issues = append(issues, hpIssue{[]string{"cookie", "rc"}, "missing", "rc is required"})
		}
		if len(issues) > 0 {
			hpIssues(ht, res, http.StatusUnprocessableEntity, issues)
			if hits != 0 {
				ht.Fatalf("handler ran on %d", hits)
			}
			return
		}
		if res.Status != http.StatusOK || hits != 1 {
			ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
		}
		want := hpNeed{N: 0}
		if nPresent {
			want.N = n
		}
		if rqMode == 2 {
			want.RQ = rq
		}
		if rhMode == 2 {
			want.RH = rh
		}
		if rcMode == 2 {
			want.RC = rc
		}
		if oqMode == 2 {
			want.OQ = oq
		}
		if ohMode == 2 {
			want.OH = oh
		}
		if ocMode == 2 {
			want.OC = oc
		}
		var got hpNeed
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			ht.Fatalf("got %+v want %+v", got, want)
		}
	})
}

type hpNeed struct {
	RQ string `query:"rq" required:"true"`
	RH string `header:"X-Req" required:"true"`
	RC string `cookie:"rc" required:"true"`
	OQ string `query:"oq"`
	OH string `header:"X-Opt"`
	OC string `cookie:"oc"`
	N  int    `query:"n"`
}

func TestPropSliceQueryAndHeader(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		qs := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abc").MaxSize(4)).MaxSize(4))
		hs := hegel.Draw(ht, hegel.Lists(hegel.Integers(-30, 30)).MaxSize(4))

		var hits int
		app := gfast.New()
		app.Get("/lists", func(ctx context.Context, in *struct {
			Q []string `query:"q"`
			H []int    `header:"X-N"`
		}) (*struct {
			Q []string `json:"q"`
			H []int    `json:"h"`
		}, error) {
			hits++
			return &struct {
				Q []string `json:"q"`
				H []int    `json:"h"`
			}{Q: in.Q, H: in.H}, nil
		})

		q := url.Values{}
		for _, value := range qs {
			q.Add("q", value)
		}
		target := "/lists"
		if encoded := q.Encode(); encoded != "" {
			target += "?" + encoded
		}
		header := http.Header{}
		for _, n := range hs {
			header.Add("X-N", strconv.Itoa(n))
		}
		res := app.Request(http.MethodGet, target, nil, header)
		if res.Status != http.StatusOK || hits != 1 {
			ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
		}
		var got struct {
			Q []string `json:"q"`
			H []int    `json:"h"`
		}
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if !hpSameStrings(got.Q, qs) || !hpSameInts(got.H, hs) {
			ht.Fatalf("got %+v want q %v h %v", got, qs, hs)
		}
	})
}

func hpSameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func hpSameInts(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestPropConstraintsAndProblemBody(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		gt := hegel.Draw(ht, hegel.Integers(-2, 8))
		ge := hegel.Draw(ht, hegel.Integers(-2, 8))
		lt := hegel.Draw(ht, hegel.Integers(-2, 8))
		le := hegel.Draw(ht, hegel.Integers(-2, 8))
		code := hegel.Draw(ht, hegel.Text().Alphabet("abyzAB01").MaxSize(6))
		kind := hegel.Draw(ht, hegel.OneOf(
			hegel.SampledFrom([]string{"hat", "bat", "cat"}),
			hegel.Text().Alphabet("hatbc").MaxSize(6),
		))
		when, whenOK := hpDrawnDateTime(ht)
		id, idOK := hpDrawnUUID(ht)
		email, emailOK := hpDrawnEmail(ht)
		site, siteOK := hpDrawnURI(ht)
		items := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abc").MaxSize(3)).MaxSize(5))

		var hits int
		app := gfast.New()
		app.Get("/lim", func(ctx context.Context, in *hpLimits) (*hpLimits, error) {
			hits++
			return in, nil
		})

		q := url.Values{}
		q.Set("gt", strconv.Itoa(gt))
		q.Set("ge", strconv.Itoa(ge))
		q.Set("lt", strconv.Itoa(lt))
		q.Set("le", strconv.Itoa(le))
		q.Set("code", code)
		q.Set("kind", kind)
		q.Set("when", when)
		q.Set("id", id)
		q.Set("email", email)
		q.Set("site", site)
		for _, item := range items {
			q.Add("item", item)
		}
		res := app.Request(http.MethodGet, "/lim?"+q.Encode(), nil)
		var issues []hpIssue
		if gt <= 2 {
			issues = append(issues, hpIssue{[]string{"query", "gt"}, "greater_than", "gt must be greater than 2"})
		}
		if ge < 2 {
			issues = append(issues, hpIssue{[]string{"query", "ge"}, "greater_than_equal", "ge must be greater than or equal to 2"})
		}
		if lt >= 5 {
			issues = append(issues, hpIssue{[]string{"query", "lt"}, "less_than", "lt must be less than 5"})
		}
		if le > 5 {
			issues = append(issues, hpIssue{[]string{"query", "le"}, "less_than_equal", "le must be less than or equal to 5"})
		}
		if !hpPatternOK(code) {
			issues = append(issues, hpIssue{[]string{"query", "code"}, "string_pattern_mismatch", "code must match pattern ^[a-z]{2,4}$"})
		}
		if kind != "hat" && kind != "bat" && kind != "cat" {
			issues = append(issues, hpIssue{[]string{"query", "kind"}, "enum", "kind must be one of hat, bat, cat"})
		}
		if !whenOK {
			issues = append(issues, hpIssue{[]string{"query", "when"}, "date_time", "when must be a valid date-time"})
		}
		if !idOK {
			issues = append(issues, hpIssue{[]string{"query", "id"}, "uuid", "id must be a valid uuid"})
		}
		if !emailOK {
			issues = append(issues, hpIssue{[]string{"query", "email"}, "email", "email must be a valid email"})
		}
		if !siteOK {
			issues = append(issues, hpIssue{[]string{"query", "site"}, "uri", "site must be a valid uri"})
		}
		switch {
		case len(items) < 1:
			issues = append(issues, hpIssue{[]string{"query", "item"}, "too_short", "item must have at least 1 items"})
		case len(items) > 3:
			issues = append(issues, hpIssue{[]string{"query", "item"}, "too_long", "item must have at most 3 items"})
		}
		if len(issues) > 0 {
			hpIssues(ht, res, http.StatusUnprocessableEntity, issues)
			if hits != 0 {
				ht.Fatalf("handler ran")
			}
			return
		}
		if res.Status != http.StatusOK || hits != 1 {
			ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
		}
		var got hpLimits
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		want := hpLimits{GT: gt, GE: ge, LT: lt, LE: le, Code: code, Kind: kind, When: when, ID: id, Email: email, Site: site, Item: items}
		if !reflect.DeepEqual(got, want) {
			ht.Fatalf("got %+v want %+v", got, want)
		}
	})
}

type hpLimits struct {
	GT    int      `query:"gt" gt:"2"`
	GE    int      `query:"ge" ge:"2"`
	LT    int      `query:"lt" lt:"5"`
	LE    int      `query:"le" le:"5"`
	Code  string   `query:"code" pattern:"^[a-z]{2,4}$"`
	Kind  string   `query:"kind" enum:"hat,bat,cat"`
	When  string   `query:"when" format:"date-time"`
	ID    string   `query:"id" format:"uuid"`
	Email string   `query:"email" format:"email"`
	Site  string   `query:"site" format:"uri"`
	Item  []string `query:"item" minItems:"1" maxItems:"3"`
}

var hpUUIDBits = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func hpPatternOK(value string) bool {
	if len(value) < 2 || len(value) > 4 {
		return false
	}
	for _, r := range value {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

func hpDrawnDateTime(ht *hegel.T) (string, bool) {
	ht.Helper()
	good := hegel.Draw(ht, hegel.Booleans())
	if good {
		y := hegel.Draw(ht, hegel.Integers(1970, 2099))
		m := hegel.Draw(ht, hegel.Integers(1, 12))
		d := hegel.Draw(ht, hegel.Integers(1, 28))
		hh := hegel.Draw(ht, hegel.Integers(0, 23))
		mm := hegel.Draw(ht, hegel.Integers(0, 59))
		ss := hegel.Draw(ht, hegel.Integers(0, 59))
		raw := time.Date(y, time.Month(m), d, hh, mm, ss, 0, time.UTC).Format(time.RFC3339)
		return raw, true
	}
	raw := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019:-T").MaxSize(16))
	if _, err := time.Parse(time.RFC3339, raw); err == nil {
		return "not-a-date", false
	}
	return raw, false
}

func hpDrawnUUID(ht *hegel.T) (string, bool) {
	ht.Helper()
	hex := hegel.Text().Alphabet("0123456789abcdefABCDEF")
	if hegel.Draw(ht, hegel.Booleans()) {
		widths := []int{8, 4, 4, 4, 12}
		parts := make([]string, len(widths))
		for i, n := range widths {
			parts[i] = hegel.Draw(ht, hex.MinSize(n).MaxSize(n))
		}
		return strings.Join(parts, "-"), true
	}
	raw := hegel.Draw(ht, hegel.Text().Alphabet("0123456789abcdefABCDEF-g").MaxSize(40))
	if hpUUIDBits.MatchString(raw) {
		return "not-a-uuid", false
	}
	return raw, false
}

func hpDrawnEmail(ht *hegel.T) (string, bool) {
	ht.Helper()
	if hegel.Draw(ht, hegel.Booleans()) {
		local := hegel.Draw(ht, hegel.Text().Alphabet("abcxyz012").MinSize(1).MaxSize(6))
		host := hegel.Draw(ht, hegel.Text().Alphabet("abcxyz").MinSize(1).MaxSize(6))
		tld := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(2).MaxSize(3))
		return local + "@" + host + "." + tld, true
	}
	raw := hegel.Draw(ht, hegel.Text().Alphabet("abc @.").MaxSize(12))
	addr, err := mail.ParseAddress(raw)
	if err == nil && addr.Address == raw {
		return "not-an-email", false
	}
	return raw, false
}

func hpDrawnURI(ht *hegel.T) (string, bool) {
	ht.Helper()
	if hegel.Draw(ht, hegel.Booleans()) {
		path := hegel.Draw(ht, hegel.Text().Alphabet("abc").MaxSize(6))
		return "https://example.com/" + path, true
	}
	raw := hegel.Draw(ht, hegel.Text().Alphabet("abc:/ .").MaxSize(18))
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Scheme != "" && !strings.ContainsAny(raw, " \t\r\n") {
		return "/relative", false
	}
	return raw, false
}

func TestPropExtraAllow(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		allow := hegel.Draw(ht, hegel.Booleans())
		boxed := hegel.Draw(ht, hegel.Booleans())
		include := hegel.Draw(ht, hegel.Booleans())
		title := hegel.Draw(ht, hegel.Text().Alphabet("abc").MaxSize(6))
		key := hegel.Draw(ht, hegel.Text().Alphabet("xyz").MinSize(1).MaxSize(4))
		extra := hegel.Draw(ht, hegel.Integers(0, 9))

		var hits int
		app := gfast.New()
		app.Post("/strict", func(ctx context.Context, in *hpPlain) (*hpPlain, error) {
			hits++
			return in, nil
		})
		app.Post("/loose", func(ctx context.Context, in *hpLoose) (*hpPlain, error) {
			hits++
			return &hpPlain{Title: in.Title}, nil
		})
		app.Post("/strict-body", func(ctx context.Context, in *struct {
			Body hpPlain
		}) (*hpPlain, error) {
			hits++
			return &in.Body, nil
		})
		app.Post("/loose-body", func(ctx context.Context, in *struct {
			Body hpPlain `extra:"allow"`
		}) (*hpPlain, error) {
			hits++
			return &in.Body, nil
		})

		payload := map[string]any{"title": title}
		if include {
			payload[key] = extra
		}
		body, err := json.Marshal(payload)
		if err != nil {
			ht.Fatal(err)
		}
		path := "/strict"
		if boxed {
			path = "/strict-body"
		}
		if allow {
			path = "/loose"
			if boxed {
				path = "/loose-body"
			}
		}
		res := app.Request(http.MethodPost, path, body)
		if include && !allow {
			hpStatus(ht, res, http.StatusBadRequest)
			var problem struct {
				Detail string `json:"detail"`
			}
			if err := res.JSON(&problem); err != nil {
				ht.Fatal(err)
			}
			if !strings.Contains(problem.Detail, "unknown object member name "+strconv.Quote(key)) || hits != 0 {
				ht.Fatalf("detail %q hits %d", problem.Detail, hits)
			}
			return
		}
		if res.Status != http.StatusOK || hits != 1 {
			ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
		}
		var got hpPlain
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.Title != title {
			ht.Fatalf("title %q want %q", got.Title, title)
		}
	})
}

type hpPlain struct {
	Title string `json:"title"`
}

type hpLoose struct {
	Title string   `json:"title"`
	_     struct{} `extra:"allow"`
}

func TestPropValidateFailsRequest(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		useBody := hegel.Draw(ht, hegel.Booleans())
		title := hegel.Draw(ht, hegel.Text().Alphabet("abc").MaxSize(6))
		bad := hegel.Draw(ht, hegel.Integers(0, 2))

		var hits int
		app := gfast.New()
		app.Get("/q", func(ctx context.Context, in *hpCheckedQuery) (*hpPlain, error) {
			hits++
			return &hpPlain{Title: in.Title}, nil
		})
		app.Post("/b", func(ctx context.Context, in *struct {
			Body hpCheckedBody
		}) (*hpPlain, error) {
			hits++
			return &hpPlain{Title: in.Body.Title}, nil
		})

		var res *gfast.Result
		if useBody {
			raw, err := json.Marshal(map[string]any{"title": title, "bad": bad})
			if err != nil {
				ht.Fatal(err)
			}
			res = app.Request(http.MethodPost, "/b", raw)
		} else {
			q := url.Values{}
			q.Set("title", title)
			q.Set("bad", strconv.Itoa(bad))
			res = app.Request(http.MethodGet, "/q?"+q.Encode(), nil)
		}
		if len([]rune(title)) < 2 {
			loc := []string{"query", "title"}
			if useBody {
				loc = []string{"body", "title"}
			}
			hpIssues(ht, res, http.StatusUnprocessableEntity, []hpIssue{{
				loc, "string_too_short", "title must be at least 2 characters",
			}})
			if hits != 0 || strings.Contains(string(res.Body), "plain-") || strings.Contains(string(res.Body), "status-") {
				ht.Fatalf("validate ran: hits %d body %s", hits, res.Body)
			}
			return
		}
		switch bad {
		case 1:
			msg := "plain-" + title
			hpIssues(ht, res, http.StatusUnprocessableEntity, []hpIssue{{[]string{"body"}, "value_error", msg}})
			if hits != 0 {
				ht.Fatalf("handler ran")
			}
		case 2:
			msg := "status-" + title
			hpProblem(ht, res, http.StatusBadRequest, msg)
			if hits != 0 || strings.Contains(string(res.Body), "value_error") {
				ht.Fatalf("hits %d body %s", hits, res.Body)
			}
		default:
			if res.Status != http.StatusOK || hits != 1 {
				ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
			}
			var got hpPlain
			if err := res.JSON(&got); err != nil {
				ht.Fatal(err)
			}
			if got.Title != title {
				ht.Fatalf("title %q", got.Title)
			}
		}
	})
}

type hpCheckedQuery struct {
	Title string `query:"title" minLength:"2"`
	Bad   int    `query:"bad"`
}

func (in *hpCheckedQuery) Validate() error {
	switch in.Bad {
	case 1:
		return errors.New("plain-" + in.Title)
	case 2:
		return gfast.BadRequest("status-" + in.Title)
	default:
		return nil
	}
}

type hpCheckedBody struct {
	Title string `json:"title" minLength:"2"`
	Bad   int    `json:"bad"`
}

func (in *hpCheckedBody) Validate() error {
	switch in.Bad {
	case 1:
		return errors.New("plain-" + in.Title)
	case 2:
		return gfast.BadRequest("status-" + in.Title)
	default:
		return nil
	}
}

func TestPropDynamicStatusHeadersCookies(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		nilBody := hegel.Draw(ht, hegel.Booleans())
		status := hegel.Draw(ht, hegel.Integers(200, 599))
		registered := hegel.Draw(ht, hegel.Integers(200, 599))
		name := "X-" + hegel.Draw(ht, hegel.Text().Alphabet("Abcdefgh").MinSize(1).MaxSize(6))
		values := hegel.Draw(ht, hegel.Lists(hegel.Text().Alphabet("abcXYZ019 ").MinSize(1).MaxSize(6)).MinSize(1).MaxSize(3))
		cookieName := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		cookieValue := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		n := hegel.Draw(ht, hegel.Integers(-20, 20))

		app := gfast.New()
		app.Post("/made", func(ctx context.Context, in *struct{}) (*struct {
			N int `json:"n"`
		}, error) {
			res := gfast.ResponseFrom(ctx)
			res.SetStatus(status)
			for _, value := range values {
				res.Header().Add(name, value)
			}
			res.SetCookie(&http.Cookie{Name: cookieName, Value: cookieValue, Path: "/"})
			if nilBody {
				return nil, nil
			}
			return &struct {
				N int `json:"n"`
			}{N: n}, nil
		}, gfast.Status(registered))

		res := app.Request(http.MethodPost, "/made", nil)
		wantStatus := status
		if nilBody {
			wantStatus = http.StatusNoContent
		}
		if res.Status != wantStatus {
			ht.Fatalf("status %d want %d body %s", res.Status, wantStatus, res.Body)
		}
		if got := res.Header.Values(http.CanonicalHeaderKey(name)); !reflect.DeepEqual(got, values) {
			ht.Fatalf("header %v want %v", got, values)
		}
		if !strings.Contains(res.Header.Get("Set-Cookie"), cookieName+"="+cookieValue) {
			ht.Fatalf("cookie %q", res.Header.Get("Set-Cookie"))
		}
		if nilBody {
			if len(res.Body) != 0 || res.Header.Get("Content-Type") != "" {
				ht.Fatalf("nil body %q type %q", res.Body, res.Header.Get("Content-Type"))
			}
			return
		}
		if res.Header.Get("Content-Type") != "application/json" {
			ht.Fatalf("type %q", res.Header.Get("Content-Type"))
		}
		var got struct {
			N int `json:"n"`
		}
		if err := res.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.N != n {
			ht.Fatalf("n %d want %d", got.N, n)
		}
	})
}

func TestPropHEADEmptyBodyKeepsGETHeaders(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		id := hegel.Draw(ht, hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(8))
		mark := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ").MinSize(1).MaxSize(8))
		status := hegel.Draw(ht, hegel.Integers(200, 299))
		missing := hegel.Draw(ht, hegel.Booleans())

		app := gfast.New()
		app.Get("/items/{id}", func(ctx context.Context, in *struct {
			ID string `path:"id"`
			Q  string `query:"q" required:"true"`
		}) (*struct {
			ID string `json:"id"`
		}, error) {
			res := gfast.ResponseFrom(ctx)
			res.SetStatus(status)
			res.Header().Set("X-Mark", mark)
			res.SetCookie(&http.Cookie{Name: "sid", Value: in.ID, Path: "/"})
			return &struct {
				ID string `json:"id"`
			}{ID: in.ID}, nil
		})

		target := "/items/" + url.PathEscape(id)
		if !missing {
			target += "?q=1"
		}
		get := app.Request(http.MethodGet, target, nil)
		head := app.Request(http.MethodHead, target, nil)
		if head.Status != get.Status || len(head.Body) != 0 {
			ht.Fatalf("get %d head %d body %q / %q", get.Status, head.Status, get.Body, head.Body)
		}
		if head.Header.Get("Content-Type") != get.Header.Get("Content-Type") || head.Header.Get("X-Mark") != get.Header.Get("X-Mark") || head.Header.Get("Set-Cookie") != get.Header.Get("Set-Cookie") {
			ht.Fatalf("head %#v get %#v", head.Header, get.Header)
		}
		if missing {
			hpIssues(ht, get, http.StatusUnprocessableEntity, []hpIssue{{[]string{"query", "q"}, "missing", "q is required"}})
			if head.Header.Get("X-Mark") != "" || head.Header.Get("Set-Cookie") != "" {
				ht.Fatalf("handler headers on head %#v", head.Header)
			}
			return
		}
		if get.Status != status || len(get.Body) == 0 || head.Header.Get("X-Mark") != mark || !strings.Contains(head.Header.Get("Set-Cookie"), "sid="+id) {
			ht.Fatalf("get %d head mark %q cookie %q body %s", get.Status, head.Header.Get("X-Mark"), head.Header.Get("Set-Cookie"), get.Body)
		}
		var got struct {
			ID string `json:"id"`
		}
		if err := get.JSON(&got); err != nil {
			ht.Fatal(err)
		}
		if got.ID != id {
			ht.Fatalf("id %q", got.ID)
		}
	})
}

func TestPropOptionalCredentialAndAPIKeyCookie(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		kind := hegel.Draw(ht, hegel.Integers(0, 4))
		state := hegel.Draw(ht, hegel.Integers(0, 2))
		optional := hegel.Draw(ht, hegel.Booleans())
		token := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		user := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ").MinSize(1).MaxSize(6))
		pass := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ:").MaxSize(6))
		key := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(8))
		second := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ019").MinSize(1).MaxSize(6))
		schemeCase := hegel.Draw(ht, hegel.Integers(0, 2))
		badShape := hegel.Draw(ht, hegel.Integers(0, 2))

		var hits int
		app := gfast.New()
		app.Get("/bearer", func(ctx context.Context, in *struct {
			Cred gfast.Bearer `gfast:"dep=bearerAuthOptional"`
		}) (*hpCredOut, error) {
			hits++
			return &hpCredOut{Token: in.Cred.Token, Scopes: append([]string(nil), in.Cred.Scopes...)}, nil
		}, gfast.Scopes("items:read"))
		app.Get("/basic", func(ctx context.Context, in *struct {
			Cred gfast.Basic `gfast:"dep=basicAuthOptional"`
		}) (*hpCredOut, error) {
			hits++
			return &hpCredOut{User: in.Cred.Username, Pass: in.Cred.Password}, nil
		})
		app.Get("/header", func(ctx context.Context, in *struct {
			Key gfast.APIKey `gfast:"dep=apiKey_header_X_API_Key_optional"`
		}) (*hpCredOut, error) {
			hits++
			return &hpCredOut{Value: in.Key.Value, Name: in.Key.Name, In: in.Key.In}, nil
		})
		app.Get("/query", func(ctx context.Context, in *struct {
			Key gfast.APIKey `gfast:"dep=apiKey_query_api_key_optional"`
		}) (*hpCredOut, error) {
			hits++
			return &hpCredOut{Value: in.Key.Value, Name: in.Key.Name, In: in.Key.In}, nil
		})
		app.Get("/cookie", func(ctx context.Context, in *struct {
			Key gfast.APIKey `gfast:"dep=apiKey_cookie_session"`
		}) (*hpCredOut, error) {
			hits++
			return &hpCredOut{Value: in.Key.Value, Name: in.Key.Name, In: in.Key.In}, nil
		})
		app.Get("/cookie-optional", func(ctx context.Context, in *struct {
			Key gfast.APIKey `gfast:"dep=apiKey_cookie_session_optional"`
		}) (*hpCredOut, error) {
			hits++
			return &hpCredOut{Value: in.Key.Value, Name: in.Key.Name, In: in.Key.In}, nil
		})

		header := http.Header{}
		target := "/bearer"
		var want hpCredOut
		var challenge, detail string
		ok := state == 2
		switch kind {
		case 0:
			target = "/bearer"
			challenge, detail = "Bearer", "missing bearer token"
			switch state {
			case 0:
				if badShape == 1 {
					header.Set("Authorization", "Token "+token)
				}
			case 1:
				switch badShape {
				case 0:
					header.Set("Authorization", "Bearer")
				case 1:
					header.Set("Authorization", "Bearer   ")
				default:
					header.Set("Authorization", "bearer")
				}
			default:
				scheme := []string{"Bearer", "bearer", "BEARER"}[schemeCase]
				header.Set("Authorization", scheme+" "+token)
				want = hpCredOut{Token: token, Scopes: []string{"items:read"}}
			}
		case 1:
			target = "/basic"
			challenge, detail = `Basic realm="api"`, "missing basic credentials"
			switch state {
			case 0:
				if badShape == 1 {
					header.Set("Authorization", "Bearer "+token)
				}
			case 1:
				if badShape == 0 {
					header.Set("Authorization", "Basic !!!!")
				} else {
					header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user)))
				}
			default:
				scheme := []string{"Basic", "basic", "BASIC"}[schemeCase]
				header.Set("Authorization", scheme+" "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
				want = hpCredOut{User: user, Pass: pass}
			}
		case 2:
			target = "/header"
			challenge, detail = "X-API-Key", "missing api key"
			switch state {
			case 1:
				header.Add("X-API-Key", "")
				header.Add("X-API-Key", key)
			case 2:
				header.Add("X-API-Key", key)
				header.Add("X-API-Key", second)
				want = hpCredOut{Value: key, Name: "X-API-Key", In: "header"}
			}
		case 3:
			target = "/query"
			challenge, detail = "apiKey", "missing api key"
			switch state {
			case 1:
				target = "/query?api_key=&api_key=" + url.QueryEscape(key)
			case 2:
				target = "/query?api_key=" + url.QueryEscape(key) + "&api_key=" + url.QueryEscape(second)
				want = hpCredOut{Value: key, Name: "api_key", In: "query"}
			}
		default:
			challenge, detail = "apiKey", "missing api key"
			if optional {
				target = "/cookie-optional"
			} else {
				target = "/cookie"
			}
			switch state {
			case 0:
				if badShape == 1 {
					header.Set("Cookie", "other="+key)
				}
			case 1:
				header.Set("Cookie", "session=; session="+key)
			default:
				header.Set("Cookie", "session="+key+"; session="+second)
				want = hpCredOut{Value: key, Name: "session", In: "cookie"}
			}
			if state == 0 && optional {
				ok = true
			}
			if state == 0 && !optional {
				ok = false
			}
		}
		if kind < 4 && state == 0 {
			ok = true
		}

		res := app.Request(http.MethodGet, target, nil, header)
		if ok {
			if res.Status != http.StatusOK || hits != 1 {
				ht.Fatalf("status %d hits %d body %s", res.Status, hits, res.Body)
			}
			var got hpCredOut
			if err := res.JSON(&got); err != nil {
				ht.Fatal(err)
			}
			if got.Token != want.Token || got.User != want.User || got.Pass != want.Pass || got.Value != want.Value || got.Name != want.Name || got.In != want.In || !hpSameStrings(got.Scopes, want.Scopes) {
				ht.Fatalf("got %+v want %+v", got, want)
			}
			return
		}
		hpProblem(ht, res, http.StatusUnauthorized, detail)
		hpChallenge(ht, res, challenge)
		if hits != 0 {
			ht.Fatalf("handler ran")
		}
	})
}

type hpCredOut struct {
	Token  string   `json:"token"`
	User   string   `json:"user"`
	Pass   string   `json:"pass"`
	Value  string   `json:"value"`
	Name   string   `json:"name"`
	In     string   `json:"in"`
	Scopes []string `json:"scopes"`
}

func TestPropOAuth2RedirectURL(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		title := hegel.Draw(ht, hegel.Text().Alphabet("ab<>&").MaxSize(12))
		app := gfast.New(gfast.Title(title))
		res := app.Request(http.MethodGet, "/docs", nil)
		if res.Status != http.StatusOK || !strings.Contains(res.Header.Get("Content-Type"), "text/html") {
			ht.Fatalf("status %d type %q", res.Status, res.Header.Get("Content-Type"))
		}
		body := string(res.Body)
		const redirect = `oauth2RedirectUrl: window.location.origin + "/docs/oauth2-redirect"`
		if !strings.Contains(body, "<title>"+hpHTML(title)+"</title>") || !strings.Contains(body, redirect) {
			ht.Fatalf("docs page missing title or redirect: %s", body)
		}
	})
}

func TestPropOnStartBeforeFirstRequest(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		value := hegel.Draw(ht, hegel.Text().Alphabet("abcxyz").MinSize(1).MaxSize(8))
		var startHits atomic.Int32
		var handleHits atomic.Int32
		var stored atomic.Value
		app := gfast.New(gfast.OnStart(func(ctx context.Context) error {
			if ctx == nil {
				return errors.New("nil context")
			}
			startHits.Add(1)
			stored.Store(value)
			return nil
		}))
		app.Get("/v", func(ctx context.Context, in *struct{}) (*struct {
			V string `json:"v"`
		}, error) {
			handleHits.Add(1)
			v, _ := stored.Load().(string)
			return &struct {
				V string `json:"v"`
			}{V: v}, nil
		})

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			ht.Fatal(err)
		}
		defer ln.Close()
		done := make(chan error, 1)
		go func() { done <- app.Serve(ln) }()

		client := &http.Client{Timeout: time.Second}
		endpoint := "http://" + ln.Addr().String() + "/v"
		first := hpGetJSON(ht, client, endpoint)
		var got struct {
			V string `json:"v"`
		}
		if err := json.Unmarshal(first, &got); err != nil {
			ht.Fatal(err)
		}
		if got.V != value || startHits.Load() != 1 || handleHits.Load() != 1 {
			ht.Fatalf("got %q start %d handle %d", got.V, startHits.Load(), handleHits.Load())
		}
		second := hpGetJSON(ht, client, endpoint)
		got = struct {
			V string `json:"v"`
		}{}
		if err := json.Unmarshal(second, &got); err != nil {
			ht.Fatal(err)
		}
		if got.V != value || startHits.Load() != 1 || handleHits.Load() != 2 {
			ht.Fatalf("second %q start %d handle %d", got.V, startHits.Load(), handleHits.Load())
		}
		_ = ln.Close()
		select {
		case err := <-done:
			if err != nil && !strings.Contains(err.Error(), "closed") {
				ht.Fatal(err)
			}
		case <-time.After(2 * time.Second):
			ht.Fatal("Serve did not return")
		}
	})
}

func TestPropOAuth2SchemeURLs(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		clientID := hegel.Draw(ht, hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(8))
		scope := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(8))
		desc := hegel.Draw(ht, hegel.Text().Alphabet("abc ").MaxSize(12))
		withPassword := hegel.Draw(ht, hegel.Booleans())
		cfg := gfast.OAuthConfig{
			Clients: []gfast.OAuthClient{{
				ID:           clientID,
				RedirectURIs: []string{"https://app.example/cb"},
				Scopes:       []string{scope},
			}},
			Scopes: map[string]string{scope: desc},
		}
		if withPassword {
			cfg.Password = func(ctx context.Context, username, password string) (string, error) {
				return "user", nil
			}
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

		res := app.Request(http.MethodGet, "/openapi.json", nil)
		if res.Status != http.StatusOK {
			ht.Fatalf("openapi %d %s", res.Status, res.Body)
		}
		var doc struct {
			Components struct {
				SecuritySchemes map[string]struct {
					Type  string `json:"type"`
					Flows struct {
						AuthorizationCode struct {
							AuthorizationURL string            `json:"authorizationUrl"`
							TokenURL         string            `json:"tokenUrl"`
							Scopes           map[string]string `json:"scopes"`
						} `json:"authorizationCode"`
						ClientCredentials struct {
							TokenURL string            `json:"tokenUrl"`
							Scopes   map[string]string `json:"scopes"`
						} `json:"clientCredentials"`
						Password *struct {
							TokenURL string            `json:"tokenUrl"`
							Scopes   map[string]string `json:"scopes"`
						} `json:"password"`
					} `json:"flows"`
				} `json:"securitySchemes"`
			} `json:"components"`
		}
		if err := json.Unmarshal(res.Body, &doc); err != nil {
			ht.Fatal(err)
		}
		scheme, ok := doc.Components.SecuritySchemes["bearerAuth"]
		if !ok || scheme.Type != "oauth2" {
			ht.Fatalf("scheme %#v", doc.Components.SecuritySchemes)
		}
		code := scheme.Flows.AuthorizationCode
		if code.AuthorizationURL != "/oauth/authorize" || code.TokenURL != "/oauth/token" || code.Scopes[scope] != desc {
			ht.Fatalf("authorization code flow %+v", code)
		}
		if scheme.Flows.ClientCredentials.TokenURL != "/oauth/token" || scheme.Flows.ClientCredentials.Scopes[scope] != desc {
			ht.Fatalf("client credentials %+v", scheme.Flows.ClientCredentials)
		}
		if withPassword {
			if scheme.Flows.Password == nil || scheme.Flows.Password.TokenURL != "/oauth/token" || scheme.Flows.Password.Scopes[scope] != desc {
				ht.Fatalf("password flow %+v", scheme.Flows.Password)
			}
		} else if scheme.Flows.Password != nil {
			ht.Fatalf("password flow present %+v", scheme.Flows.Password)
		}
		auth := app.Request(http.MethodGet, code.AuthorizationURL, nil)
		if auth.Status != http.StatusBadRequest || !strings.Contains(string(auth.Body), "unknown client") {
			ht.Fatalf("authorize url %d %s", auth.Status, auth.Body)
		}
		token := app.Request(http.MethodPost, code.TokenURL, []byte("grant_type=authorization_code"), http.Header{
			"Content-Type": []string{"application/x-www-form-urlencoded"},
		})
		if token.Status != http.StatusUnauthorized || !strings.Contains(string(token.Body), "invalid_client") {
			ht.Fatalf("token url %d %s", token.Status, token.Body)
		}
	})
}

func TestPropOAuthCodePKCE(t *testing.T) {
	prop(t, func(ht *hegel.T) {
		clientID := hegel.Draw(ht, hegel.Text().Alphabet("abc012").MinSize(1).MaxSize(8))
		subject := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(8))
		scope := hegel.Draw(ht, hegel.Text().Alphabet("abc").MinSize(1).MaxSize(6))
		state := hegel.Draw(ht, hegel.Text().Alphabet("abcXYZ012").MinSize(1).MaxSize(8))
		verifier := hegel.Draw(ht, hegel.Text().Alphabet("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~").MinSize(43).MaxSize(48))
		bad := []byte(verifier)
		if bad[0] == 'a' {
			bad[0] = 'b'
		} else {
			bad[0] = 'a'
		}
		wrong := string(bad)
		sum := sha256.Sum256([]byte(verifier))
		challenge := base64.RawURLEncoding.EncodeToString(sum[:])
		redirectURI := "https://app.example/cb"

		app := gfast.New(gfast.OAuthServer(gfast.OAuthConfig{
			Clients: []gfast.OAuthClient{{
				ID:           clientID,
				RedirectURIs: []string{redirectURI},
				Scopes:       []string{scope},
			}},
			Scopes: map[string]string{scope: scope},
			Session: func(ctx context.Context, r *http.Request) (string, error) {
				return subject, nil
			},
		}))
		app.Get("/me", func(ctx context.Context, in *struct {
			Cred gfast.Bearer `gfast:"dep=bearerAuth"`
		}) (*struct {
			Sub string `json:"sub"`
			CID string `json:"cid"`
		}, error) {
			return &struct {
				Sub string `json:"sub"`
				CID string `json:"cid"`
			}{Sub: in.Cred.Subject, CID: in.Cred.ClientID}, nil
		})

		issue := func() string {
			q := url.Values{}
			q.Set("response_type", "code")
			q.Set("client_id", clientID)
			q.Set("redirect_uri", redirectURI)
			q.Set("code_challenge", challenge)
			q.Set("code_challenge_method", "S256")
			q.Set("state", state)
			q.Set("scope", scope)
			res := app.Request(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
			if res.Status != http.StatusFound {
				ht.Fatalf("authorize %d %s", res.Status, res.Body)
			}
			loc, err := url.Parse(res.Header.Get("Location"))
			if err != nil {
				ht.Fatal(err)
			}
			if loc.Query().Get("state") != state || loc.Query().Get("code") == "" {
				ht.Fatalf("location %q", res.Header.Get("Location"))
			}
			return loc.Query().Get("code")
		}
		exchange := func(code, verifier string) *gfast.Result {
			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("redirect_uri", redirectURI)
			form.Set("client_id", clientID)
			form.Set("code_verifier", verifier)
			return app.Request(http.MethodPost, "/oauth/token", []byte(form.Encode()), http.Header{
				"Content-Type": []string{"application/x-www-form-urlencoded"},
			})
		}

		badRes := exchange(issue(), wrong)
		if badRes.Status != http.StatusBadRequest || strings.Contains(string(badRes.Body), "access_token") {
			ht.Fatalf("wrong verifier %d %s", badRes.Status, badRes.Body)
		}
		var oauthErr struct {
			Error string `json:"error"`
		}
		if err := badRes.JSON(&oauthErr); err != nil || oauthErr.Error != "invalid_grant" {
			ht.Fatalf("wrong verifier body %s err %v", badRes.Body, err)
		}

		goodRes := exchange(issue(), verifier)
		if goodRes.Status != http.StatusOK {
			ht.Fatalf("token %d %s", goodRes.Status, goodRes.Body)
		}
		var issued struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
		}
		if err := goodRes.JSON(&issued); err != nil {
			ht.Fatal(err)
		}
		if issued.AccessToken == "" || issued.TokenType != "Bearer" {
			ht.Fatalf("issued %+v", issued)
		}
		me := app.Request(http.MethodGet, "/me", nil, http.Header{"Authorization": []string{"Bearer " + issued.AccessToken}})
		if me.Status != http.StatusOK {
			ht.Fatalf("me %d %s", me.Status, me.Body)
		}
		var who struct {
			Sub string `json:"sub"`
			CID string `json:"cid"`
		}
		if err := me.JSON(&who); err != nil {
			ht.Fatal(err)
		}
		if who.Sub != subject || who.CID != clientID {
			ht.Fatalf("who %+v subject %s client %s", who, subject, clientID)
		}
	})
}

func hpGetJSON(ht *hegel.T, client *http.Client, endpoint string) []byte {
	ht.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var last error
	for {
		res, err := client.Get(endpoint)
		if err == nil {
			body, readErr := io.ReadAll(res.Body)
			res.Body.Close()
			if readErr != nil {
				ht.Fatal(readErr)
			}
			if res.StatusCode != http.StatusOK {
				ht.Fatalf("status %d body %s", res.StatusCode, body)
			}
			return body
		}
		last = err
		if time.Now().After(deadline) {
			ht.Fatal(last)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
