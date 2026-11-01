package gfast

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"net/url"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	jsonv2 "encoding/json/v2"
)

type inputPlan struct {
	params     []paramField
	body       []int
	bodyTag    reflect.StructTag
	bodyType   reflect.Type
	hasBody    bool
	flat       bool
	allowExtra bool
	hasForm    bool
	hasFile    bool
}

type paramField struct {
	index []int
	loc   string
	name  string
	typ   reflect.Type
	tag   reflect.StructTag
}

var (
	fileHeaderType = reflect.TypeFor[multipart.FileHeader]()
	timeType       = reflect.TypeFor[time.Time]()
	uuidPattern    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	patternMu      sync.Mutex
	patternCache   = map[string]*regexp.Regexp{}
)

func planInput(t reflect.Type) inputPlan {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		panic("gfast: handler input must be a struct")
	}
	walkTags(t, 0)
	var plan inputPlan
	walkInput(t, nil, &plan)
	if !plan.hasBody && hasJSONFields(t) {
		plan.flat = true
		plan.allowExtra = typeAllowsExtra(t)
	}
	if (plan.hasBody || plan.flat) && (plan.hasForm || plan.hasFile) {
		panic("gfast: JSON body and form or file fields cannot share one request")
	}
	return plan
}

func walkInput(t reflect.Type, prefix []int, plan *inputPlan) {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "RawBody" {
			continue
		}
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		index := append(append([]int{}, prefix...), i)
		if f.Name == "Body" {
			plan.body = index
			plan.hasBody = true
			plan.bodyTag = f.Tag
			plan.bodyType = f.Type
			plan.allowExtra = allowsExtra(f, f.Type)
			continue
		}
		if _, ok := depTag(f); ok {
			continue
		}
		if loc, name, ok := paramTag(f); ok {
			plan.params = append(plan.params, paramField{index: index, loc: loc, name: name, typ: f.Type, tag: f.Tag})
			if loc == "form" {
				plan.hasForm = true
			}
			if loc == "file" {
				plan.hasFile = true
			}
			continue
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && ft != timeType && ft != fileHeaderType {
			walkInput(f.Type, index, plan)
		}
	}
}

func paramTag(f reflect.StructField) (string, string, bool) {
	for _, loc := range []string{"path", "query", "header", "cookie", "form", "file"} {
		name := f.Tag.Get(loc)
		if name == "" {
			continue
		}
		if name == "-" {
			return "", "", false
		}
		return loc, name, true
	}
	return "", "", false
}

func hasJSONFields(t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		if f.Name == "Body" || f.Name == "RawBody" {
			continue
		}
		if _, ok := depTag(f); ok {
			continue
		}
		if _, _, ok := paramTag(f); ok {
			continue
		}
		if f.Anonymous {
			if hasJSONFields(f.Type) {
				return true
			}
			continue
		}
		if isJSONField(f) {
			return true
		}
	}
	return false
}

func allowsExtra(f reflect.StructField, typ reflect.Type) bool {
	return f.Tag.Get("extra") == "allow" || typeAllowsExtra(typ)
}

func typeAllowsExtra(t reflect.Type) bool {
	if t == nil {
		return false
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Tag.Get("extra") == "allow" {
			return true
		}
		if f.Anonymous && typeAllowsExtra(f.Type) {
			return true
		}
	}
	return false
}

func bindInput(r *http.Request, dst reflect.Value, plan inputPlan) error {
	// Defaults are written first. JSON objects merge into that value, so a missing key keeps its default.
	if err := applyDefaults(dst, 0); err != nil {
		return err
	}
	if err := parseForm(r, plan); err != nil {
		return err
	}
	var issues []fieldIssue
	for _, p := range plan.params {
		field := fieldByIndexAlloc(dst, p.index)
		if p.loc == "file" {
			got, err := bindFile(r, p, field)
			if err != nil {
				return err
			}
			issues = append(issues, got...)
			continue
		}
		vals, ok, err := paramValues(r, p)
		if err != nil {
			return err
		}
		if !ok {
			if p.loc == "path" {
				return BadRequest("missing path parameter " + p.name)
			}
			if p.tag.Get("required") == "true" && !hasScalarDefault(p.tag, p.typ) {
				issues = append(issues, fieldIssue{Loc: paramLoc(p), Type: "missing", Msg: p.name + " is required"})
			}
			continue
		}
		if err := assignValues(field, vals); err != nil {
			return BadRequest(p.name + ": " + err.Error())
		}
	}
	if plan.hasBody || plan.flat {
		if err := bindJSON(r, dst, plan); err != nil {
			return err
		}
	}
	// When the body is one Body field, sibling json tags are not part of that body.
	issues = append(issues, validateStruct(dst, []string{"body"}, plan.hasBody)...)
	if len(issues) > 0 {
		return invalid(issues)
	}
	return runValidates(dst, plan)
}

func paramLoc(p paramField) []string {
	switch p.loc {
	case "form":
		return []string{"form", p.name}
	case "file":
		return []string{"file", p.name}
	default:
		return []string{p.loc, p.name}
	}
}

func hasScalarDefault(tag reflect.StructTag, typ reflect.Type) bool {
	_, ok := tag.Lookup("default")
	return ok && isScalarType(typ)
}

func parseForm(r *http.Request, plan inputPlan) error {
	if !plan.hasForm && !plan.hasFile {
		return nil
	}
	media := ""
	if ct := r.Header.Get("Content-Type"); ct != "" {
		parsed, _, err := mime.ParseMediaType(ct)
		if err != nil {
			return BadRequest("invalid content type")
		}
		media = strings.ToLower(parsed)
	}
	switch {
	case strings.HasPrefix(media, "multipart/"):
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return BadRequest(err.Error())
		}
		return nil
	case media == "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return BadRequest(err.Error())
		}
		return nil
	case r.Body == nil || r.ContentLength == 0:
		return nil
	default:
		return BadRequest("expected form body")
	}
}

func paramValues(r *http.Request, p paramField) ([]string, bool, error) {
	switch p.loc {
	case "path":
		v := r.PathValue(p.name)
		if v == "" {
			return nil, false, nil
		}
		return []string{v}, true, nil
	case "query":
		vs := r.URL.Query()[p.name]
		if len(vs) == 0 {
			return nil, false, nil
		}
		return vs, true, nil
	case "header":
		vs := r.Header.Values(p.name)
		if len(vs) == 0 {
			return nil, false, nil
		}
		return vs, true, nil
	case "cookie":
		c, err := r.Cookie(p.name)
		if err == http.ErrNoCookie {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		return []string{c.Value}, true, nil
	case "form":
		vs := r.PostForm[p.name]
		if len(vs) == 0 {
			return nil, false, nil
		}
		return vs, true, nil
	default:
		return nil, false, BadRequest("unsupported parameter location")
	}
}

func assignValues(field reflect.Value, vals []string) error {
	if field.Kind() == reflect.Pointer && field.Type().Elem().Kind() == reflect.Slice {
		field.Set(reflect.New(field.Type().Elem()))
		field = field.Elem()
	}
	if field.Kind() == reflect.Slice {
		return setSlice(field, vals)
	}
	if len(vals) == 0 {
		return nil
	}
	return setScalar(field, vals[0])
}

func setSlice(field reflect.Value, vals []string) error {
	out := reflect.MakeSlice(field.Type(), len(vals), len(vals))
	for i, raw := range vals {
		if err := setScalar(out.Index(i), raw); err != nil {
			return err
		}
	}
	field.Set(out)
	return nil
}

func bindFile(r *http.Request, p paramField, field reflect.Value) ([]fieldIssue, error) {
	var hs []*multipart.FileHeader
	if r.MultipartForm != nil {
		hs = r.MultipartForm.File[p.name]
	}
	if len(hs) == 0 {
		if p.tag.Get("required") == "true" {
			return []fieldIssue{{Loc: []string{"file", p.name}, Type: "missing", Msg: p.name + " is required"}}, nil
		}
		return nil, nil
	}
	if err := setFile(field, hs); err != nil {
		return nil, err
	}
	return nil, nil
}

func setFile(field reflect.Value, hs []*multipart.FileHeader) error {
	if field.Kind() == reflect.Pointer {
		elem := field.Type().Elem()
		if elem == fileHeaderType {
			field.Set(reflect.ValueOf(hs[0]))
			return nil
		}
		if elem.Kind() == reflect.Slice {
			inner := reflect.New(elem)
			if err := setFile(inner.Elem(), hs); err != nil {
				return err
			}
			field.Set(inner)
			return nil
		}
		return BadRequest("cannot bind file to " + field.Type().String())
	}
	if field.Type() == fileHeaderType {
		field.Set(reflect.ValueOf(*hs[0]))
		return nil
	}
	if field.Kind() == reflect.Slice && field.Type().Elem() == fileHeaderType {
		out := reflect.MakeSlice(field.Type(), len(hs), len(hs))
		for i, h := range hs {
			out.Index(i).Set(reflect.ValueOf(*h))
		}
		field.Set(out)
		return nil
	}
	if field.Kind() == reflect.Slice && field.Type().Elem() == reflect.PointerTo(fileHeaderType) {
		out := reflect.MakeSlice(field.Type(), len(hs), len(hs))
		for i, h := range hs {
			out.Index(i).Set(reflect.ValueOf(h))
		}
		field.Set(out)
		return nil
	}
	return BadRequest("cannot bind file to " + field.Type().String())
}

func bindJSON(r *http.Request, dst reflect.Value, plan inputPlan) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	var target any
	if plan.hasBody {
		field := fieldByIndexAlloc(dst, plan.body)
		target = field.Addr().Interface()
	} else {
		target = dst.Addr().Interface()
	}
	var opts []jsonv2.Options
	if !plan.allowExtra {
		opts = append(opts, jsonv2.RejectUnknownMembers(true))
	}
	if err := jsonv2.UnmarshalRead(r.Body, target, opts...); err != nil && err != io.EOF {
		return BadRequest(err.Error())
	}
	return nil
}

func setScalar(field reflect.Value, raw string) error {
	if field.Kind() == reflect.Pointer {
		field.Set(reflect.New(field.Type().Elem()))
		field = field.Elem()
	}
	switch field.Kind() {
	case reflect.String:
		field.SetString(raw)
	case reflect.Bool:
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return err
		}
		field.SetBool(v)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, err := strconv.ParseInt(raw, 10, field.Type().Bits())
		if err != nil {
			return err
		}
		field.SetInt(v)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v, err := strconv.ParseUint(raw, 10, field.Type().Bits())
		if err != nil {
			return err
		}
		field.SetUint(v)
	case reflect.Float32, reflect.Float64:
		v, err := strconv.ParseFloat(raw, field.Type().Bits())
		if err != nil {
			return err
		}
		field.SetFloat(v)
	default:
		return fmt.Errorf("cannot bind %s", field.Type())
	}
	return nil
}

func applyDefaults(v reflect.Value, depth int) error {
	if depth > 32 || !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		return applyDefaults(v.Elem(), depth+1)
	}
	if v.Kind() != reflect.Struct || v.Type() == fileHeaderType || v.Type() == timeType {
		return nil
	}
	for i := 0; i < v.NumField(); i++ {
		f := v.Type().Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		if f.Name == "RawBody" {
			continue
		}
		if _, ok := depTag(f); ok {
			continue
		}
		fv := v.Field(i)
		if fv.Kind() == reflect.Pointer && fv.IsNil() && fv.Type().Elem().Kind() == reflect.Struct && structHasDefault(fv.Type().Elem(), 0) {
			fv.Set(reflect.New(fv.Type().Elem()))
		}
		if raw, ok := f.Tag.Lookup("default"); ok && isScalarType(f.Type) {
			if err := setScalar(fv, raw); err != nil {
				return BadRequest(f.Name + ": " + err.Error())
			}
			continue
		}
		if err := applyDefaults(fv, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func structHasDefault(t reflect.Type, depth int) bool {
	if depth > 8 {
		return false
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		if _, ok := f.Tag.Lookup("default"); ok {
			return true
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && structHasDefault(ft, depth+1) {
			return true
		}
	}
	return false
}

func invalid(issues []fieldIssue) error {
	if len(issues) == 0 {
		return nil
	}
	parts := make([]string, len(issues))
	for i, issue := range issues {
		parts[i] = issue.Msg
	}
	return &httpError{status: http.StatusUnprocessableEntity, detail: strings.Join(parts, "; "), errors: issues}
}

func runValidates(dst reflect.Value, plan inputPlan) error {
	if err := runValidate(dst); err != nil {
		return err
	}
	if plan.hasBody {
		if err := runValidate(fieldByIndexAlloc(dst, plan.body)); err != nil {
			return err
		}
	}
	return nil
}

// callValidate runs Validate() error when v has that method.
// It returns the method's error unchanged.
func callValidate(v reflect.Value) error {
	if !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return nil
	}
	target := v
	if v.Kind() != reflect.Pointer {
		if !v.CanAddr() {
			return nil
		}
		target = v.Addr()
	}
	method := target.MethodByName("Validate")
	if !method.IsValid() {
		return nil
	}
	mt := method.Type()
	if mt.NumIn() != 0 || mt.NumOut() != 1 || !mt.Out(0).AssignableTo(reflect.TypeFor[error]()) {
		return nil
	}
	out := method.Call(nil)
	if out[0].IsNil() {
		return nil
	}
	return out[0].Interface().(error)
}

func runValidate(v reflect.Value) error {
	err := callValidate(v)
	if err == nil {
		return nil
	}
	var se StatusError
	if errors.As(err, &se) {
		return err
	}
	return invalid([]fieldIssue{{Loc: []string{"body"}, Type: "value_error", Msg: err.Error()}})
}

func validateStruct(v reflect.Value, prefix []string, bodyOnly bool) []fieldIssue {
	if !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct || v.Type() == fileHeaderType || v.Type() == timeType {
		return nil
	}
	var issues []fieldIssue
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		if f.Name == "RawBody" {
			continue
		}
		if _, ok := depTag(f); ok {
			continue
		}
		// Json-tagged siblings are not decoded when the request has a Body field.
		if bodyOnly && f.Name != "Body" && isJSONField(f) {
			continue
		}
		fv := v.Field(i)
		loc := fieldLoc(prefix, f)
		issues = append(issues, checkField(f, fv, loc)...)
		if _, _, isParam := paramTag(f); isParam {
			continue
		}
		childPrefix := prefix
		childBodyOnly := bodyOnly
		if f.Name == "Body" {
			childPrefix = []string{"body"}
			childBodyOnly = false
		} else if !f.Anonymous && isJSONField(f) {
			childPrefix = loc
			childBodyOnly = false
		}
		issues = append(issues, walkValue(fv, childPrefix, childBodyOnly)...)
	}
	return issues
}

func walkValue(v reflect.Value, prefix []string, bodyOnly bool) []fieldIssue {
	if !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Struct:
		return validateStruct(v, prefix, bodyOnly)
	case reflect.Slice, reflect.Array:
		return walkSlice(v, prefix, bodyOnly)
	default:
		return nil
	}
}

func walkSlice(v reflect.Value, prefix []string, bodyOnly bool) []fieldIssue {
	et := v.Type().Elem()
	if et.Kind() == reflect.Pointer {
		et = et.Elem()
	}
	if et.Kind() != reflect.Struct || et == fileHeaderType || et == timeType {
		return nil
	}
	var issues []fieldIssue
	for i := 0; i < v.Len(); i++ {
		issues = append(issues, walkValue(v.Index(i), appendLoc(prefix, strconv.Itoa(i)), bodyOnly)...)
	}
	return issues
}

func fieldLoc(prefix []string, f reflect.StructField) []string {
	if loc, name, ok := paramTag(f); ok {
		return []string{locKind(loc), name}
	}
	if f.Name == "Body" {
		return []string{"body"}
	}
	if f.Anonymous {
		return prefix
	}
	if name, ok := jsonFieldName(f); ok {
		return appendLoc(prefix, name)
	}
	ft := f.Type
	if ft.Kind() == reflect.Pointer {
		ft = ft.Elem()
	}
	if ft.Kind() == reflect.Struct && ft != timeType && ft != fileHeaderType {
		return prefix
	}
	return appendLoc(prefix, f.Name)
}

func locKind(loc string) string {
	switch loc {
	case "form":
		return "form"
	case "file":
		return "file"
	default:
		return loc
	}
}

func appendLoc(prefix []string, parts ...string) []string {
	loc := make([]string, 0, len(prefix)+len(parts))
	loc = append(loc, prefix...)
	return append(loc, parts...)
}

func fieldLabel(loc []string, f reflect.StructField) string {
	for i := len(loc) - 1; i >= 0; i-- {
		part := loc[i]
		switch part {
		case "body", "query", "header", "cookie", "path", "form", "file":
			continue
		}
		if _, err := strconv.Atoi(part); err == nil {
			continue
		}
		return part
	}
	return jsonName(f)
}

func checkField(f reflect.StructField, v reflect.Value, loc []string) []fieldIssue {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() == reflect.Slice || v.Kind() == reflect.Array {
		issues := countItems(f, v, loc)
		et := v.Type().Elem()
		if et.Kind() == reflect.Pointer {
			et = et.Elem()
		}
		if isScalarKind(et.Kind()) {
			for i := 0; i < v.Len(); i++ {
				issues = append(issues, scalarChecks(f, v.Index(i), appendLoc(loc, strconv.Itoa(i)))...)
			}
		}
		return issues
	}
	return scalarChecks(f, v, loc)
}

func countItems(f reflect.StructField, v reflect.Value, loc []string) []fieldIssue {
	name := fieldLabel(loc, f)
	var issues []fieldIssue
	if raw := f.Tag.Get("minItems"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && v.Len() < n {
			issues = append(issues, fieldIssue{Loc: loc, Type: "too_short", Msg: name + " must have at least " + raw + " items"})
		}
	}
	if raw := f.Tag.Get("maxItems"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && v.Len() > n {
			issues = append(issues, fieldIssue{Loc: loc, Type: "too_long", Msg: name + " must have at most " + raw + " items"})
		}
	}
	return issues
}

func scalarChecks(f reflect.StructField, v reflect.Value, loc []string) []fieldIssue {
	if !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	name := fieldLabel(loc, f)
	var issues []fieldIssue
	if v.Kind() == reflect.String {
		issues = append(issues, stringChecks(f, v.String(), loc, name)...)
	}
	issues = append(issues, numberChecks(f, v, loc, name)...)
	if raw := f.Tag.Get("enum"); raw != "" && isScalarKind(v.Kind()) && !enumMatch(v, raw) {
		issues = append(issues, fieldIssue{Loc: loc, Type: "enum", Msg: name + " must be one of " + strings.Join(splitCSV(raw), ", ")})
	}
	return issues
}

func stringChecks(f reflect.StructField, value string, loc []string, name string) []fieldIssue {
	var issues []fieldIssue
	n := utf8.RuneCountInString(value)
	if raw := f.Tag.Get("minLength"); raw != "" {
		if min, err := strconv.Atoi(raw); err == nil && n < min {
			issues = append(issues, fieldIssue{Loc: loc, Type: "string_too_short", Msg: name + " must be at least " + raw + " characters"})
		}
	}
	if raw := f.Tag.Get("maxLength"); raw != "" {
		if max, err := strconv.Atoi(raw); err == nil && n > max {
			issues = append(issues, fieldIssue{Loc: loc, Type: "string_too_long", Msg: name + " must be at most " + raw + " characters"})
		}
	}
	if raw := f.Tag.Get("pattern"); raw != "" {
		if re := cachedPattern(raw); re != nil && !re.MatchString(value) {
			issues = append(issues, fieldIssue{Loc: loc, Type: "string_pattern_mismatch", Msg: name + " must match pattern " + raw})
		}
	}
	if raw := f.Tag.Get("format"); raw != "" && !validFormat(raw, value) {
		issues = append(issues, fieldIssue{Loc: loc, Type: strings.ReplaceAll(raw, "-", "_"), Msg: name + " must be a valid " + raw})
	}
	return issues
}

func numberChecks(f reflect.StructField, v reflect.Value, loc []string, name string) []fieldIssue {
	var issues []fieldIssue
	checks := []struct {
		key  string
		typ  string
		pass func(int) bool
		text string
	}{
		{"gt", "greater_than", func(cmp int) bool { return cmp > 0 }, "must be greater than "},
		{"ge", "greater_than_equal", func(cmp int) bool { return cmp >= 0 }, "must be greater than or equal to "},
		{"lt", "less_than", func(cmp int) bool { return cmp < 0 }, "must be less than "},
		{"le", "less_than_equal", func(cmp int) bool { return cmp <= 0 }, "must be less than or equal to "},
	}
	for _, check := range checks {
		raw := f.Tag.Get(check.key)
		if raw == "" {
			continue
		}
		cmp, ok := numericCmp(v, raw)
		if ok && !check.pass(cmp) {
			issues = append(issues, fieldIssue{Loc: loc, Type: check.typ, Msg: name + " " + check.text + raw})
		}
	}
	return issues
}

func numericCmp(v reflect.Value, raw string) (int, bool) {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		bound, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return 0, false
		}
		n := v.Int()
		switch {
		case n < bound:
			return -1, true
		case n > bound:
			return 1, true
		default:
			return 0, true
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		bound, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return 0, false
		}
		n := v.Uint()
		switch {
		case n < bound:
			return -1, true
		case n > bound:
			return 1, true
		default:
			return 0, true
		}
	case reflect.Float32, reflect.Float64:
		bound, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return 0, false
		}
		n := v.Float()
		switch {
		case n < bound:
			return -1, true
		case n > bound:
			return 1, true
		default:
			return 0, true
		}
	default:
		return 0, false
	}
}

func enumMatch(v reflect.Value, raw string) bool {
	for _, part := range splitCSV(raw) {
		switch v.Kind() {
		case reflect.String:
			if v.String() == part {
				return true
			}
		case reflect.Bool:
			b, err := strconv.ParseBool(part)
			if err == nil && v.Bool() == b {
				return true
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			n, err := strconv.ParseInt(part, 10, 64)
			if err == nil && v.Int() == n {
				return true
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			n, err := strconv.ParseUint(part, 10, 64)
			if err == nil && v.Uint() == n {
				return true
			}
		case reflect.Float32, reflect.Float64:
			n, err := strconv.ParseFloat(part, 64)
			if err == nil && v.Float() == n {
				return true
			}
		}
	}
	return false
}

func validFormat(format, value string) bool {
	switch format {
	case "date-time":
		_, err := time.Parse(time.RFC3339, value)
		return err == nil
	case "uuid":
		return uuidPattern.MatchString(value)
	case "email":
		addr, err := mail.ParseAddress(value)
		return err == nil && addr.Address == value
	case "uri":
		parsed, err := url.Parse(value)
		return err == nil && parsed.Scheme != "" && !strings.ContainsAny(value, " \t\r\n")
	default:
		return true
	}
}

func cachedPattern(raw string) *regexp.Regexp {
	patternMu.Lock()
	defer patternMu.Unlock()
	if re, ok := patternCache[raw]; ok {
		return re
	}
	re, err := regexp.Compile(raw)
	if err != nil {
		return nil
	}
	patternCache[raw] = re
	return re
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}
	return parts
}

func walkTags(t reflect.Type, depth int) {
	if depth > 32 {
		return
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || t == fileHeaderType || t == timeType {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		checkConstraintSyntax(f)
		walkTags(f.Type, depth+1)
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Slice || ft.Kind() == reflect.Array {
			walkTags(ft.Elem(), depth+1)
		}
	}
}

func checkConstraintSyntax(f reflect.StructField) {
	base := f.Type
	if base.Kind() == reflect.Pointer {
		base = base.Elem()
	}
	elem := constraintType(f.Type)
	for _, key := range []string{"gt", "ge", "lt", "le"} {
		raw := f.Tag.Get(key)
		if raw == "" {
			continue
		}
		if !isNumeric(elem.Kind()) {
			panic(fmt.Sprintf("gfast: field %s: %s is only valid on numbers", f.Name, key))
		}
		if err := parseBound(elem, raw); err != nil {
			panic(fmt.Sprintf("gfast: field %s: %s: %v", f.Name, key, err))
		}
	}
	if raw := f.Tag.Get("pattern"); raw != "" {
		if elem.Kind() != reflect.String {
			panic(fmt.Sprintf("gfast: field %s: pattern is only valid on strings", f.Name))
		}
		if _, err := regexp.Compile(raw); err != nil {
			panic(fmt.Sprintf("gfast: field %s: invalid pattern: %v", f.Name, err))
		}
	}
	for _, key := range []string{"minItems", "maxItems"} {
		raw := f.Tag.Get(key)
		if raw == "" {
			continue
		}
		if base.Kind() != reflect.Slice && base.Kind() != reflect.Array {
			panic(fmt.Sprintf("gfast: field %s: %s is only valid on slices", f.Name, key))
		}
		if _, err := strconv.Atoi(raw); err != nil {
			panic(fmt.Sprintf("gfast: field %s: %s: %v", f.Name, key, err))
		}
	}
	for _, key := range []string{"minLength", "maxLength"} {
		raw := f.Tag.Get(key)
		if raw == "" {
			continue
		}
		if _, err := strconv.Atoi(raw); err != nil {
			panic(fmt.Sprintf("gfast: field %s: %s: %v", f.Name, key, err))
		}
	}
	if raw := f.Tag.Get("enum"); raw != "" {
		if !isScalarKind(elem.Kind()) {
			panic(fmt.Sprintf("gfast: field %s: enum is only valid on scalars", f.Name))
		}
		for _, part := range splitCSV(raw) {
			if err := setScalar(reflect.New(elem).Elem(), part); err != nil {
				panic(fmt.Sprintf("gfast: field %s: enum: %v", f.Name, err))
			}
		}
	}
	if raw, ok := f.Tag.Lookup("default"); ok {
		if !isScalarType(f.Type) {
			panic(fmt.Sprintf("gfast: field %s: default is only valid on scalars", f.Name))
		}
		if err := setScalar(reflect.New(f.Type).Elem(), raw); err != nil {
			panic(fmt.Sprintf("gfast: field %s: default: %v", f.Name, err))
		}
	}
}

func constraintType(t reflect.Type) reflect.Type {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
	}
	return t
}

func parseBound(t reflect.Type, raw string) error {
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		_, err := strconv.ParseInt(raw, 10, t.Bits())
		return err
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		_, err := strconv.ParseUint(raw, 10, t.Bits())
		return err
	case reflect.Float32, reflect.Float64:
		_, err := strconv.ParseFloat(raw, t.Bits())
		return err
	default:
		return fmt.Errorf("not a number")
	}
}

func isScalarType(t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return isScalarKind(t.Kind())
}

func isScalarKind(k reflect.Kind) bool {
	switch k {
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

func isNumeric(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

func jsonName(f reflect.StructField) string {
	if name, ok := jsonFieldName(f); ok {
		return name
	}
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	if name == "-" {
		return "-"
	}
	return f.Name
}

// jsonFieldName reports the JSON object name when the field is part of a JSON body.
// An empty name in `json:",option"` keeps the Go field name. `json:"-"` is not a body field.
func jsonFieldName(f reflect.StructField) (string, bool) {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return "", false
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return "", false
	}
	if name == "" {
		name = f.Name
	}
	return name, true
}

func isJSONField(f reflect.StructField) bool {
	_, ok := jsonFieldName(f)
	return ok
}
