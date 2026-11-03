package gfast

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"unicode"
	"unsafe"
)

// Dependency is a value produced by Dep, Bearer, Basic, or an API key helper.
// Optional credential readers are separate dependencies from the required ones.
type Dependency interface {
	dependency() *depEntry
}

// provider is the concrete dependency value. Identity is this value, not the
// return type, so two providers may return the same type.
type provider struct {
	entry *depEntry
}

func (p provider) dependency() *depEntry {
	if p.entry == nil {
		panic("gfast: nil dependency")
	}
	return p.entry
}

type depEntry struct {
	id     int
	name   string
	fn     reflect.Value
	out    reflect.Type
	params []depParam
	scheme *namedScheme

	mu    sync.Mutex
	bound bool
}

type depParam struct {
	dep *depEntry
}

type namedScheme struct {
	name        string
	typ         string
	scheme      string
	in          string
	param       string
	description string
}

type override struct {
	fn     reflect.Value
	params []depParam
}

var (
	regMu               sync.Mutex
	regByName           = map[string]*depEntry{}
	regByID             = map[int]*depEntry{}
	regSeq              int
	bearerEntry         *depEntry
	bearerOptionalEntry *depEntry
	basicEntry          *depEntry
	basicOptionalEntry  *depEntry
)

var (
	contextType = reflect.TypeOf((*context.Context)(nil)).Elem()
	errorType   = reflect.TypeOf((*error)(nil)).Elem()
)

func init() {
	bearerEntry = addDep("bearerAuth", readBearer, bearerScheme())
	bearerOptionalEntry = addDep("bearerAuthOptional", readBearerOptional, bearerScheme())
	basicEntry = addDep("basicAuth", readBasic, basicScheme())
	basicOptionalEntry = addDep("basicAuthOptional", readBasicOptional, basicScheme())
}

// Dep registers a provider under name.
// fn is func(ctx context.Context, deps...) (T, error). Each extra parameter
// is another dependency, matched by type. A type with more than one provider
// cannot be taken as a parameter; the handler field tag selects it by name.
func Dep(name string, fn any) Dependency {
	if strings.TrimSpace(name) == "" {
		panic("gfast: dependency name is empty")
	}
	v := reflect.ValueOf(fn)
	validateFn(name, v, nil)
	return provider{entry: addDep(name, fn, nil)}
}

func newAPIKey(in, headerName string, opts []AuthOption) Dependency {
	if strings.TrimSpace(headerName) == "" {
		panic("gfast: api key name is empty")
	}
	scheme := apiKeyScheme(in, headerName)
	name := scheme.name
	optional := authOptional(opts)
	if optional {
		name += "_optional"
	}
	// Same location, name, and options are the reader already stored under
	// name. A different provider under that name still panics.
	entry := insertDep(name, reflect.ValueOf(readAPIKey(in, headerName, optional)), scheme, true)
	return provider{entry: entry}
}

func addDep(name string, fn any, scheme *namedScheme) *depEntry {
	return insertDep(name, reflect.ValueOf(fn), scheme, false)
}

func insertDep(name string, v reflect.Value, scheme *namedScheme, reuse bool) *depEntry {
	regMu.Lock()
	defer regMu.Unlock()
	if e, ok := regByName[name]; ok {
		if reuse && sameAPIKey(e, scheme) {
			return e
		}
		panic("gfast: duplicate dependency " + name)
	}
	regSeq++
	e := &depEntry{
		id:     regSeq,
		name:   name,
		fn:     v,
		out:    v.Type().Out(0),
		scheme: scheme,
	}
	regByName[name] = e
	regByID[e.id] = e
	return e
}

// sameAPIKey reports whether e is the reader described by scheme.
// A sanitized name collision has a different param and must not match.
func sameAPIKey(e *depEntry, scheme *namedScheme) bool {
	if e == nil || e.scheme == nil || scheme == nil {
		return false
	}
	return e.scheme.typ == scheme.typ &&
		e.scheme.scheme == scheme.scheme &&
		e.scheme.in == scheme.in &&
		e.scheme.param == scheme.param &&
		e.scheme.name == scheme.name &&
		e.scheme.description == scheme.description
}

func validateFn(name string, v reflect.Value, want reflect.Type) {
	if v.Kind() != reflect.Func {
		panic(fmt.Sprintf("gfast: dependency %s is not a function", name))
	}
	t := v.Type()
	if t.IsVariadic() || t.NumIn() < 1 || t.In(0) != contextType || t.NumOut() != 2 || t.Out(1) != errorType {
		panic(fmt.Sprintf("gfast: dependency %s must be func(context.Context, ...) (T, error)", name))
	}
	if want != nil && !t.Out(0).AssignableTo(want) {
		panic(fmt.Sprintf("gfast: dependency %s returns %s, want %s", name, t.Out(0), want))
	}
}

func (e *depEntry) bind(stack []string) {
	if contains(stack, e.name) {
		panic("gfast: dependency cycle: " + strings.Join(append(stack, e.name), " -> "))
	}
	e.mu.Lock()
	if e.bound {
		e.mu.Unlock()
		return
	}
	fn := e.fn
	e.mu.Unlock()

	params := makeParams(e.name, fn, append(stack, e.name))

	e.mu.Lock()
	if !e.bound {
		e.params = params
		e.bound = true
	}
	e.mu.Unlock()
}

func makeParams(owner string, fn reflect.Value, stack []string) []depParam {
	t := fn.Type()
	params := make([]depParam, 0, t.NumIn()-1)
	for i := 1; i < t.NumIn(); i++ {
		dep := lookupParam(owner, t.In(i))
		dep.bind(stack)
		params = append(params, depParam{dep: dep})
	}
	return params
}

func lookupParam(owner string, t reflect.Type) *depEntry {
	if t == bearerEntry.out {
		return bearerEntry
	}
	if t == basicEntry.out {
		return basicEntry
	}
	regMu.Lock()
	defer regMu.Unlock()
	var found *depEntry
	for _, e := range regByID {
		if e.out != t || e == bearerEntry || e == basicEntry {
			continue
		}
		if found != nil {
			panic(fmt.Sprintf("gfast: dependency %s: %s has more than one provider; request it with a gfast:\"dep=Name\" field", owner, t))
		}
		found = e
	}
	if found == nil {
		panic(fmt.Sprintf("gfast: dependency %s: no provider for %s", owner, t))
	}
	return found
}

func lookupName(name string) *depEntry {
	regMu.Lock()
	defer regMu.Unlock()
	e, ok := regByName[name]
	if !ok {
		panic("gfast: unknown dependency " + name)
	}
	return e
}

func (e *depEntry) paramsOf() []depParam {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]depParam(nil), e.params...)
}

func (e *depEntry) collectSchemes(seen map[int]struct{}, out map[string]*namedScheme) {
	if _, ok := seen[e.id]; ok {
		return
	}
	seen[e.id] = struct{}{}
	if e.scheme != nil {
		out[e.scheme.name] = e.scheme
	}
	for _, p := range e.paramsOf() {
		p.dep.collectSchemes(seen, out)
	}
}

type depField struct {
	index []int
	dep   *depEntry
}

func collectDepFields(t reflect.Type) []depField {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	var fields []depField
	walkDepFields(t, nil, &fields, map[reflect.Type]struct{}{})
	return fields
}

func walkDepFields(t reflect.Type, prefix []int, fields *[]depField, active map[reflect.Type]struct{}) {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || t == timeType || t == fileHeaderType {
		return
	}
	// active is the path currently being walked. A repeat is a cycle.
	// A type used again after this call returns is a separate branch.
	if _, seen := active[t]; seen {
		panic("gfast: recursive type " + t.String())
	}
	active[t] = struct{}{}
	defer delete(active, t)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "Body" || f.Name == "RawBody" {
			continue
		}
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		index := append(append([]int{}, prefix...), i)
		if name, ok := depTag(f); ok {
			if name == "" {
				name = f.Name
			}
			entry := lookupName(name)
			if !assignable(entry.out, f.Type) {
				panic(fmt.Sprintf("gfast: field %s is %s, dependency %s returns %s", f.Name, f.Type, name, entry.out))
			}
			*fields = append(*fields, depField{index: index, dep: entry})
			continue
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && ft != timeType && ft != fileHeaderType {
			walkDepFields(f.Type, index, fields, active)
		}
	}
}

func depTag(f reflect.StructField) (string, bool) {
	raw, ok := f.Tag.Lookup("gfast")
	if !ok {
		return "", false
	}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "dep" {
			return "", true
		}
		if strings.HasPrefix(part, "dep=") {
			name := strings.TrimPrefix(part, "dep=")
			if name == "" {
				panic("gfast: empty dep name on field " + f.Name)
			}
			return name, true
		}
	}
	return "", false
}

func assignable(from, to reflect.Type) bool {
	if from.AssignableTo(to) {
		return true
	}
	if to.Kind() == reflect.Pointer && from.AssignableTo(to.Elem()) {
		return true
	}
	if from.Kind() == reflect.Pointer && from.Elem().AssignableTo(to) {
		return true
	}
	return false
}

func assignField(field, val reflect.Value) {
	if val.Type().AssignableTo(field.Type()) {
		field.Set(val)
		return
	}
	if field.Kind() == reflect.Pointer && val.Type().AssignableTo(field.Type().Elem()) {
		p := reflect.New(field.Type().Elem())
		p.Elem().Set(val)
		field.Set(p)
		return
	}
	if val.Kind() == reflect.Pointer && val.Elem().Type().AssignableTo(field.Type()) {
		if val.IsNil() {
			panic("gfast: dependency returned nil for a non-pointer field")
		}
		field.Set(val.Elem())
		return
	}
	panic(fmt.Sprintf("gfast: cannot assign %s to %s", val.Type(), field.Type()))
}

func fieldByIndexAlloc(v reflect.Value, index []int) reflect.Value {
	for _, i := range index {
		for v.Kind() == reflect.Pointer {
			if v.IsNil() {
				setField(v, reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		}
		v = v.Field(i)
	}
	return v
}

// setField writes val into field. An anonymous embed of an unexported type is
// addressable but not settable here. NewAt reaches that pointer so exported
// fields inside it can be filled.
func setField(field, val reflect.Value) {
	if field.CanSet() {
		field.Set(val)
		return
	}
	if !field.CanAddr() {
		panic("gfast: cannot set field")
	}
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(val)
}

func callDep(ctx context.Context, e *depEntry) (reflect.Value, error) {
	st, err := stateFrom(ctx)
	if err != nil {
		return reflect.Value{}, err
	}
	if v, ok := st.memo[e.id]; ok {
		return v, nil
	}
	if st.stack[e.id] {
		return reflect.Value{}, fmt.Errorf("gfast: dependency cycle at %s", e.name)
	}
	st.stack[e.id] = true
	defer delete(st.stack, e.id)

	e.bind(nil)
	fn := e.fn
	params := e.paramsOf()
	if ov, ok := st.app.override(e.id); ok {
		fn = ov.fn
		params = ov.params
	}

	args := make([]reflect.Value, 1+len(params))
	args[0] = reflect.ValueOf(ctx)
	for i, p := range params {
		val, err := callDep(ctx, p.dep)
		if err != nil {
			return reflect.Value{}, err
		}
		args[i+1] = val
	}
	out := fn.Call(args)
	if !out[1].IsNil() {
		return reflect.Value{}, out[1].Interface().(error)
	}
	val := out[0]
	st.memo[e.id] = val
	if c, ok := asCloser(val); ok {
		st.closers = append(st.closers, c)
	}
	return val, nil
}

func asCloser(v reflect.Value) (io.Closer, bool) {
	if !v.IsValid() {
		return nil, false
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map, reflect.Func, reflect.Chan:
		if v.IsNil() {
			return nil, false
		}
	}
	c, ok := v.Interface().(io.Closer)
	return c, ok
}

func bindOverride(e *depEntry, fn any) override {
	want := e.out
	v := reflect.ValueOf(fn)
	validateFn(e.name, v, want)
	if !v.Type().Out(0).AssignableTo(want) {
		panic(fmt.Sprintf("gfast: override for %s returns %s, want %s", e.name, v.Type().Out(0), want))
	}
	params := makeParams(e.name, v, []string{e.name})
	return override{fn: v, params: params}
}

func sanitize(name string) string {
	var b strings.Builder
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func contains(list []string, name string) bool {
	for _, s := range list {
		if s == name {
			return true
		}
	}
	return false
}
