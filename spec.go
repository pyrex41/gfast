package gfast

import (
	"encoding"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	jsonv2 "encoding/json/v2"
)

type apiDoc struct {
	OpenAPI      string                   `json:"openapi"`
	Info         docInfo                  `json:"info"`
	Servers      []Server                 `json:"servers,omitempty"`
	ExternalDocs *externalDoc             `json:"externalDocs,omitempty"`
	Tags         []tagDoc                 `json:"tags,omitempty"`
	Paths        map[string]map[string]op `json:"paths"`
	Webhooks     map[string]any           `json:"webhooks,omitempty"`
	Components   *docComponents           `json:"components,omitempty"`
}

type externalDoc struct {
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
}

type tagDoc struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type docInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type docComponents struct {
	Schemas         map[string]*docSchema `json:"schemas,omitempty"`
	SecuritySchemes map[string]secScheme  `json:"securitySchemes,omitempty"`
}

type secScheme struct {
	Type        string         `json:"type"`
	Scheme      string         `json:"scheme,omitempty"`
	In          string         `json:"in,omitempty"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Flows       *oauthFlowsDoc `json:"flows,omitempty"`
}

// oauthFlowsDoc is the OpenAPI OAuth 2.0 flows object.
type oauthFlowsDoc struct {
	AuthorizationCode *oauthFlowDoc `json:"authorizationCode,omitempty"`
	ClientCredentials *oauthFlowDoc `json:"clientCredentials,omitempty"`
	Password          *oauthFlowDoc `json:"password,omitempty"`
}

type oauthFlowDoc struct {
	AuthorizationURL string            `json:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl"`
	Scopes           map[string]string `json:"scopes"`
}

type op struct {
	OperationID  string                `json:"operationId,omitempty"`
	Summary      string                `json:"summary,omitempty"`
	Description  string                `json:"description,omitempty"`
	Deprecated   bool                  `json:"deprecated,omitzero"`
	Tags         []string              `json:"tags,omitempty"`
	ExternalDocs *externalDoc          `json:"externalDocs,omitempty"`
	Parameters   []opParam             `json:"parameters,omitempty"`
	RequestBody  *opBody               `json:"requestBody,omitempty"`
	Responses    map[string]opResp     `json:"responses,omitempty"`
	Callbacks    map[string]any        `json:"callbacks,omitempty"`
	Security     []map[string][]string `json:"security,omitempty"`
}

type opParam struct {
	Name        string     `json:"name"`
	In          string     `json:"in"`
	Description string     `json:"description,omitempty"`
	Required    bool       `json:"required,omitempty"`
	Schema      *docSchema `json:"schema,omitempty"`
}

type opBody struct {
	Required bool               `json:"required"`
	Content  map[string]opMedia `json:"content"`
}

type opMedia struct {
	Schema *docSchema `json:"schema,omitempty"`
}

type opResp struct {
	Description string             `json:"description"`
	Content     map[string]opMedia `json:"content,omitempty"`
}

type docSchema struct {
	Ref                  string                `json:"$ref,omitempty"`
	Type                 string                `json:"type,omitempty"`
	Format               string                `json:"format,omitempty"`
	Description          string                `json:"description,omitempty"`
	Properties           map[string]*docSchema `json:"properties,omitempty"`
	Required             []string              `json:"required,omitempty"`
	Items                *docSchema            `json:"items,omitempty"`
	AdditionalProperties *docSchema            `json:"additionalProperties,omitempty"`
	MinLength            *int                  `json:"minLength,omitempty"`
	MaxLength            *int                  `json:"maxLength,omitempty"`
	MinItems             *int                  `json:"minItems,omitempty"`
	MaxItems             *int                  `json:"maxItems,omitempty"`
	Minimum              *float64              `json:"minimum,omitempty"`
	Maximum              *float64              `json:"maximum,omitempty"`
	ExclusiveMinimum     *float64              `json:"exclusiveMinimum,omitempty"`
	ExclusiveMaximum     *float64              `json:"exclusiveMaximum,omitempty"`
	Pattern              string                `json:"pattern,omitempty"`
	Enum                 []any                 `json:"enum,omitzero"`
	Default              any                   `json:"default,omitzero"`
	Example              schemaExample         `json:"example,omitzero"`
}

// schemaExample is present even when the example is 0, false, or "".
type schemaExample struct {
	v   any
	set bool
}

func (e schemaExample) IsZero() bool { return !e.set }

func (e schemaExample) MarshalJSON() ([]byte, error) {
	return jsonv2.Marshal(e.v)
}

type schemaKey struct {
	t   reflect.Type
	top bool
}

func newOperation(route routeConfig, method, path string) op {
	id := route.operationID
	if id == "" {
		id = operationID(method, path)
	}
	return op{
		OperationID:  id,
		Summary:      route.summary,
		Description:  route.description,
		Deprecated:   route.deprecated,
		Tags:         route.tags,
		ExternalDocs: route.externalDocs,
		Callbacks:    route.callbacks,
	}
}

func (a *App) addOperation(path, method string, route routeConfig, in reflect.Type, out reflect.Type, schemes map[string]*namedScheme, status int) {
	if !route.inSchema() {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	code, success := a.describeSuccess(status, out)
	operation := newOperation(route, method, path)
	operation.Responses = map[string]opResp{
		strconv.Itoa(code): success,
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
	if plan.hasBody || plan.flat {
		var schema *docSchema
		if plan.hasBody {
			schema = a.schemaFor(plan.bodyType)
			decorateSchema(schema, plan.bodyTag, plan.bodyType)
		} else {
			schema = a.schemaForMode(in, true)
		}
		operation.RequestBody = &opBody{
			Required: true,
			Content: map[string]opMedia{
				"application/json": {Schema: schema},
			},
		}
	} else if ct, schema, required := a.formSchema(plan); schema != nil {
		operation.RequestBody = &opBody{
			Required: required,
			Content:  map[string]opMedia{ct: {Schema: schema}},
		}
	}
	a.putOperation(path, method, operation, schemes, route.scopes)
}

// putOperation stores an operation. The caller holds a.mu.
func (a *App) putOperation(path, method string, operation op, schemes map[string]*namedScheme, scopes []string) {
	if len(schemes) > 0 {
		operation.Security = []map[string][]string{securityRequirement(schemes, scopes)}
	}
	if a.doc.Paths == nil {
		a.doc.Paths = map[string]map[string]op{}
	}
	item := a.doc.Paths[path]
	if item == nil {
		item = map[string]op{}
	}
	item[strings.ToLower(method)] = operation
	a.doc.Paths[path] = item
	if len(schemes) == 0 {
		return
	}
	comps := a.components()
	if comps.SecuritySchemes == nil {
		comps.SecuritySchemes = map[string]secScheme{}
	}
	for name, scheme := range schemes {
		if _, ok := comps.SecuritySchemes[name]; ok {
			continue
		}
		comps.SecuritySchemes[name] = a.documentedScheme(scheme)
	}
}

func (a *App) describeSuccess(status int, out reflect.Type) (int, opResp) {
	if out.Kind() == reflect.Pointer {
		out = out.Elem()
	}
	switch out {
	case reflect.TypeFor[Redirect]():
		if status < 300 || status > 399 {
			status = http.StatusTemporaryRedirect
		}
		return status, opResp{Description: "Redirect"}
	case reflect.TypeFor[FileResponse]():
		return status, binarySuccess()
	case reflect.TypeFor[Events]():
		return status, opResp{
			Description: "Success",
			Content: map[string]opMedia{
				"text/event-stream": {Schema: &docSchema{Type: "string"}},
			},
		}
	}
	if implementsReader(out) {
		return status, binarySuccess()
	}
	return status, opResp{
		Description: "Success",
		Content: map[string]opMedia{
			"application/json": {Schema: a.schemaFor(out)},
		},
	}
}

func binarySuccess() opResp {
	return opResp{
		Description: "Success",
		Content: map[string]opMedia{
			"application/octet-stream": {Schema: &docSchema{Type: "string", Format: "binary"}},
		},
	}
}

func implementsReader(t reflect.Type) bool {
	rt := reflect.TypeFor[io.Reader]()
	if t.Implements(rt) {
		return true
	}
	return t.Kind() != reflect.Pointer && reflect.PointerTo(t).Implements(rt)
}

func (a *App) addExtraResponses(responses map[string]opResp, extras []extraResponse) {
	for _, extra := range extras {
		key := strconv.Itoa(extra.status)
		resp := responses[key]
		if extra.description != "" {
			resp.Description = extra.description
		}
		if resp.Description == "" {
			resp.Description = http.StatusText(extra.status)
		}
		if resp.Description == "" {
			resp.Description = "Response"
		}
		if extra.model != nil || extra.media != "" {
			media := extra.media
			if media == "" {
				media = "application/json"
			}
			if resp.Content == nil {
				resp.Content = map[string]opMedia{}
			}
			item := opMedia{}
			if extra.model != nil {
				item.Schema = a.schemaFor(reflect.TypeOf(extra.model))
			}
			resp.Content[media] = item
		}
		responses[key] = resp
	}
}

// schemaFor and the methods below are called with a.mu held.
func (a *App) schemaFor(t reflect.Type) *docSchema {
	return a.schemaForMode(t, false)
}

func (a *App) schemaForMode(t reflect.Type, topJSON bool) *docSchema {
	if t == nil {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t == timeType:
		return &docSchema{Type: "string", Format: "date-time"}
	case jsonMarshaler(t):
		return &docSchema{}
	case textMarshaler(t):
		return &docSchema{Type: "string"}
	}
	switch t.Kind() {
	case reflect.String:
		return &docSchema{Type: "string"}
	case reflect.Bool:
		return &docSchema{Type: "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &docSchema{Type: "integer"}
	case reflect.Float32, reflect.Float64:
		return &docSchema{Type: "number"}
	case reflect.Slice, reflect.Array:
		if byteWire(t) {
			return &docSchema{Type: "string", Format: "byte"}
		}
		return &docSchema{Type: "array", Items: a.schemaFor(t.Elem())}
	case reflect.Map:
		return &docSchema{Type: "object", AdditionalProperties: a.schemaFor(t.Elem())}
	case reflect.Struct:
		if t.Name() != "" {
			return a.refStruct(t, topJSON)
		}
		return a.structSchema(t, topJSON)
	default:
		return &docSchema{}
	}
}

func (a *App) refStruct(t reflect.Type, topJSON bool) *docSchema {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	key := schemaKey{t: t, top: topJSON}
	if a.schemaIDs == nil {
		a.schemaIDs = map[schemaKey]string{}
		a.schemaUsed = map[string]struct{}{}
	}
	if name, ok := a.schemaIDs[key]; ok {
		return schemaRef(name)
	}
	name := a.schemaName(t)
	// Store the id before walking fields so a nested use of this type is a $ref.
	a.schemaIDs[key] = name
	built := a.structSchema(t, topJSON)
	comps := a.components()
	if comps.Schemas == nil {
		comps.Schemas = map[string]*docSchema{}
	}
	comps.Schemas[name] = built
	return schemaRef(name)
}

func schemaRef(name string) *docSchema {
	return &docSchema{Ref: "#/components/schemas/" + name}
}

func (a *App) components() *docComponents {
	if a.doc.Components == nil {
		a.doc.Components = &docComponents{}
	}
	return a.doc.Components
}

func (a *App) schemaName(t reflect.Type) string {
	base := t.Name()
	if base == "" {
		base = "Schema"
	}
	if _, taken := a.schemaUsed[base]; !taken {
		a.schemaUsed[base] = struct{}{}
		return base
	}
	candidate := base
	if pkg := t.PkgPath(); pkg != "" {
		candidate = strings.ReplaceAll(pkg, "/", "_") + "_" + base
	}
	if _, taken := a.schemaUsed[candidate]; !taken {
		a.schemaUsed[candidate] = struct{}{}
		return candidate
	}
	for n := 2; ; n++ {
		next := fmt.Sprintf("%s_%d", candidate, n)
		if _, taken := a.schemaUsed[next]; !taken {
			a.schemaUsed[next] = struct{}{}
			return next
		}
	}
}

func (a *App) structSchema(t reflect.Type, topJSON bool) *docSchema {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	props := map[string]*docSchema{}
	var required []string
	for _, field := range jsonFields(t, topJSON) {
		prop := a.schemaFor(field.typ)
		decorateSchema(prop, field.tag, field.typ)
		props[field.name] = prop
		// omitempty and omitzero are optional. required:"true" stays required
		// even when the json tag also omits the zero value.
		if field.tag.Get("required") == "true" || (!field.omitempty && !field.omitzero) {
			required = append(required, field.name)
		}
	}
	return &docSchema{Type: "object", Properties: props, Required: required}
}

// jsonField is one JSON object member. Depth is the embed depth.
// On a handler input (top), Body and RawBody are transport fields, not members.
type jsonField struct {
	name      string
	typ       reflect.Type
	tag       reflect.StructTag
	omitempty bool
	omitzero  bool
	explicit  bool
	depth     int
}

func jsonFields(t reflect.Type, top bool) []jsonField {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || scalarWire(t) {
		return nil
	}
	var out []jsonField
	index := map[string]int{}
	var walk func(reflect.Type, bool, int, map[reflect.Type]struct{})
	walk = func(t reflect.Type, top bool, depth int, seen map[reflect.Type]struct{}) {
		for t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || scalarWire(t) {
			return
		}
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		defer delete(seen, t)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" && !f.Anonymous {
				continue
			}
			if top && (f.Name == "Body" || f.Name == "RawBody") {
				continue
			}
			if _, ok := depTag(f); ok {
				continue
			}
			if _, _, ok := paramTag(f); ok {
				continue
			}
			info := jsonTagOf(f)
			if info.skip {
				continue
			}
			if flattenJSON(f, info, top) {
				walk(f.Type, top, depth+1, seen)
				continue
			}
			if top && !isJSONField(f) {
				continue
			}
			if !f.IsExported() || info.name == "" {
				continue
			}
			next := jsonField{
				name: info.name, typ: f.Type, tag: f.Tag,
				omitempty: info.omitempty, omitzero: info.omitzero,
				explicit: info.explicit, depth: depth,
			}
			if at, ok := index[next.name]; ok {
				if !jsonFieldWins(next, out[at]) {
					continue
				}
				out[at] = next
				continue
			}
			index[next.name] = len(out)
			out = append(out, next)
		}
	}
	walk(t, top, 0, map[reflect.Type]struct{}{})
	return out
}

func jsonFieldWins(next, prev jsonField) bool {
	if next.depth != prev.depth {
		return next.depth < prev.depth
	}
	return next.explicit && !prev.explicit
}

type jsonTag struct {
	name      string
	explicit  bool
	omitempty bool
	omitzero  bool
	skip      bool
}

func jsonTagOf(f reflect.StructField) jsonTag {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return jsonTag{name: f.Name}
	}
	name, opt, _ := strings.Cut(tag, ",")
	if name == "-" {
		return jsonTag{skip: true}
	}
	out := jsonTag{explicit: name != ""}
	if name == "" {
		name = f.Name
	}
	out.name = name
	for _, part := range strings.Split(opt, ",") {
		switch part {
		case "omitempty":
			out.omitempty = true
		case "omitzero":
			out.omitzero = true
		}
	}
	return out
}

func flattenJSON(f reflect.StructField, info jsonTag, top bool) bool {
	if info.explicit {
		return false
	}
	if top {
		if !f.Anonymous || f.Tag.Get("json") != "" {
			return false
		}
	} else if !f.Anonymous {
		return false
	}
	ft := f.Type
	for ft.Kind() == reflect.Pointer {
		ft = ft.Elem()
	}
	return ft.Kind() == reflect.Struct && !scalarWire(ft)
}

func scalarWire(t reflect.Type) bool {
	return t == timeType || t == fileHeaderType || jsonMarshaler(t) || textMarshaler(t)
}

func byteWire(t reflect.Type) bool {
	if t.Kind() != reflect.Slice && t.Kind() != reflect.Array {
		return false
	}
	elem := t.Elem()
	return elem.Kind() == reflect.Uint8 && elem.PkgPath() == ""
}

var (
	jsonMarshalerType   = reflect.TypeFor[jsonv2.Marshaler]()
	jsonMarshalerToType = reflect.TypeFor[jsonv2.MarshalerTo]()
	textMarshalerType   = reflect.TypeFor[encoding.TextMarshaler]()
	textAppenderType    = reflect.TypeFor[encoding.TextAppender]()
)

func jsonMarshaler(t reflect.Type) bool {
	return implementsIface(t, jsonMarshalerType) || implementsIface(t, jsonMarshalerToType)
}

func textMarshaler(t reflect.Type) bool {
	return implementsIface(t, textMarshalerType) || implementsIface(t, textAppenderType)
}

func implementsIface(t, iface reflect.Type) bool {
	return t != nil && (t.Implements(iface) || reflect.PointerTo(t).Implements(iface))
}

func (a *App) paramSchema(p paramField) *docSchema {
	var schema *docSchema
	if p.loc == "file" {
		schema = fileSchema(p.typ)
	} else {
		schema = a.schemaFor(p.typ)
	}
	decorateSchema(schema, p.tag, p.typ)
	return schema
}

func fileSchema(t reflect.Type) *docSchema {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		return &docSchema{Type: "array", Items: &docSchema{Type: "string", Format: "binary"}}
	}
	return &docSchema{Type: "string", Format: "binary"}
}

func (a *App) formSchema(plan inputPlan) (string, *docSchema, bool) {
	props := map[string]*docSchema{}
	var required []string
	hasFile := false
	anyField := false
	bodyRequired := false
	for _, p := range plan.params {
		if p.loc != "form" && p.loc != "file" {
			continue
		}
		anyField = true
		if p.loc == "file" {
			hasFile = true
		}
		props[p.name] = a.paramSchema(p)
		if p.tag.Get("required") == "true" {
			required = append(required, p.name)
			bodyRequired = true
		}
	}
	if !anyField {
		return "", nil, false
	}
	ct := "application/x-www-form-urlencoded"
	if hasFile {
		ct = "multipart/form-data"
	}
	return ct, &docSchema{Type: "object", Properties: props, Required: required}, bodyRequired
}

func decorateSchema(s *docSchema, tag reflect.StructTag, typ reflect.Type) {
	if s == nil {
		return
	}
	if doc := tag.Get("doc"); doc != "" {
		s.Description = doc
	}
	if raw, ok := tag.Lookup(Example); ok {
		s.Example = schemaExample{v: schemaValue(typ, raw), set: true}
	}
	if raw, ok := tag.Lookup("default"); ok && isScalarType(typ) {
		s.Default = schemaValue(typ, raw)
	}
	base := typ
	if base.Kind() == reflect.Pointer {
		base = base.Elem()
	}
	target := s
	targetKind := base.Kind()
	if base.Kind() == reflect.Slice || base.Kind() == reflect.Array {
		if raw := tag.Get("minItems"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				s.MinItems = &n
			}
		}
		if raw := tag.Get("maxItems"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil {
				s.MaxItems = &n
			}
		}
		if s.Items != nil {
			target = s.Items
		}
		targetKind = base.Elem().Kind()
		if targetKind == reflect.Pointer {
			targetKind = base.Elem().Elem().Kind()
		}
	}
	if raw := tag.Get("minLength"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			target.MinLength = &n
		}
	}
	if raw := tag.Get("maxLength"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			target.MaxLength = &n
		}
	}
	if raw := tag.Get("pattern"); raw != "" {
		target.Pattern = raw
	}
	if raw := tag.Get("format"); raw != "" {
		target.Format = raw
	}
	if raw := tag.Get("enum"); raw != "" {
		parts := splitCSV(raw)
		vals := make([]any, len(parts))
		elem := constraintType(typ)
		for i, part := range parts {
			vals[i] = schemaValue(elem, part)
		}
		target.Enum = vals
	}
	if isNumeric(targetKind) {
		if n := floatPtr(tag.Get("gt")); n != nil {
			target.ExclusiveMinimum = n
		}
		if n := floatPtr(tag.Get("ge")); n != nil {
			target.Minimum = n
		}
		if n := floatPtr(tag.Get("lt")); n != nil {
			target.ExclusiveMaximum = n
		}
		if n := floatPtr(tag.Get("le")); n != nil {
			target.Maximum = n
		}
	}
}

func schemaValue(t reflect.Type, raw string) any {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return raw
	case reflect.Bool:
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return raw
		}
		return v
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return raw
		}
		return v
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return raw
		}
		return v
	case reflect.Float32, reflect.Float64:
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return raw
		}
		return v
	default:
		return raw
	}
}

func floatPtr(raw string) *float64 {
	if raw == "" {
		return nil
	}
	n, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return nil
	}
	return &n
}
