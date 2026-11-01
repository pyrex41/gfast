package gfast

import (
	"reflect"
	"strconv"
	"strings"
)

type apiDoc struct {
	OpenAPI    string                   `json:"openapi"`
	Info       docInfo                  `json:"info"`
	Paths      map[string]map[string]op `json:"paths"`
	Components *docComponents           `json:"components,omitempty"`
}

type docInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type docComponents struct {
	SecuritySchemes map[string]secScheme `json:"securitySchemes,omitempty"`
}

type secScheme struct {
	Type        string `json:"type"`
	Scheme      string `json:"scheme,omitempty"`
	In          string `json:"in,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type op struct {
	OperationID string                `json:"operationId,omitempty"`
	Summary     string                `json:"summary,omitempty"`
	Description string                `json:"description,omitempty"`
	Tags        []string              `json:"tags,omitempty"`
	Parameters  []opParam             `json:"parameters,omitempty"`
	RequestBody *opBody               `json:"requestBody,omitempty"`
	Responses   map[string]opResp     `json:"responses,omitempty"`
	Security    []map[string][]string `json:"security,omitempty"`
}

type opParam struct {
	Name     string     `json:"name"`
	In       string     `json:"in"`
	Required bool       `json:"required,omitempty"`
	Schema   *docSchema `json:"schema,omitempty"`
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
	Type       string                `json:"type,omitempty"`
	Properties map[string]*docSchema `json:"properties,omitempty"`
	Required   []string              `json:"required,omitempty"`
	Items      *docSchema            `json:"items,omitempty"`
	MinLength  *int                  `json:"minLength,omitempty"`
	MaxLength  *int                  `json:"maxLength,omitempty"`
}

func (a *App) addOperation(path, method string, route routeConfig, in reflect.Type, out reflect.Type, schemes map[string]*namedScheme, status int) {
	operation := op{
		OperationID: operationID(method, path),
		Summary:     route.summary,
		Description: route.description,
		Tags:        route.tags,
		Responses: map[string]opResp{
			strconv.Itoa(status): {
				Description: "Success",
				Content: map[string]opMedia{
					"application/json": {Schema: schemaFor(out)},
				},
			},
		},
	}
	if len(schemes) > 0 {
		operation.Security = []map[string][]string{securityRequirement(schemes, route.scopes)}
	}
	plan := planInput(in)
	for _, p := range plan.params {
		operation.Parameters = append(operation.Parameters, opParam{
			Name:     p.name,
			In:       p.loc,
			Required: p.loc == "path",
			Schema:   &docSchema{Type: "string"},
		})
	}
	if plan.hasBody {
		bodyType := fieldType(in, plan.body)
		operation.RequestBody = &opBody{
			Required: true,
			Content: map[string]opMedia{
				"application/json": {Schema: schemaFor(bodyType)},
			},
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
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
	if a.doc.Components == nil {
		a.doc.Components = &docComponents{}
	}
	if a.doc.Components.SecuritySchemes == nil {
		a.doc.Components.SecuritySchemes = map[string]secScheme{}
	}
	for name, scheme := range schemes {
		if _, ok := a.doc.Components.SecuritySchemes[name]; ok {
			continue
		}
		a.doc.Components.SecuritySchemes[name] = secScheme{
			Type:        scheme.typ,
			Scheme:      scheme.scheme,
			In:          scheme.in,
			Name:        scheme.param,
			Description: scheme.description,
		}
	}
}

func fieldType(t reflect.Type, index []int) reflect.Type {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	for _, i := range index {
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		t = t.Field(i).Type
	}
	return t
}

func schemaFor(t reflect.Type) *docSchema {
	if t == nil {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
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
		return &docSchema{Type: "array", Items: schemaFor(t.Elem())}
	case reflect.Struct:
		props := map[string]*docSchema{}
		var required []string
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
			name := jsonName(f)
			if name == "-" {
				continue
			}
			prop := schemaFor(f.Type)
			if raw := f.Tag.Get("minLength"); raw != "" {
				if n, err := strconv.Atoi(raw); err == nil {
					prop.MinLength = &n
				}
			}
			if raw := f.Tag.Get("maxLength"); raw != "" {
				if n, err := strconv.Atoi(raw); err == nil {
					prop.MaxLength = &n
				}
			}
			props[name] = prop
			required = append(required, name)
		}
		return &docSchema{Type: "object", Properties: props, Required: required}
	default:
		return &docSchema{}
	}
}
