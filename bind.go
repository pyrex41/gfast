package gfast

import (
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	jsonv2 "encoding/json/v2"
)

type inputPlan struct {
	params  []paramField
	body    []int
	hasBody bool
}

type paramField struct {
	index []int
	loc   string
	name  string
}

func planInput(t reflect.Type) inputPlan {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		panic("gfast: handler input must be a struct")
	}
	var plan inputPlan
	walkInput(t, nil, &plan)
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
			continue
		}
		if _, ok := depTag(f); ok {
			continue
		}
		if loc, name, ok := paramTag(f); ok {
			plan.params = append(plan.params, paramField{index: index, loc: loc, name: name})
			continue
		}
		ft := f.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && ft.String() != "time.Time" {
			walkInput(f.Type, index, plan)
		}
	}
}

func paramTag(f reflect.StructField) (string, string, bool) {
	for _, loc := range []string{"path", "query", "header", "cookie"} {
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

func bindInput(r *http.Request, dst reflect.Value, plan inputPlan) error {
	for _, p := range plan.params {
		raw, ok, err := paramValue(r, p)
		if err != nil {
			return err
		}
		if !ok {
			if p.loc == "path" {
				return BadRequest("missing path parameter " + p.name)
			}
			continue
		}
		field := fieldByIndexAlloc(dst, p.index)
		if err := setScalar(field, raw); err != nil {
			return BadRequest(p.name + ": " + err.Error())
		}
	}
	if plan.hasBody && r.Body != nil && r.ContentLength != 0 {
		field := fieldByIndexAlloc(dst, plan.body)
		target := field.Addr().Interface()
		if err := jsonv2.UnmarshalRead(r.Body, target, jsonv2.RejectUnknownMembers(true)); err != nil && err != io.EOF {
			return BadRequest(err.Error())
		}
		if err := validateValue(field); err != nil {
			return err
		}
	} else if plan.hasBody {
		field := fieldByIndexAlloc(dst, plan.body)
		if err := validateValue(field); err != nil {
			return err
		}
	}
	return nil
}

func paramValue(r *http.Request, p paramField) (string, bool, error) {
	switch p.loc {
	case "path":
		v := r.PathValue(p.name)
		return v, v != "", nil
	case "query":
		vs := r.URL.Query()[p.name]
		if len(vs) == 0 {
			return "", false, nil
		}
		return vs[0], true, nil
	case "header":
		v := r.Header.Get(p.name)
		return v, v != "", nil
	case "cookie":
		c, err := r.Cookie(p.name)
		if err == http.ErrNoCookie {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		return c.Value, true, nil
	default:
		return "", false, BadRequest("unsupported parameter location")
	}
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

func validateValue(v reflect.Value) error {
	if !v.IsValid() {
		return nil
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return validateValue(v.Elem())
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" && !f.Anonymous {
				continue
			}
			fv := v.Field(i)
			if err := checkRules(f, fv); err != nil {
				return err
			}
			if fv.Kind() == reflect.Struct || fv.Kind() == reflect.Pointer || fv.Kind() == reflect.Slice {
				if err := validateValue(fv); err != nil {
					return err
				}
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if err := validateValue(v.Index(i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkRules(f reflect.StructField, v reflect.Value) error {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() == reflect.String {
		n := utf8.RuneCountInString(v.String())
		if raw := f.Tag.Get("minLength"); raw != "" {
			min, err := strconv.Atoi(raw)
			if err == nil && n < min {
				return unprocessable(jsonName(f) + " must be at least " + raw + " characters")
			}
		}
		if raw := f.Tag.Get("maxLength"); raw != "" {
			max, err := strconv.Atoi(raw)
			if err == nil && n > max {
				return unprocessable(jsonName(f) + " must be at most " + raw + " characters")
			}
		}
	}
	return nil
}

func jsonName(f reflect.StructField) string {
	name := f.Tag.Get("json")
	if name == "" || name == "-" {
		return f.Name
	}
	return strings.Split(name, ",")[0]
}

func unprocessable(msg string) error {
	return statusErr(http.StatusUnprocessableEntity, msg)
}
