// Package importer validates private source material without running engines or
// fetching addresses contained in a configuration. Errors contain fixed codes.
package importer

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

const MaxBytes = 512 * 1024

type Error string

func (e Error) Error() string { return string(e) }
func check(ok bool, code string) {
	if !ok {
		panic(Error(code))
	}
}

type object = map[string]any

func obj(v any) object { m, ok := v.(map[string]any); check(ok, "source_shape"); return m }
func arr(v any) []any  { a, ok := v.([]any); check(ok, "source_shape"); return a }
func str(v any) string { s, ok := v.(string); check(ok, "source_shape"); return s }
func member(v string, values ...string) bool {
	for _, s := range values {
		if s == v {
			return true
		}
	}
	return false
}
func keys(m object, allowed ...string) {
	for k := range m {
		check(member(k, allowed...), "source_unknown_field")
	}
}
func number(v any) int64 {
	n, ok := v.(json.Number)
	check(ok, "source_integer")
	i, e := strconv.ParseInt(string(n), 10, 64)
	check(e == nil, "source_integer")
	return i
}
func optional(m object, k string, def any) any {
	if v, ok := m[k]; ok {
		return v
	}
	return def
}
func validText(s string, limit int) bool {
	if len([]rune(s)) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 32 || r >= 127 && r <= 159 {
			return false
		}
	}
	return true
}

// encoding/json replaces malformed surrogate escapes, which could silently
// change a credential. Reject them before decoding, along with duplicate keys.
func unicodeEscapes(raw []byte) bool {
	in := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			in = !in
			continue
		}
		if !in || raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, e := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if e != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n < 0xd800 || n > 0xdbff {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if e != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}
func strictJSON(raw []byte) any {
	check(len(raw) > 0 && len(raw) <= MaxBytes && utf8.Valid(raw) && unicodeEscapes(raw), "source_json")
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var read func(int) any
	read = func(depth int) any {
		check(depth <= 32, "source_depth")
		tok, e := d.Token()
		check(e == nil, "source_json")
		delim, ok := tok.(json.Delim)
		if !ok {
			return tok
		}
		switch delim {
		case '{':
			m := object{}
			for d.More() {
				k, e := d.Token()
				check(e == nil, "source_json")
				key := str(k)
				_, exists := m[key]
				check(!exists, "source_duplicate_key")
				m[key] = read(depth + 1)
			}
			t, e := d.Token()
			check(e == nil && t == json.Delim('}'), "source_json")
			return m
		case '[':
			a := []any{}
			for d.More() {
				a = append(a, read(depth+1))
			}
			t, e := d.Token()
			check(e == nil && t == json.Delim(']'), "source_json")
			return a
		default:
			panic(Error("source_json"))
		}
	}
	v := read(0)
	_, e := d.Token()
	check(errors.Is(e, io.EOF), "source_json")
	return v
}

// Decode validates the shared JSON envelope before any typed request binding.
func Decode(raw []byte) (v any, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(Error); ok {
				v = nil
				err = e
			} else {
				panic(r)
			}
		}
	}()
	return strictJSON(raw), nil
}

// ValidJSONUnicode rejects malformed escaped UTF-16 in HTTP request envelopes.
func ValidJSONUnicode(raw []byte) bool { return utf8.Valid(raw) && unicodeEscapes(raw) }
