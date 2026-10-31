package connection

import (
	"bytes"
	"encoding/json"
	"io"
)

// Reject duplicate/unknown keys even when the endpoint is decoded from JSONB
// independently of the HTTP envelope. This never accepts private fields in Spec.
func (s *Spec) UnmarshalJSON(raw []byte) error {
	if len(raw) > 8192 {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for d.More() {
		tok, e = d.Token()
		key, ok := tok.(string)
		if e != nil || !ok || seen[key] {
			return ErrInvalid
		}
		seen[key] = true
		var part json.RawMessage
		if d.Decode(&part) != nil || bytes.Equal(part, []byte("null")) {
			return ErrInvalid
		}
	}
	if _, e = d.Token(); e != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	type plain Spec
	var result plain
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil {
		return ErrInvalid
	}
	*s = Spec(result)
	return nil
}
