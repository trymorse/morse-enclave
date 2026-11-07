// Package exactjson reads JSON the way JavaScript's JSON.parse does, so a
// document the router hands both the gate and the browser gets one reading.
// A key matches only its exact spelling, the last of two equal keys wins,
// unknown keys are ignored, and a key whose value is null is present.
// encoding/json's struct decoding folds key case, even ſ to s, and treats a
// null as absent, so the two verifiers disagreed on lexical variants of one
// document. Its base64 and integer readers refuse what either side refuses.
package exactjson

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
)

// MaxSafeInteger is the largest integer every JavaScript number holds exactly.
const MaxSafeInteger = 1<<53 - 1

var (
	// Standard base64 with padding and no whitespace: Go's decoder skips
	// \r and \n, and the browser's refuses them.
	base64Shape   = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	decimalDigits = regexp.MustCompile(`^[0-9]+$`)
)

// Value is a JSON value within one read: the document Parse returned, or a
// member or an element of it. Every Value of a read shares the read's first
// error, and a lookup past that error yields a Value that reads as nothing,
// so a shape reads as a list of lookups with one Err check at the end.
type Value struct {
	raw  json.RawMessage
	path string
	err  *error
}

// Parse starts a read of one JSON document.
func Parse(raw []byte) Value {
	v := Value{err: new(error)}
	if !json.Valid(raw) {
		*v.err = errors.New("not JSON")
		return v
	}
	v.raw = raw
	return v
}

// Err is the first failure of the read this value belongs to.
func (v Value) Err() error { return *v.err }

// Raw is the value's own bytes, nil once the read has failed.
func (v Value) Raw() json.RawMessage { return v.raw }

func (v Value) fail(format string, args ...any) Value {
	if *v.err == nil {
		msg := fmt.Sprintf(format, args...)
		if v.path != "" {
			msg = v.path + ": " + msg
		}
		*v.err = errors.New(msg)
	}
	return Value{err: v.err}
}

func (v Value) members() (map[string]json.RawMessage, bool) {
	if *v.err != nil || len(v.raw) == 0 || v.raw[0] != '{' {
		return nil, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(v.raw, &m); err != nil {
		return nil, false
	}
	return m, true
}

func (v Value) child(name string, raw json.RawMessage) Value {
	path := name
	if v.path != "" {
		path = v.path + "." + name
	}
	return Value{raw: raw, path: path, err: v.err}
}

// Has reports whether the value is an object with key, whatever its value.
func (v Value) Has(key string) bool {
	m, ok := v.members()
	if !ok {
		return false
	}
	_, has := m[key]
	return has
}

// Key is the member of an object. An absent key fails the read; a null one
// is a Value whose reads fail.
func (v Value) Key(key string) Value {
	if *v.err != nil {
		return Value{err: v.err}
	}
	m, ok := v.members()
	if !ok {
		return v.fail("not an object")
	}
	raw, has := m[key]
	if !has {
		return v.child(key, nil).fail("absent")
	}
	return v.child(key, raw)
}

// Items are the elements of an array.
func (v Value) Items() []Value {
	if *v.err != nil {
		return nil
	}
	var items []json.RawMessage
	if len(v.raw) == 0 || v.raw[0] != '[' || json.Unmarshal(v.raw, &items) != nil {
		v.fail("not an array")
		return nil
	}
	out := make([]Value, len(items))
	for i, raw := range items {
		out[i] = v.child(strconv.Itoa(i), raw)
	}
	return out
}

// Text is a string value.
func (v Value) Text() string {
	if *v.err != nil {
		return ""
	}
	var s string
	if len(v.raw) == 0 || v.raw[0] != '"' || json.Unmarshal(v.raw, &s) != nil {
		v.fail("not a string")
		return ""
	}
	return s
}

// Bytes is a string of standard base64 with padding and no whitespace.
func (v Value) Bytes() []byte {
	s := v.Text()
	if *v.err != nil {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if !base64Shape.MatchString(s) || err != nil {
		v.fail("not base64")
		return nil
	}
	return b
}

// Uint is a non-negative integer no larger than MaxSafeInteger, as a JSON
// number in any lexical form (1, 1.0, 1e3) or, as protobuf JSON writes a
// uint64, a string of decimal digits.
func (v Value) Uint() uint64 {
	if *v.err != nil {
		return 0
	}
	if len(v.raw) > 0 && v.raw[0] == '"' {
		s := v.Text()
		n, err := strconv.ParseUint(s, 10, 64)
		if !decimalDigits.MatchString(s) || err != nil || n > MaxSafeInteger {
			v.fail("not a string of decimal digits up to 2^53-1")
			return 0
		}
		return n
	}
	f, err := strconv.ParseFloat(string(v.raw), 64)
	if err != nil || f < 0 || f > MaxSafeInteger || f != math.Trunc(f) {
		v.fail("not an integer from 0 to 2^53-1")
		return 0
	}
	return uint64(f)
}
