package jsonx

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"time"
)

func Encode(v any) []byte {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return bytes.TrimSuffix(out.Bytes(), []byte("\n"))
}

func Optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func UTC(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	return new(t.UTC())
}

func Base64(b []byte) *string {
	if b == nil {
		return nil
	}
	return new(base64.StdEncoding.EncodeToString(b))
}
