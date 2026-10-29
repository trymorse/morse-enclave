package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"unicode/utf16"
)

const maxSafeInteger = 1 << 53

var (
	ErrNumber = errors.New("jcs: only integers of magnitude at most 2^53 are canonicalized")
	hexDigits = "0123456789abcdef"
)

func AppendString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			dst = append(dst, '\\', '"')
		case '\\':
			dst = append(dst, '\\', '\\')
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			} else {
				dst = append(dst, c)
			}
		}
	}
	return append(dst, '"')
}

func String(s string) []byte { return AppendString(nil, s) }

func Marshal(v any) ([]byte, error) { return appendValue(nil, v) }

func Decode(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("jcs: data follows the JSON value")
	}
	return v, nil
}

func Canonicalize(raw []byte) ([]byte, error) {
	v, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	return Marshal(v)
}

func appendValue(dst []byte, v any) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		return strconv.AppendBool(dst, t), nil
	case string:
		return AppendString(dst, t), nil
	case json.Number:
		n, err := strconv.ParseInt(t.String(), 10, 64)
		if err != nil || n > maxSafeInteger || n < -maxSafeInteger {
			return nil, ErrNumber
		}
		return strconv.AppendInt(dst, n, 10), nil
	case []any:
		dst = append(dst, '[')
		for i, e := range t {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			if dst, err = appendValue(dst, e); err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.SortFunc(keys, compareUTF16)
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = AppendString(dst, k)
			dst = append(dst, ':')
			var err error
			if dst, err = appendValue(dst, t[k]); err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	default:
		return nil, fmt.Errorf("jcs: %T is not a decoded JSON value", v)
	}
}

func compareUTF16(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}
