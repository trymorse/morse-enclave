package chat

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"

	"morse/backend/internal/strictjson"
)

const (
	MaxMessages   = 4096
	MaxJSONValues = 1 << 18
)

var (
	ErrTooManyMessages = errors.New("chat: messages holds more entries than MaxMessages")
	ErrTooManyValues   = errors.New("chat: the body holds more JSON values than MaxJSONValues")
)

type shapeFrame struct {
	keys        map[string]struct{}
	lastKey     string
	awaitingKey bool
	elements    int
	isMessages  bool
}

func (f *shapeFrame) isObject() bool { return f.keys != nil }

func checkShape(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var stack []*shapeFrame
	values := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var top *shapeFrame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if delim, ok := tok.(json.Delim); ok && (delim == '}' || delim == ']') {
			stack = stack[:len(stack)-1]
			continue
		}
		if top != nil && top.isObject() && top.awaitingKey {
			key := tok.(string)
			folded := strings.Map(foldRune, key)
			if _, seen := top.keys[folded]; seen {
				return strictjson.ErrDuplicateKey
			}
			top.keys[folded] = struct{}{}
			top.lastKey, top.awaitingKey = key, false
			continue
		}
		if values++; values > MaxJSONValues {
			return ErrTooManyValues
		}
		switch {
		case top == nil:
		case top.isObject():
			top.awaitingKey = true
		default:
			top.elements++
			if top.isMessages && top.elements > MaxMessages {
				return ErrTooManyMessages
			}
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &shapeFrame{keys: map[string]struct{}{}, awaitingKey: true})
		case json.Delim('['):
			isMessages := len(stack) == 1 && top.lastKey == "messages"
			stack = append(stack, &shapeFrame{isMessages: isMessages})
		}
	}
}

// foldRune is the smallest rune in r's case-fold orbit, the fold encoding/json matches struct fields by. Keys that
// fold alike count as one repeated key, so no decoder here reads a field under one spelling while a vendor reads
// the raw bytes under another.
func foldRune(r rune) rune {
	for {
		folded := unicode.SimpleFold(r)
		if folded <= r {
			return folded
		}
		r = folded
	}
}
