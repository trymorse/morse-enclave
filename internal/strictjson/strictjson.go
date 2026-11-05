package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
)

type Invalid string

func (e Invalid) Error() string { return string(e) }

var ErrDuplicateKey = errors.New("strictjson: a JSON object repeats a key")

var errOneObject = Invalid("The request body must hold exactly one JSON object.")

var errOneValue = errors.New("strictjson: the data holds more than one JSON value")

func Object(body io.Reader, allowed ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(body)
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('{') {
		return nil, errOneObject
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		if !slices.Contains(allowed, key) {
			return nil, Invalid("Unknown field " + strconv.Quote(key) + ".")
		}
		if _, seen := fields[key]; seen {
			return nil, ErrDuplicateKey
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	switch _, err := dec.Token(); {
	case err == io.EOF:
		return fields, nil
	case err != nil:
		return nil, err
	}
	return nil, errOneObject
}

func Decode(body io.Reader, into map[string]any) error {
	fields, err := Object(body, slices.Collect(maps.Keys(into))...)
	if err != nil {
		return err
	}
	for key, value := range fields {
		if err := json.Unmarshal(value, into[key]); err != nil {
			return err
		}
	}
	return nil
}

func UniqueKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueKeys(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errOneValue
	}
	return nil
}

func uniqueKeys(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := tok.(string)
			if seen[key] {
				return ErrDuplicateKey
			}
			seen[key] = true
			if err := uniqueKeys(dec); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for dec.More() {
			if err := uniqueKeys(dec); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = dec.Token()
	return err
}
