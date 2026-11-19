package catalog

import (
	"encoding/json"
	"fmt"

	"morse/backend/internal/enum"
)

type ResponseFormat uint8

const (
	ResponseFormatJSONObject ResponseFormat = iota
	ResponseFormatJSONSchema
)

var responseFormatNames = enum.Names[ResponseFormat]{ResponseFormatJSONObject: "json_object", ResponseFormatJSONSchema: "json_schema"}

func ParseResponseFormat(name string) (ResponseFormat, bool) { return responseFormatNames.Parse(name) }

func (f ResponseFormat) String() string { return responseFormatNames.String(f) }

type ResponseFormats uint8

func ParseResponseFormats(names []string) (ResponseFormats, error) {
	var formats ResponseFormats
	last := -1
	for _, name := range names {
		f, ok := responseFormatNames.Parse(name)
		switch {
		case !ok:
			return 0, fmt.Errorf("response_formats names %q, and each must be one of %s", name, responseFormatNames.List())
		case int(f) <= last:
			return 0, fmt.Errorf("response_formats must name each of %s at most once, in that order", responseFormatNames.List())
		}
		last = int(f)
		formats |= 1 << f
	}
	return formats, nil
}

func (fs ResponseFormats) Honours(f ResponseFormat) bool {
	return responseFormatNames.Valid(f) && fs&(1<<f) != 0
}

func (fs ResponseFormats) Names() []string {
	var names []string
	for _, f := range responseFormatNames.Values() {
		if fs.Honours(f) {
			names = append(names, f.String())
		}
	}
	return names
}

func (fs ResponseFormats) MarshalJSON() ([]byte, error) { return json.Marshal(fs.Names()) }
