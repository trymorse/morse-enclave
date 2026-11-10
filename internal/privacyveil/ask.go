package privacyveil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Restore says where the values go back in a reply.
type Restore uint8

const (
	// RestoreProse puts every value back, but in a tool call's arguments, where only a grant releases one.
	RestoreProse Restore = iota
	// RestoreNone leaves every placeholder as written, for a client that restores from the report itself.
	RestoreNone
)

// Ask is a request's privacy_veil: whether it asks for the Veil, and how.
type Ask struct {
	On      bool
	Report  bool
	Restore Restore
	release []grant
}

type grant struct {
	tool  string
	all   bool
	types map[Type]bool
}

// ErrAsk is a privacy_veil that is not true, false, null, or an object of report, restore and release.
var ErrAsk = errors.New(`privacy_veil must be true, false, null, or {"report": bool, "restore": "prose" or "none", "release": [{"tool": name, "types": [...]}]}`)

const wildcard = "*"

// ParseAsk reads a privacy_veil. An absent or null one asks for nothing.
func ParseAsk(raw json.RawMessage) (Ask, error) {
	raw = bytes.TrimSpace(raw)
	switch string(raw) {
	case "", "null", "false":
		return Ask{}, nil
	case "true":
		return Ask{On: true}, nil
	}
	if len(raw) == 0 || raw[0] != '{' {
		return Ask{}, ErrAsk
	}
	var object struct {
		Report  *bool   `json:"report"`
		Restore *string `json:"restore"`
		Release []struct {
			Tool  string   `json:"tool"`
			Types []string `json:"types"`
		} `json:"release"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&object) != nil || dec.More() {
		return Ask{}, ErrAsk
	}
	ask := Ask{On: true, Report: object.Report != nil && *object.Report}
	if object.Restore != nil {
		switch *object.Restore {
		case "prose":
		case "none":
			ask.Restore = RestoreNone
		default:
			return Ask{}, ErrAsk
		}
	}
	for _, r := range object.Release {
		if r.Tool == "" || len(r.Types) == 0 {
			return Ask{}, fmt.Errorf("%w: a release names a tool, or %q, and its types", ErrAsk, wildcard)
		}
		g := grant{tool: r.Tool, types: map[Type]bool{}}
		for _, name := range r.Types {
			if name == wildcard {
				g.all = true
				continue
			}
			t, ok := ParseType(name)
			if !ok {
				return Ask{}, fmt.Errorf("%w: %q is not a type; the types are %s and %q", ErrAsk, name, typeNames.List(), wildcard)
			}
			g.types[t] = true
		}
		ask.release = append(ask.release, g)
	}
	return ask, nil
}

// Releases is which types of value go back into a call of tool's arguments: those a grant for the tool, or for
// every tool, names, and with a wildcard every type but the sensitive ones, which a grant must name.
func (a Ask) Releases(tool string) func(Type) bool {
	return func(t Type) bool {
		if a.Restore == RestoreNone {
			return false
		}
		for _, g := range a.release {
			if g.tool != tool && g.tool != wildcard {
				continue
			}
			if g.types[t] || g.all && !t.Sensitive() {
				return true
			}
		}
		return false
	}
}
