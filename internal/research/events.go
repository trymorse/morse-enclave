package research

import (
	"encoding/json"
	"strings"

	"morse/backend/internal/enum"
	"morse/backend/internal/jobs"
	"morse/backend/internal/web"
)

type NoteKind uint8

const (
	Plan NoteKind = iota
	Result
	Progress
)

var noteNames = enum.Names[NoteKind]{Plan: "plan", Result: "result", Progress: "status"}

func (k NoteKind) String() string { return noteNames.String(k) }

// Event is one step of a run as the client sees it. Only the constructors make one, so every event
// carries only its own type's fields, each within its cap.
type Event struct {
	wire   wireEvent
	status jobs.Status
}

type wireEvent struct {
	Type       string `json:"type"`
	Status     string `json:"status,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Message    string `json:"message,omitempty"`
	Objective  string `json:"objective,omitempty"`
	Query      string `json:"query,omitempty"`
	URL        string `json:"url,omitempty"`
	Considered *int   `json:"considered,omitempty"`
	Read       *int   `json:"read,omitempty"`
}

const stateType = "state"

func State(s jobs.Status) Event {
	return Event{wire: wireEvent{Type: stateType, Status: Statuses.String(s)}, status: s}
}

func Note(kind NoteKind, message string) (Event, bool) {
	text, ok := capped(message)
	return Event{wire: wireEvent{Type: "note", Kind: kind.String(), Message: text}}, ok
}

func Objective(objective string) (Event, bool) {
	text, ok := capped(objective)
	return Event{wire: wireEvent{Type: "search", Objective: text}}, ok
}

func Query(query string) (Event, bool) {
	text, ok := capped(query)
	return Event{wire: wireEvent{Type: "search", Query: text}}, ok
}

func Read(raw string) (Event, bool) {
	link, ok := web.PageURL(strings.TrimSpace(raw))
	return Event{wire: wireEvent{Type: "read", URL: link}}, ok
}

func Stats(considered, read int) Event {
	considered, read = max(considered, 0), max(read, 0)
	return Event{wire: wireEvent{Type: "stats", Considered: &considered, Read: &read}}
}

func (e Event) Status() (jobs.Status, bool) { return e.status, e.wire.Type == stateType }

func capped(s string) (string, bool) {
	s, _ = web.Clip(strings.TrimSpace(s), MaxMessageChars)
	return s, s != ""
}

func (e Event) MarshalJSON() ([]byte, error) { return json.Marshal(e.wire) }

func (e Event) String() string { return "research.Event(" + e.wire.Type + ")" }

func (e Event) GoString() string { return e.String() }
