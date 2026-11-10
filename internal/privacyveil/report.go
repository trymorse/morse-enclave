package privacyveil

import "encoding/json"

// MaxReport is the largest report a reply carries. Past it, entities are dropped from the end and Truncated says so.
const MaxReport = 32 << 10

// Report is what the Veil did to one request, for its client: the parts it sent as written, the placeholders it left
// in tool calls, and, when the client asks, every detail and its placeholder.
type Report struct {
	Unveiled  []string `json:"unveiled,omitempty"`
	Held      []Held   `json:"held,omitempty"`
	Entities  []Entity `json:"entities,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// Held is a tool call whose arguments kept placeholders.
type Held struct {
	ToolCall     int      `json:"tool_call"`
	Placeholders []string `json:"placeholders"`
}

// JSON is the report, cut to MaxReport.
func (r Report) JSON() []byte {
	for {
		out, _ := json.Marshal(r)
		if len(out) <= MaxReport || len(r.Entities) == 0 && len(r.Held) == 0 {
			return out
		}
		r.Truncated = true
		if len(r.Entities) > 0 {
			r.Entities = r.Entities[:len(r.Entities)/2]
		} else {
			r.Held = r.Held[:len(r.Held)/2]
		}
	}
}

func (r Report) String() string   { return "privacyveil.Report" }
func (r Report) GoString() string { return r.String() }
