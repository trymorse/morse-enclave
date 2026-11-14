// Package dialect is the seam through which a chat route speaks a wire format other than Chat Completions to its
// client. A dialect decodes the client's request into a Chat Completions body, which the worker then opens, routes,
// bills, and runs as any chat, and encodes the reply, met as Chat Completions chunks, back into the client's format.
// Its errors leave in the client's envelope, whether the relay or the worker writes them.
package dialect

import (
	"bytes"
	"encoding/json"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
)

// HeaderAPIKey is where the Anthropic SDKs send an API key, which the relay and the door read as the bearer token
// when a request has no Authorization header.
const HeaderAPIKey = "X-Api-Key"

// Dialect is a client wire format. The zero Dialect is Chat Completions, which needs no decoding.
type Dialect struct {
	// Decode reads a client's request as a Chat Completions body. known says whether a model name is one the worker
	// serves, so a dialect can take a vendor's own name for a Morse model.
	Decode   func(body []byte, known func(model string) bool) (Decoded, error)
	Envelope func(apierr.Error) []byte
}

func (d Dialect) Native() bool { return d.Decode == nil }

type Decoded struct {
	Body []byte
	// Reply makes an encoder for one attempt at the reply. Each attempt begins its reply anew.
	Reply func() Encoder
}

// Event is one server-sent event: Name is its event: line, which none is written for when empty, and Data its data.
// The writer pads a JSON object's data with filler that hides its length, unless the event is Unpadded.
type Event struct {
	Name     string
	Data     []byte
	Unpadded bool
}

// Encoder writes one chat reply in a client's wire format. A stream calls Chunk for each chunk, then End once it
// completes or Failed once it fails after it began. A reply that does not stream is written whole by Whole.
type Encoder interface {
	Chunk(c chat.Chunk) []Event
	End(usage chat.Usage) []Event
	Failed(e apierr.Error) []Event
	Whole(c chat.Chunk, usage chat.Usage) []byte
}

type ChatCompletions struct{}

func (ChatCompletions) Chunk(c chat.Chunk) []Event { return []Event{{Data: chunkBytes(c)}} }

func (ChatCompletions) End(chat.Usage) []Event { return []Event{{Data: []byte("[DONE]")}} }

func (ChatCompletions) Failed(e apierr.Error) []Event {
	return []Event{{Data: e.Envelope(), Unpadded: true}}
}

func (ChatCompletions) Whole(c chat.Chunk, _ chat.Usage) []byte { return chunkBytes(c) }

func chunkBytes(c chat.Chunk) []byte {
	var b bytes.Buffer
	c.WriteTo(&b)
	return b.Bytes()
}

// ParseEnvelope reads a refusal back from the Chat Completions error envelope a reply of status carries. A body in
// another dialect's envelope, which says "type":"error" at its top, is none.
func ParseEnvelope(status int, body []byte) (apierr.Error, bool) {
	var envelope struct {
		Type  string `json:"type"`
		Error *struct {
			Message string  `json:"message"`
			Type    string  `json:"type"`
			Param   *string `json:"param"`
			Code    string  `json:"code"`
			Reason  string  `json:"reason"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil || envelope.Error == nil || envelope.Type != "" {
		return apierr.Error{}, false
	}
	e := envelope.Error
	refusal := apierr.Error{Status: status, Type: e.Type, Code: e.Code, Message: e.Message, Reason: e.Reason}
	if e.Param != nil {
		refusal.Param = *e.Param
	}
	return refusal, true
}
