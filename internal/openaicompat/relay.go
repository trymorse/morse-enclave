package openaicompat

import (
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"reflect"
	"slices"

	"morse/backend/internal/capped"
	"morse/backend/internal/chat"
	"morse/backend/internal/completions"
	"morse/backend/internal/sse"
	"morse/backend/internal/upstream"
)

type Relay struct {
	upstream.Endpoint
	Model string
	Force map[string]json.RawMessage
	// Admits widens a forced field to every value its func accepts, beside the forced one.
	Admits  map[string]func(json.RawMessage) bool
	Receipt Receipt
}

var _ chat.Relayer = (*Relay)(nil)

// A Receipt names a reply's receipt headers once it can. The relay asks it with the upstream's response
// headers and each frame's event, nil for a frame of comments, and begins the reply on the first answer that
// is named, writing what it held before.
type Receipt func(upstream http.Header, event []byte) (headers []chat.Header, named bool)

// ReceiptHeaders relays the response headers it names, so the reply begins on its first frame.
func ReceiptHeaders(names ...string) Receipt {
	return func(upstream http.Header, _ []byte) ([]chat.Header, bool) {
		var out []chat.Header
		for _, name := range names {
			if value := upstream.Get(name); value != "" {
				out = append(out, chat.Header{Name: name, Value: value})
			}
		}
		return out, true
	}
}

// ReceiptFromReplyID names the receipt by the first event's id, so the reply begins on its first event.
func ReceiptFromReplyID(_ http.Header, event []byte) ([]chat.Header, bool) {
	if event == nil {
		return nil, false
	}
	if id := replyID(event); id != "" {
		return []chat.Header{{Name: chat.HeaderReceiptID, Value: id}}, true
	}
	return nil, true
}

func (r *Relay) Check(req *chat.Request) error {
	want := pinned(r.Model, r.Force)
	if req.Stream {
		want["stream_options"] = verbatimStreamOptions(req)
	}
	for _, name := range slices.Sorted(maps.Keys(want)) {
		got, ok := req.Field(name)
		if admits := r.Admits[name]; ok && admits != nil && admits(got) {
			continue
		}
		if !ok || !jsonEqual(got, want[name]) {
			return &chat.Mismatch{Field: name, Want: want[name]}
		}
	}
	if _, sent := req.Field("provider"); sent && want["provider"] == nil {
		return &chat.Mismatch{Field: "provider"}
	}
	return nil
}

func verbatimStreamOptions(req *chat.Request) json.RawMessage {
	var opts map[string]json.RawMessage
	if raw, ok := req.Field("stream_options"); ok {
		json.Unmarshal(raw, &opts)
	}
	if opts == nil {
		opts = map[string]json.RawMessage{}
	}
	opts["include_usage"] = json.RawMessage("true")
	delete(opts, "include_obfuscation")
	out, _ := json.Marshal(opts)
	return out
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}

func (r *Relay) Relay(ctx context.Context, c chat.Call, sealed chat.E2EE, begin func(chat.Relayed) io.Writer) (chat.Replied, error) {
	accept := "application/json"
	if c.Stream {
		accept = "text/event-stream"
	}
	header := http.Header{"Accept": {accept}}
	sealed.Forward(header.Set)
	resp, err := r.Open(ctx, upstream.Request{Method: http.MethodPost, Path: chatCompletionsPath, Header: header, Body: c.Verbatim()})
	if err != nil {
		return chat.Replied{}, err
	}
	defer resp.Body.Close()
	if err := sealed.Confirm(resp.Header.Get); err != nil {
		return chat.Replied{}, err
	}
	head := chat.Relayed{ContentType: resp.Header.Get("Content-Type")}
	var w io.Writer
	var held []byte
	write := func(frame, event []byte) error {
		if w == nil {
			headers, named := r.Receipt(resp.Header, event)
			if !named {
				if held = append(held, frame...); len(held) > maxEvent {
					return sse.ErrTooLarge
				}
				return nil
			}
			head.Headers = headers
			w = begin(head)
			frame = append(held, frame...)
		}
		_, err := w.Write(frame)
		return err
	}
	g := gate{sealed: sealed}
	if !c.Stream {
		body, err := capped.ReadAll(resp.Body, MaxCompletionBody)
		if err != nil {
			return chat.Replied{}, err
		}
		if !g.passes(body) {
			return chat.Replied{}, chat.ErrUnsealedReply
		}
		if err := write(body, body); err != nil {
			return chat.Replied{}, err
		}
		replied := chat.Replied{UnknownFields: g.unknown}
		var peek usagePeek
		if json.Unmarshal(body, &peek); peek.Usage != nil {
			replied.Usage = peek.Usage.Domain()
		}
		return replied, nil
	}
	var tap usageTap
	err = relayGated(resp.Body, &g, write, &tap)
	return chat.Replied{Usage: tap.last, Events: tap.events, UnknownFields: g.unknown}, err
}

func replyID(event []byte) string {
	var reply struct{ ID string }
	json.Unmarshal(event, &reply)
	return reply.ID
}

type usagePeek struct {
	Usage *completions.Usage `json:"usage"`
}

type usageTap struct {
	last   chat.Usage
	events int
}

func (t *usageTap) event(data []byte) (done bool) {
	if isDone(data) {
		return true
	}
	t.events++
	var peek usagePeek
	if json.Unmarshal(data, &peek) == nil && peek.Usage != nil {
		t.last = peek.Usage.Domain()
	}
	return false
}
