package tinfoil

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"morse/backend/internal/e2ee/ehbp"
	"morse/backend/internal/e2ee/ehbp/ehbpclient"
	"morse/backend/internal/privacyveil"
	"morse/backend/internal/upstream"
)

const (
	redactPath       = "/redact"
	maxRedaction     = 4 << 20
	headerBilledCall = "X-Tinfoil-Billable-Requests"
	headerBilledIn   = "X-Tinfoil-Billable-Input-Tokens"
)

// Filter is Tinfoil's privacy filter, which finds the personal details in text inside its attested enclave. It is
// reached over a client pinned to the TLS key the enclave's report binds, and sends no text unless the gate holds a
// verified report.
type Filter struct {
	endpoint upstream.Endpoint
	gate     Gate
	// sealTo is the X25519 key of the filter's latest verified report, which every request's body is sealed to with
	// EHBP, so the text stays sealed to the attested guest even past a TLS terminator in front of it. Nil sends the
	// body in the clear, for the verify skill's stand-in alone.
	sealTo func() ([32]byte, bool)
}

var _ privacyveil.Filter = (*Filter)(nil)

func NewFilter(baseURL, apiKey string, pinned *http.Client, gate Gate, sealTo func() ([32]byte, bool)) *Filter {
	return &Filter{endpoint: upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: pinned, Refuse: refuseRedaction}, gate: gate, sealTo: sealTo}
}

// refuseRedaction names the status alone: the filter's error body can quote the text it was sent.
func refuseRedaction(r upstream.Reply) error {
	return fmt.Errorf("tinfoil: the privacy filter answered %d", r.Status)
}

func (f *Filter) Redact(ctx context.Context, text string) (privacyveil.Redaction, error) {
	if !f.gate.Ready() {
		return privacyveil.Redaction{}, privacyveil.ErrUnattested
	}
	body, _ := json.Marshal(struct {
		Text string `json:"text"`
	}{text})
	var out struct {
		Spans *[]struct {
			Label      string `json:"label"`
			Start, End int
			Text       string `json:"text"`
		} `json:"detected_spans"`
	}
	reply, err := f.send(ctx, body, &out)
	switch {
	case errors.Is(err, upstream.ErrMalformed):
		return privacyveil.Redaction{}, privacyveil.ErrMalformed
	case err != nil:
		return privacyveil.Redaction{}, err
	case out.Spans == nil:
		// A reply that does not list what it found, as one whose schema moved the list would, vouches for no text.
		return privacyveil.Redaction{}, privacyveil.ErrMalformed
	}
	r := privacyveil.Redaction{Requests: headerCount(reply.Header, headerBilledCall, 1), InputTokens: headerCount(reply.Header, headerBilledIn, 0)}
	for _, s := range *out.Spans {
		start, end, ok := privacyveil.ByteOffsets(text, s.Start, s.End)
		if !ok || text[start:end] != s.Text {
			return r, privacyveil.ErrMalformed
		}
		r.Spans = append(r.Spans, privacyveil.LabeledSpan{Start: start, End: end, Label: s.Label})
	}
	return r, nil
}

// send posts body to /redact and reads the reply into out: sealed with EHBP to the verified report's key, whose
// reply must come back sealed too, or in the clear to the stand-in. The billing headers travel in the clear.
func (f *Filter) send(ctx context.Context, body []byte, out any) (upstream.Reply, error) {
	if f.sealTo == nil {
		return f.endpoint.JSON(ctx, upstream.Request{Method: http.MethodPost, Path: redactPath, Body: body}, out, maxRedaction)
	}
	key, ok := f.sealTo()
	if !ok {
		return upstream.Reply{}, privacyveil.ErrUnattested
	}
	sealed, wire, err := ehbpclient.SealRequest(key[:], body)
	if err != nil {
		return upstream.Reply{}, err
	}
	reply, err := f.endpoint.Call(ctx, upstream.Request{Method: http.MethodPost, Path: redactPath, Body: wire,
		Header: http.Header{ehbp.HeaderEncapsulatedKey: {sealed.EncapsulatedHex()}, "Content-Type": {"application/json"}}}, maxRedaction)
	switch {
	case err != nil:
		return reply, err
	case reply.Status/100 != 2:
		return reply, refuseRedaction(reply)
	}
	opener, err := sealed.Reply(reply.Header.Get(ehbp.HeaderResponseNonce))
	if err != nil {
		return reply, upstream.ErrMalformed
	}
	plain, err := opener.OpenAll(bytes.NewReader(reply.Body))
	if err != nil || json.Unmarshal(plain, out) != nil {
		return reply, upstream.ErrMalformed
	}
	return reply, nil
}

func headerCount(h http.Header, name string, otherwise int) int {
	n, err := strconv.Atoi(h.Get(name))
	if err != nil || n < 0 {
		return otherwise
	}
	return n
}
