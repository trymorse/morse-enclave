package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/dialect/messages"
	"morse/backend/internal/tokenizer"
)

const TokenCountPattern = "POST /v1/messages/count_tokens"

type TokenCountAdmission struct {
	admitted
	Model      catalog.ModelID
	Candidates []catalog.EndpointID
}

func (TokenCountAdmission) kind() admissionKind { return admitsTokenCount }

type TokenCountGrant struct{}

func (TokenCountGrant) kind() grantKind { return grantsTokenCount }

type openedTokenCount struct {
	cuts
	request *chat.Request
	counter *tokenizer.Tokenizer
}

func (w *InProcess) openTokenCount(o Opening) (Admission, error) {
	protocol := protocolOf(o.Header.Get)
	if o.KeyCaller && protocol.scheme != nil {
		return nil, catalog.ErrKeyE2EE
	}
	decoded, err := w.decode(o, protocol, messages.CountDialect)
	if err != nil {
		return nil, err
	}
	req, err := chat.ParseRequest(bytes.NewReader(decoded.Body))
	if err != nil {
		return nil, contentRefusal(err)
	}
	name, known := w.chats[req.Model]
	if !known {
		return nil, apierr.ErrModelNotFound
	}
	if o.KeyCaller {
		if name.sealedOnly() {
			return nil, catalog.ErrKeyE2EE
		}
		if want, err := floorOf(req); err == nil && want.floor.Sealed() {
			return nil, catalog.FloorError{Floor: want.floor, KeyCaller: true}
		}
		if o.KeyFloor.Sealed() {
			return nil, catalog.FloorError{Floor: o.KeyFloor, Key: true, KeyCaller: true}
		}
	}
	routes := slices.Concat(name.named, name.plaintext)
	counted := slices.IndexFunc(routes, func(r chatRoute) bool { return r.Counter != nil })
	oc := &openedTokenCount{cuts: newCuts(), request: req}
	if counted >= 0 {
		oc.counter = routes[counted].Counter
	}
	return TokenCountAdmission{admitted: admitted{w.keep(o, oc)}, Model: name.model, Candidates: endpointsOf(routes)}, nil
}

func (o *openedTokenCount) cut(reason measure.Cut) { o.cuts.cut(reason, true) }

func (o *openedTokenCount) run(_ context.Context, _ *InProcess, _ Handle, g Grant, reply http.ResponseWriter) Measured {
	if _, ok := g.(TokenCountGrant); !ok {
		return unrunnable(reply)
	}
	counted, err := json.Marshal(struct {
		InputTokens int `json:"input_tokens"`
	}{o.inputTokens(o.cuts.run)})
	writeErr := err
	if err == nil {
		writeErr = writeJSONBody(newReplyWriter(reply), func(out io.Writer) error {
			_, err := out.Write(counted)
			return err
		})
	}
	end := endingOf(o.cuts.client, writeErr, nil)
	return Measured{Measurement: measure.Measurement{Outcome: end.outcome()}, Cut: end.cut(), Served: writeErr == nil}
}

func (o *openedTokenCount) inputTokens(ctx context.Context) int {
	attachments, attachmentBytes, err := o.request.Attachments()
	if err != nil {
		attachments, attachmentBytes = 0, 0
	}
	estimate := measure.BytesEstimate(o.request.Size()-attachmentBytes) + attachments*measure.AttachmentTokens
	if n, ok := o.tokenized(ctx); ok {
		return min(n, estimate)
	}
	return estimate
}

func (o *openedTokenCount) tokenized(ctx context.Context) (int, bool) {
	texts, messages, ok := o.request.RenderedPromptTexts()
	if o.counter == nil || !ok {
		return 0, false
	}
	n := measure.TemplateTokensPerMessage * (messages + 2)
	for _, text := range texts {
		tokens, err := o.counter.Count(ctx, text)
		if err != nil {
			return 0, false
		}
		n += tokens
	}
	return n, true
}
