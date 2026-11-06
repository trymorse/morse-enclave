package worker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee/near"
)

type verbatimValue func(json.RawMessage) bool

var verbatimFields = map[string]verbatimValue{
	"model":                 nil,
	"provider":              nil,
	"messages":              nil,
	"max_tokens":            nil,
	"max_completion_tokens": nil,
	"stream":                isBool,
	"stream_options":        isUsageOnlyStreamOptions,
	"temperature":           isNumber,
	"top_p":                 isNumber,
	"frequency_penalty":     isNumber,
	"presence_penalty":      isNumber,
	"seed":                  isInteger,
	"n":                     isOne,
	"reasoning_effort":      isReasoningEffort,
}

func isBool(raw json.RawMessage) bool {
	return string(raw) == "true" || string(raw) == "false"
}

func isNumber(raw json.RawMessage) bool {
	var n json.Number
	return raw[0] != '"' && json.Unmarshal(raw, &n) == nil
}

func isInteger(raw json.RawMessage) bool {
	var n int64
	return json.Unmarshal(raw, &n) == nil
}

func isOne(raw json.RawMessage) bool { return string(raw) == "1" }

func isReasoningEffort(raw json.RawMessage) bool {
	var effort string
	return json.Unmarshal(raw, &effort) == nil && slices.Contains(chat.EffortLadder, effort)
}

var usageStreamOptions = map[string]bool{"include_usage": true, "continuous_usage_stats": true}

func isUsageOnlyStreamOptions(raw json.RawMessage) bool {
	var opts map[string]json.RawMessage
	if json.Unmarshal(raw, &opts) != nil || opts == nil {
		return false
	}
	for key, value := range opts {
		if !usageStreamOptions[key] || !isBool(value) {
			return false
		}
	}
	return true
}

var (
	verbatimMessageKeys = map[string]bool{"role": true, "content": true}
	verbatimRoles       = map[string]bool{"system": true, "user": true, "assistant": true}
)

func (u Verbatim) admit(o *openedChat, _ chat.Cast) error {
	if o.protocol.scheme.SealsBody {
		return u.admitSealedBody(o)
	}
	asked, err := admitVerbatim(u.Route, o.first.MaxOutputTokens, o.protocol.params, o.call.Request)
	if err != nil {
		return err
	}
	o.asked = asked
	if o.writing != nil {
		return errExamplesSealed
	}
	switch {
	case o.launch != nil:
		if err := u.sealLaunch(o, o.launch.Prompt); err != nil {
			return err
		}
		o.character = o.launch.Character()
	case o.own != nil:
		// The worker can't read the name lines inside the client's seal, so the rules say "the character".
		if err := u.sealLaunch(o, o.own.Unnamed()); err != nil {
			return err
		}
		o.character = o.own.Character()
	}
	n, err := o.call.PromptTextBytes()
	o.promptBytes = hex.DecodedLen(n)
	return err
}

// admitSealedBody admits a request whose body is sealed whole, from its clear headers: the worker can check
// neither the body's fields nor put a character's prompt in front of it, and the upstream refuses a body that
// names another model than the header the route checks.
func (u Verbatim) admitSealedBody(o *openedChat) error {
	switch {
	case o.writing != nil:
		return errExamplesSealed
	case o.launch != nil, o.own != nil:
		return errCharacterSealedBody
	}
	limit := o.call.OutputLimits()[0]
	if limit > o.first.MaxOutputTokens {
		return VerbatimLimitRefused(o.first.MaxOutputTokens)
	}
	if err := u.Route.Check(o.call.Request); err != nil {
		return bodyRefusal(err)
	}
	o.asked, o.promptBytes = limit, o.call.Size()
	return nil
}

// sealLaunch seals prompt, a launch character's or an own character's rules, in front of an e2ee chat as its system
// message. The client sends its own additions as a user turn: a model takes one system message, first.
func (u Verbatim) sealLaunch(o *openedChat, prompt string) error {
	msgs, err := o.call.Messages()
	if err != nil {
		return err
	}
	if slices.ContainsFunc(msgs, func(m chat.Message) bool { return m.Role == "system" }) {
		return errLaunchSystemSealed
	}
	sealed, err := u.Route.SealPrompt(o.protocol.params, prompt)
	if err != nil {
		return err
	}
	if o.protocol.scheme == near.Scheme {
		o.promptComment = near.PromptComment(sealed)
	}
	o.call.Request, err = o.call.Request.Prepend("system", sealed)
	return err
}

func (u Verbatim) serve(ctx context.Context, w *InProcess, o *openedChat, a attempt, reply http.ResponseWriter) served {
	s, unexpected := relay(ctx, reply, http.NewResponseController(reply), u.Route, a.call, o.protocol.params, o.promptComment, !o.protocol.scheme.SealsBody, o.afterCut)
	for _, field := range unexpected {
		w.reports.UnknownReplyField(a.call.Model, field)
	}
	// A reply sealed whole is read to its end even once its caller left, so any that ends without the router's
	// usage lacks it.
	if o.protocol.scheme.SealsBody && s.callErr == nil && s.reported == (chat.Usage{}) {
		w.reports.VendorUsageMissing(o.call.Model)
	}
	return s
}

func (Verbatim) count(attempt, measure.Evidence, served) *pendingCount { return nil }

// admitVerbatim answers the output limit the request asks for.
func admitVerbatim(rel chat.Relayer, maxOutputTokens int, params chat.E2EE, req *chat.Request) (int, error) {
	if provider, sent := req.Field("provider"); sent && namesFloor(provider) {
		return 0, errFloorSealed
	}
	for _, field := range req.FieldNames() {
		checkedHere, ok := verbatimFields[field]
		if raw, _ := req.Field(field); !ok || checkedHere != nil && !checkedHere(raw) {
			return 0, fieldRefused(field)
		}
	}
	limits := req.OutputLimits()
	if len(limits) == 0 {
		return 0, errE2EEOutputLimitRequired
	}
	if slices.ContainsFunc(limits, func(n int) bool { return n > maxOutputTokens }) || len(limits) == 2 && limits[0] != limits[1] {
		return 0, VerbatimLimitRefused(maxOutputTokens)
	}
	messages, err := req.Messages()
	switch {
	case errors.Is(err, chat.ErrMessageRole):
		return 0, fieldRefused("messages.role")
	case err != nil || len(messages) == 0:
		return 0, errE2EEContentNotEncrypted
	}
	for _, message := range messages {
		for _, key := range message.Keys() {
			if !verbatimMessageKeys[key] {
				return 0, fieldRefused("messages." + key)
			}
		}
		if !verbatimRoles[message.Role] {
			return 0, fieldRefused("messages.role")
		}
		if !params.IsCiphertext(message.Raw("content")) {
			return 0, errE2EEContentNotEncrypted
		}
	}
	if err := rel.Check(req); err != nil {
		return 0, bodyRefusal(err)
	}
	return limits[0], nil
}

// relay pads an event stream with comment lines unless the reply is sealed whole, as its frames take none. A
// non-nil afterCut reads on after the caller left (see relayWriter.afterCut).
func relay(ctx context.Context, w http.ResponseWriter, rc *http.ResponseController, rel chat.Relayer, c chat.Call, params chat.E2EE, lead []byte, pad bool, d *afterCut) (served, []string) {
	rw := &relayWriter{w: w, rc: rc, pad: pad, lead: lead, afterCut: d}
	replied, err := rel.Relay(ctx, c, params, func(head chat.Relayed) io.Writer {
		params.WriteApplied(w.Header().Set)
		return rw.begin(head)
	})
	events := replied.Events
	if replied.Tokens > 0 {
		events = replied.Tokens
	}
	s := served{reported: replied.Usage, reply: rw.reply(events), writeErr: rw.err, callErr: err}
	if replied.Prove != nil {
		s.reported = chat.Usage{VendorCost: replied.Usage.VendorCost}
		s.unproven = &unproven{usage: replied.Usage, prove: replied.Prove}
	}
	return s, replied.UnknownFields
}

type unproven struct {
	usage chat.Usage
	prove func(context.Context) error
}

func (rw *relayWriter) reply(events int) measure.Reply {
	if !rw.eventStream && rw.written > 0 {
		return measure.Opaque{}
	}
	return measure.SealedEvents{Events: events}
}

var (
	errE2EEContentNotEncrypted = apierr.Error{Status: http.StatusBadRequest, Type: "e2ee_content_not_encrypted", Code: "e2ee_content_not_encrypted", Message: "Every message must carry only role and content, and content must be one E2EE v2 ciphertext string."}
	errE2EEOutputLimitRequired = apierr.Error{Status: http.StatusBadRequest, Type: "e2ee_output_limit_required", Code: "e2ee_output_limit_required", Message: "On e2ee models, set max_tokens or max_completion_tokens to a positive integer, because the proxy forwards the body verbatim and cannot add a limit, so the upstream's own default would govern how much it generates."}
	errCharacterSealedBody     = apierr.Error{Status: http.StatusBadRequest, Type: "character_unsealable", Code: "character_unsealable", Message: "This e2ee model seals the whole request on the device, so the proxy can't put a character's prompt in front of it. Chat with the character on another e2ee model."}
	ErrE2EENotApplied          = apierr.Error{Status: http.StatusBadGateway, Type: "upstream_error", Code: "e2ee_not_applied", Message: "The upstream did not confirm end-to-end encryption, so the proxy withheld its reply."}
)

func bodyRefusal(err error) apierr.Error {
	var m *chat.Mismatch
	if !errors.As(err, &m) {
		return apierr.ErrInvalidBody
	}
	if m.Want == nil {
		return fieldRefused(m.Field)
	}
	return apierr.Error{Status: http.StatusBadRequest, Type: "e2ee_body_mismatch", Code: "e2ee_body_mismatch", Message: "Field " + m.Field + " must equal " + string(m.Want) + " on e2ee models, because the proxy forwards the body verbatim and cannot set it."}
}

func fieldRefused(field string) apierr.Error {
	return apierr.Error{Status: http.StatusBadRequest, Type: "e2ee_field_refused", Code: "e2ee_field_refused", Message: "Field " + field + " is refused on e2ee models, which forward the body verbatim and so admit only the fields and values of the e2ee client contract."}
}

func VerbatimLimitRefused(maxOutputTokens int) apierr.Error {
	return apierr.Error{Status: http.StatusBadRequest, Type: "e2ee_output_limit_refused", Code: "e2ee_output_limit_refused", Message: "On this e2ee model, max_tokens and max_completion_tokens may be at most " + strconv.Itoa(maxOutputTokens) + " and must be equal when both are set, because the proxy forwards the body verbatim and cannot lower them."}
}
