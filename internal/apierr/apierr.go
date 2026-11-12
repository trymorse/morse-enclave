package apierr

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

const MaxErrorBody = 64 << 10

type Error struct {
	Status  int
	Type    string
	Code    string
	Message string
	Reason  string
	Param   string
}

func (e Error) Error() string { return fmt.Sprintf("%d %s", e.Status, e.Code) }

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    string  `json:"code"`
	Reason  string  `json:"reason,omitempty"`
}

func (e Error) Envelope() []byte {
	var param *string
	if e.Param != "" {
		param = &e.Param
	}
	body, _ := json.Marshal(errorEnvelope{errorBody{Message: e.Message, Type: e.Type, Param: param, Code: e.Code, Reason: e.Reason}})
	return body
}

func (e Error) Naming(param string) Error {
	e.Param = param
	return e
}

func (e Error) EnvelopeWith(field string, value any) []byte {
	envelope := map[string]any{}
	json.Unmarshal(e.Envelope(), &envelope)
	envelope[field] = value
	body, _ := json.Marshal(envelope)
	return body
}

func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func WriteError(w http.ResponseWriter, e Error) { WriteEnvelope(w, e.Status, e.Envelope()) }

func WriteEnvelope(w http.ResponseWriter, status int, envelope []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(envelope)
}

func SetRetryAfter(w http.ResponseWriter, retryAfter time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(retryAfter.Seconds())))))
}

func Invalid(status int, code, message string) Error {
	return Error{Status: status, Type: "invalid_request_error", Code: code, Message: message}
}

func Unfunded(message string) Error {
	return Error{Status: 402, Type: "insufficient_balance", Code: "insufficient_balance", Message: message}
}

func Limited(code, message string) Error {
	return Error{Status: 429, Type: "requests", Code: code, Message: message}
}

var (
	ErrContextLengthExceeded = Invalid(400, "context_length_exceeded", "The conversation is too long for this model.")
	ErrContentFilter         = Invalid(400, "content_filter", "The model provider declined this request.")
	ErrInvalidRequest        = Invalid(400, "invalid_request", "The model provider rejected the request.")
	ErrMalformedRequest      = Invalid(400, "invalid_request", "A message, part, or tool has a shape this model does not take. The proxy refused the request before sending it to the model provider.")
	ErrRemoteMedia           = Invalid(400, "remote_media", "Media must be attached as inline data, not linked by URL.")
	ErrRequestTooLarge       = Invalid(413, "request_too_large", "Request body is too large.")
	ErrUpstreamUnavailable   = Error{Status: 502, Type: "upstream_error", Code: "upstream_unavailable", Message: "The model provider is unavailable."}
	ErrUpstreamRefused       = Error{Status: 502, Type: "upstream_error", Code: "upstream_refused", Message: "The model provider refused this request."}
	ErrUpstreamBusy          = Error{Status: 503, Type: "upstream_error", Code: "upstream_busy", Message: "The model provider is busy. Try again shortly."}
	ErrUpstream              = Error{Status: 502, Type: "upstream_error", Code: "upstream_error", Message: "The upstream model server failed."}
	ErrUnattested            = Error{Status: 503, Type: "upstream_error", Code: "upstream_unattested", Message: "The attested model endpoint could not be verified. Try again shortly."}
	ErrUpstreamRetention     = Error{Status: 502, Type: "upstream_error", Code: "upstream_retention", Message: "The model provider did not confirm zero data retention."}
	ErrModelNotFound         = Invalid(404, "model_not_found", "The requested model does not exist.")
	ErrInvalidBody           = Invalid(400, "invalid_request_body", "Request body must be a JSON object with a non-empty string model.")
	ErrUnavailable           = Error{Status: 503, Type: "server_error", Code: "service_unavailable", Message: "The service is temporarily unable to authorize requests. Try again shortly."}
	ErrShuttingDown          = Error{Status: 503, Type: "server_error", Code: "service_unavailable", Message: "The service is restarting and cut this request before it began. Retry it."}
)

func InvalidParameter(message string) Error { return Invalid(400, "invalid_parameter", message) }

type Family struct{ Busy, Unavailable, Failed Error }

func (f Family) Of(status int) Error {
	switch status {
	case 429:
		return f.Busy
	case 402:
		return f.Unavailable
	}
	return f.Failed
}

type Table map[error]Error

func (t Table) Of(err error) error {
	if refusal, ok := t.Find(err); ok {
		return refusal
	}
	return err
}

func (t Table) Find(err error) (Error, bool) {
	for sentinel, refusal := range t {
		if errors.Is(err, sentinel) {
			return refusal, true
		}
	}
	return Error{}, false
}

func Refusal(err error, fallback Error) (refusal Error, carried bool) {
	if errors.As(err, &refusal) {
		return refusal, true
	}
	return fallback, false
}

var vendorCodes = map[string]Error{
	"context_length_exceeded":        ErrContextLengthExceeded,
	"content_filter":                 ErrContentFilter,
	"content_policy_violation":       ErrContentFilter,
	"invalid_prompt":                 ErrContentFilter,
	"bio_policy":                     ErrContentFilter,
	"misalignment_policy_violation":  ErrContentFilter,
	"image_content_policy_violation": ErrContentFilter,
	"rate_limit_exceeded":            ErrUpstreamBusy,
	"rate_limit_error":               ErrUpstreamBusy,
	"server_is_overloaded":           ErrUpstreamBusy,
	"overloaded_error":               ErrUpstreamBusy,
	"insufficient_quota":             ErrUpstreamUnavailable,
	"credit_balance_exhausted":       ErrUpstreamUnavailable,
	"model_forbidden":                ErrUpstreamUnavailable,
	"model_zdr_not_supported":        ErrUpstreamUnavailable,
	"invalid_image":                  ErrInvalidRequest,
	"invalid_image_format":           ErrInvalidRequest,
	"invalid_base64_image":           ErrInvalidRequest,
	"invalid_image_url":              ErrInvalidRequest,
	"image_too_large":                ErrInvalidRequest,
	"image_too_small":                ErrInvalidRequest,
	"image_parse_error":              ErrInvalidRequest,
	"invalid_image_mode":             ErrInvalidRequest,
	"image_file_too_large":           ErrInvalidRequest,
	"unsupported_image_media_type":   ErrInvalidRequest,
	"empty_image_file":               ErrInvalidRequest,
	"failed_to_download_image":       ErrInvalidRequest,
	"image_file_not_found":           ErrInvalidRequest,
}

func VendorCode(code string) (Error, bool) {
	e, ok := vendorCodes[code]
	return e, ok
}

var contextOverflowMessages = []*regexp.Regexp{
	regexp.MustCompile(`^prompt is too long(?:: \d+ tokens > (?P<window>\d+) maximum)?`),
	regexp.MustCompile(`^The input token count (?:\(\d+\) )?exceeds the maximum number of tokens allowed(?: \(?(?P<window>\d+)\)?)?`),
	regexp.MustCompile(`^This (?:model|endpoint)'s maximum (?:context|prompt) length is (?P<window>\d+)`),
	regexp.MustCompile(`^'max_tokens' or 'max_completion_tokens' is too large: \d+\. This model's maximum context length is (?P<window>\d+)`),
	regexp.MustCompile(`^Input length \(\d+\) exceeds model's maximum context length(?: \((?P<window>\d+)\))?`),
	regexp.MustCompile(`^The input \(\d+ tokens\) is longer than the model's context length(?: \((?P<window>\d+) tokens\))?`),
	regexp.MustCompile(`^Requested token count exceeds the model's maximum context length(?: of (?P<window>\d+) tokens)?`),
}

// unservedModel is Morph's 400 for a model it does not serve, where Together answers 404. The model is the route's,
// never the client's, so it is a refusal, not the client's invalid request.
var unservedModel = regexp.MustCompile(`^Model '[^']*' is not served by this endpoint`)

type vendorReply struct {
	codes   []string
	message string
}

func readVendorReply(body []byte) (vendorReply, bool) {
	var top struct {
		Error   json.RawMessage `json:"error"`
		Message json.RawMessage `json:"message"`
	}
	if json.Unmarshal(body, &top) != nil {
		return vendorReply{}, false
	}
	if message := text(top.Error); message != "" {
		return vendorReply{message: message}, true
	}
	var nested struct {
		Code, Type, Message json.RawMessage
	}
	json.Unmarshal(top.Error, &nested)
	r := vendorReply{codes: []string{text(nested.Code), text(nested.Type)}, message: text(nested.Message)}
	if r.message == "" {
		r.message = text(top.Message)
	}
	return r, true
}

func text(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func (r vendorReply) overflowsContext() bool {
	for _, pattern := range contextOverflowMessages {
		if pattern.MatchString(r.message) {
			return true
		}
	}
	return false
}

// StatedWindow is the context window that a vendor's refusal of a prompt as too long states, or 0 when the refusal
// states none or is not one.
func StatedWindow(status int, vendorBody []byte) int {
	if SanitizedUpstreamError(status, vendorBody) != ErrContextLengthExceeded {
		return 0
	}
	reply, _ := readVendorReply(vendorBody)
	for _, pattern := range contextOverflowMessages {
		if m := pattern.FindStringSubmatch(reply.message); m != nil {
			window, _ := strconv.Atoi(m[pattern.SubexpIndex("window")])
			return window
		}
	}
	return 0
}

func SanitizedUpstreamError(status int, vendorBody []byte) Error {
	if reply, ok := readVendorReply(vendorBody); status/100 == 4 && ok {
		for _, code := range reply.codes {
			if e, ok := VendorCode(code); ok {
				return e
			}
		}
		if status == 400 && reply.overflowsContext() {
			return ErrContextLengthExceeded
		}
		if status == 400 && unservedModel.MatchString(reply.message) {
			return ErrUpstreamRefused
		}
	}
	switch {
	case status == 413:
		return ErrRequestTooLarge
	case status == 429 || status == 503 || status == 529:
		return ErrUpstreamBusy
	case status == 401 || status == 402:
		return ErrUpstreamUnavailable
	case status == 403 || status == 404:
		return ErrUpstreamRefused
	case status/100 == 4:
		return ErrInvalidRequest
	default:
		return ErrUpstream
	}
}
