package worker

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/enum"
	"morse/backend/internal/seal"
	"morse/backend/internal/taskseal"
	"morse/backend/internal/worker/taskrun"
)

const (
	headerMethod        = "Worker-Method"
	headerPath          = "Worker-Path"
	headerQuery         = "Worker-Query"
	headerOpening       = "Worker-Opening"
	headerVendorID      = "Worker-Vendor-Id"
	headerMeasured      = "Worker-Measured"
	headerContentLength = "Worker-Content-Length"
	headerVendorStatus  = "Worker-Vendor-Status"
	headerKeyID         = "Worker-Key-Id"
	headerTaskEpoch     = "Worker-Task-Epoch"
	headerTaskKey       = "Worker-Task-Key"
	taskKeyPending      = "pending"
)

func (h Handle) MarshalJSON() ([]byte, error) { return json.Marshal(h.id) }

func (h *Handle) UnmarshalJSON(data []byte) error { return json.Unmarshal(data, &h.id) }

type admissionKind uint8

const (
	admitsChat admissionKind = iota
	admitsMedia
	admitsCall
	admitsRead
	admitsLookup
	admitsPlugin
	admitsTask
)

var admissionKindNames = enum.Names[admissionKind]{
	admitsChat: "chat", admitsMedia: "media", admitsCall: "call", admitsRead: "read", admitsLookup: "lookup", admitsPlugin: "plugin", admitsTask: "task",
}

func (k admissionKind) MarshalText() ([]byte, error) { return admissionKindNames.MarshalText(k) }

func (k *admissionKind) UnmarshalText(text []byte) error {
	return admissionKindNames.UnmarshalText(k, text)
}

type grantKind uint8

const (
	grantsChat grantKind = iota
	grantsMedia
	grantsCall
	grantsVideoRead
	grantsResearchRead
	grantsResearchEvents
	grantsLookup
	grantsPlugin
)

var grantKindNames = enum.Names[grantKind]{
	grantsChat: "chat", grantsMedia: "media", grantsCall: "call",
	grantsVideoRead: "video_read", grantsResearchRead: "research_read", grantsResearchEvents: "research_events", grantsLookup: "lookup",
	grantsPlugin: "plugin",
}

func (k grantKind) MarshalText() ([]byte, error) { return grantKindNames.MarshalText(k) }

func (k *grantKind) UnmarshalText(text []byte) error { return grantKindNames.UnmarshalText(k, text) }

type envelope[K any] struct {
	Kind    K               `json:"kind"`
	Handle  Handle          `json:"handle"`
	Fields  json.RawMessage `json:"fields"`
	Pattern string          `json:"pattern,omitempty"`
}

func enveloped[K any](k K, h Handle, v any, pattern string) (envelope[K], error) {
	fields, err := json.Marshal(v)
	return envelope[K]{Kind: k, Handle: h, Fields: fields, Pattern: pattern}, err
}

func decodeAdmission[A Admission, P interface {
	*A
	take(Handle)
}](e envelope[admissionKind]) (Admission, error) {
	var a A
	err := json.Unmarshal(e.Fields, &a)
	P(&a).take(e.Handle)
	return a, err
}

func decodeGrant[G Grant](e envelope[grantKind]) (Grant, error) {
	var g G
	err := json.Unmarshal(e.Fields, &g)
	return g, err
}

var admissionOfKind = map[admissionKind]func(envelope[admissionKind]) (Admission, error){
	admitsChat:   decodeAdmission[ChatAdmission, *ChatAdmission],
	admitsMedia:  decodeAdmission[MediaAdmission, *MediaAdmission],
	admitsCall:   decodeAdmission[CallAdmission, *CallAdmission],
	admitsRead:   decodeAdmission[ReadAdmission, *ReadAdmission],
	admitsLookup: decodeAdmission[LookupAdmission, *LookupAdmission],
	admitsPlugin: decodeAdmission[PluginAdmission, *PluginAdmission],
	admitsTask:   decodeAdmission[TaskAdmission, *TaskAdmission],
}

var grantOfKind = map[grantKind]func(envelope[grantKind]) (Grant, error){
	grantsChat:           decodeGrant[ChatGrant],
	grantsMedia:          decodeGrant[MediaGrant],
	grantsCall:           decodeGrant[CallGrant],
	grantsVideoRead:      decodeGrant[VideoReadGrant],
	grantsResearchRead:   decodeGrant[ResearchReadGrant],
	grantsResearchEvents: decodeGrant[ResearchEventsGrant],
	grantsLookup:         decodeGrant[LookupGrant],
	grantsPlugin:         decodeGrant[PluginGrant],
}

func admissionWire(a Admission, pattern string) ([]byte, error) {
	e, err := enveloped(a.kind(), a.Handle(), a, pattern)
	if err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

func admissionOf(data []byte) (SealedAdmission, error) {
	var e envelope[admissionKind]
	if err := json.Unmarshal(data, &e); err != nil {
		return SealedAdmission{}, err
	}
	a, err := admissionOfKind[e.Kind](e)
	return SealedAdmission{Pattern: e.Pattern, Admission: a}, err
}

func grantWire(h Handle, g Grant) (envelope[grantKind], error) { return enveloped(g.kind(), h, g, "") }

func grantOf(data []byte) (Handle, Grant, error) {
	var e envelope[grantKind]
	if err := json.Unmarshal(data, &e); err != nil {
		return Handle{}, nil, err
	}
	g, err := grantOfKind[e.Kind](e)
	return e.Handle, g, err
}

type handleRequest struct {
	Handle Handle `json:"handle"`
}

type taskAdoptRequest struct {
	Handle   Handle `json:"handle"`
	Revision int64  `json:"revision"`
}

type submitRequest struct {
	Handle Handle   `json:"handle"`
	Grant  JobGrant `json:"grant"`
}

type cutRequest struct {
	Handle Handle      `json:"handle"`
	Reason measure.Cut `json:"reason"`
}

type pollRequest struct {
	Route    string    `json:"route"`
	VendorID string    `json:"vendor_id"`
	Deadline time.Time `json:"deadline"`
}

const WireVersion = 5

type Served struct {
	Digest string `json:"digest"`
	Wire   int    `json:"wire"`
}

type evidenceRequest struct {
	Vendor
	Nonce string `json:"nonce,omitempty"`
	V3    bool   `json:"v3,omitempty"`
	Code  bool   `json:"code,omitempty"`
	ID    string `json:"id,omitempty"`
}

func (r evidenceRequest) format() Format {
	switch {
	case r.V3 && r.Code:
		return FormatV3Code
	case r.V3:
		return FormatV3
	}
	return FormatReport
}

func attestRequest(v Vendor, nonce string, f Format) evidenceRequest {
	return evidenceRequest{Vendor: v, Nonce: nonce, V3: f != FormatReport, Code: f == FormatV3Code}
}

// A report crosses as bytes, not as JSON, so the client gets the gateway's exact bytes back.
type attestationWire struct {
	Report      []byte           `json:"report"`
	BindModel   string           `json:"bind_model"`
	GPUVerdicts []byte           `json:"gpu_verdicts,omitempty"`
	VendorPins  *chat.VendorPins `json:"vendor_pins,omitempty"`
}

type sessionsWire struct {
	Sessions []chat.ListedSession `json:"sessions"`
}

type openingWire struct {
	Prompts     []chat.PromptHash `json:"prompts,omitempty"`
	Rules       string            `json:"rules,omitempty"`
	Launch      *chat.Launch      `json:"launch,omitempty"`
	Own         *chat.OwnFrame    `json:"own,omitempty"`
	Writing     *chat.Writing     `json:"writing,omitempty"`
	KeyCaller   bool              `json:"key_caller,omitempty"`
	KeyFloor    string            `json:"key_floor,omitempty"`
	KeySettings bool              `json:"key_settings,omitempty"`
	Veil        VeilOpening       `json:"privacy_veil,omitzero"`
	keyFloor    catalog.Tier
}

func setOpening(header http.Header, c chat.Cast, f Framing, keyCaller bool, keyFloor catalog.Tier, keySettings bool, veil VeilOpening) {
	o := openingWire{Prompts: c.Prompts(), Rules: c.Rules(), Launch: f.Launch, Own: f.Own, Writing: f.Writing, KeyCaller: keyCaller, KeySettings: keySettings, Veil: veil}
	if keyFloor.Valid() {
		o.KeyFloor = keyFloor.String()
	}
	raw, _ := json.Marshal(o)
	header.Set(headerOpening, base64.StdEncoding.EncodeToString(raw))
}

func openingOf(header http.Header) (openingWire, error) {
	var o openingWire
	raw, err := base64.StdEncoding.DecodeString(header.Get(headerOpening))
	if err != nil || json.Unmarshal(raw, &o) != nil || o.Launch != nil && o.Launch.ID == "" || o.Launch != nil && o.Own != nil ||
		o.Writing != nil && slices.ContainsFunc(o.Writing.Examples, func(e chat.Example) bool { return e.ID == "" }) {
		return openingWire{}, errors.New("worker: malformed " + headerOpening)
	}
	if o.KeyFloor != "" {
		if o.keyFloor, err = catalog.ParseTier(o.KeyFloor); err != nil {
			return openingWire{}, errors.New("worker: malformed " + headerOpening)
		}
	}
	return o, nil
}

func refusalWire(err error) apierr.Error {
	var refusal apierr.Error
	if errors.As(err, &refusal) {
		return refusal
	}
	return apierr.ErrInvalidBody
}

func wireRefusal(resp *http.Response) error {
	var e struct {
		Error struct {
			Message, Type, Code, Reason string
			Param                       *string
		} `json:"error"`
		KeyID *seal.KeyID     `json:"key_id"`
		Epoch *taskseal.Epoch `json:"epoch"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, apierr.MaxErrorBody)).Decode(&e); err != nil || e.Error.Type == "" {
		return fmt.Errorf("worker: status %d with no refusal envelope", resp.StatusCode)
	}
	if e.Error.Code == ErrSealedKeyUnknown.Code {
		if e.KeyID == nil {
			return errors.New("worker: sealed_key_unknown without the key the worker holds")
		}
		return KeyUnknown{Holds: *e.KeyID}
	}
	if e.Error.Code == taskrun.ErrEpochUnknown.Code {
		if e.Epoch == nil {
			return errors.New("worker: task_epoch_unknown without the epoch the worker holds")
		}
		return taskrun.EpochUnknown{Holds: *e.Epoch}
	}
	refusal := apierr.Error{Status: resp.StatusCode, Type: e.Error.Type, Code: e.Error.Code, Message: e.Error.Message, Reason: e.Error.Reason}
	if e.Error.Param != nil {
		refusal.Param = *e.Error.Param
	}
	return refusal
}
