package worker

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/chat"
	"morse/backend/internal/enum"
	"morse/backend/internal/privacyveil"
)

const (
	// HeaderPrivacyVeil tells the client, inside the seal, that its chat was veiled: "applied", and the kinds of part
	// sent as written.
	HeaderPrivacyVeil = "X-Privacy-Veil"
	privacyVeilField  = "privacy_veil"
)

// PrivacyVeil is the worker's side of the Privacy Veil: the filter that finds the details, the cache of where it found
// them, and the limits a scan runs under. A worker with none serves no Veil, and refuses every chat that asks for it.
type PrivacyVeil struct {
	Filter privacyveil.Filter
	Cache  *privacyveil.Cache
	// MaxBytes is the most uncached text one chat may send the filter, Deadline how long its scan may take, and InFlight
	// the most uncached text the worker scans at once: a scan that would pass it is refused at once, never queued.
	MaxBytes int
	Deadline time.Duration
	InFlight int

	mu       sync.Mutex
	scanning int
	failures map[VeilFailure]int
	unknown  int
}

const (
	defaultVeilMaxBytes = 256 << 10
	defaultVeilDeadline = 45 * time.Second
	defaultVeilInFlight = 512 << 10
)

func (p *PrivacyVeil) maxBytes() int {
	if p.MaxBytes > 0 {
		return p.MaxBytes
	}
	return defaultVeilMaxBytes
}

func (p *PrivacyVeil) deadline() time.Duration {
	if p.Deadline > 0 {
		return p.Deadline
	}
	return defaultVeilDeadline
}

// admit takes n bytes of the in-flight budget, or refuses when they would pass it.
func (p *PrivacyVeil) admit(n int) (release func(), ok bool) {
	limit := p.InFlight
	if limit <= 0 {
		limit = defaultVeilInFlight
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.scanning > 0 && p.scanning+n > limit {
		return nil, false
	}
	p.scanning += n
	return func() {
		p.mu.Lock()
		p.scanning -= n
		p.mu.Unlock()
	}, true
}

func (p *PrivacyVeil) failed(f VeilFailure) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failures == nil {
		p.failures = map[VeilFailure]int{}
	}
	p.failures[f]++
}

// Failures takes the counts of Veils that failed since it last ran, by reason: the chats the Veil could not serve. The
// worker's log reports them once a minute, never one request at a time, so the host cannot tell which request held a
// detail. The prod alarm sums them.
func (p *PrivacyVeil) Failures() map[string]int { return p.take(VeilFailure.outage) }

// Refusals takes the counts of Veils the chat itself ended since it last ran, by reason: a chat too large to scan, and
// a client that left during its scan. They say nothing of the filter's health, so the alarm leaves them out.
func (p *PrivacyVeil) Refusals() map[string]int {
	return p.take(func(f VeilFailure) bool { return !f.outage() })
}

func (p *PrivacyVeil) take(which func(VeilFailure) bool) map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	counts := map[string]int{}
	for f, n := range p.failures {
		if which(f) {
			counts[f.String()] = n
			delete(p.failures, f)
		}
	}
	return counts
}

func (f VeilFailure) outage() bool { return f != VeilTooLarge && f != VeilCut }

func (p *PrivacyVeil) unknownLabels(n int) {
	if n == 0 {
		return
	}
	p.mu.Lock()
	p.unknown += n
	p.mu.Unlock()
}

// UnknownLabels takes the count of spans the filter labelled in a way this build does not know, and veiled as PII,
// since it last ran. The log names no label: the filter chooses them.
func (p *PrivacyVeil) UnknownLabels() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.unknown
	p.unknown = 0
	return n
}

// VeilOpening is what the relay tells the worker of a chat's Veil: whether the Veil is switched on, whether the
// caller's key requires it, and, for a key's unsealed chat, the partition its scans are cached under.
type VeilOpening struct {
	Enabled   bool   `json:"enabled,omitempty"`
	Floor     bool   `json:"floor,omitempty"`
	Partition []byte `json:"partition,omitempty"`
}

// VeilAdmission tells the relay a chat asked for the Veil, and how much of its text the filter will read: the calls
// it makes and their text, joints included, to the KiB.
type VeilAdmission struct {
	UncachedKiB int
	Pieces      int
}

// VeilMeasure is what a chat's Veil did: the filter's billable calls and tokens, the time the scan took, and why it
// failed, if it did.
type VeilMeasure struct {
	Calls, Tokens int
	Millis        int64
	Failed        VeilFailure `json:",omitzero"`
}

type VeilFailure uint8

const (
	VeilOK VeilFailure = iota
	VeilUnattested
	VeilUnreachable
	VeilOverloaded
	VeilTimeout
	VeilMalformed
	VeilSelfCheck
	VeilFailedOther
	// VeilTooLarge is a chat refused at /open for more uncached text than a scan may send. It is counted for the log,
	// and never crosses the wire in a measurement.
	VeilTooLarge
	// VeilCut is a scan the client left before it ended. The filter may be well.
	VeilCut
)

var veilFailureNames = enum.Names[VeilFailure]{VeilOK: "ok", VeilUnattested: "unattested", VeilUnreachable: "unreachable", VeilOverloaded: "overloaded",
	VeilTimeout: "timeout", VeilMalformed: "malformed", VeilSelfCheck: "self_check", VeilFailedOther: "other", VeilTooLarge: "too_large", VeilCut: "cut"}

func (f VeilFailure) String() string { return veilFailureNames.String(f) }

func (f VeilFailure) MarshalText() ([]byte, error) { return veilFailureNames.MarshalText(f) }

// UnmarshalText reads a reason a newer worker names but this build does not as other, so the relay still settles.
func (f *VeilFailure) UnmarshalText(text []byte) error {
	if veilFailureNames.UnmarshalText(f, text) != nil {
		*f = VeilFailedOther
	}
	return nil
}

var (
	errVeilUnavailable   = apierr.Error{Status: http.StatusServiceUnavailable, Type: "server_error", Code: "privacy_veil_unavailable", Message: "The Privacy Veil can't serve this chat now, so it was not sent. Send it again later, or without privacy_veil."}
	errVeilTooLarge      = apierr.Invalid(http.StatusRequestEntityTooLarge, "privacy_veil_too_large", "The Privacy Veil scans at most "+kib(defaultVeilMaxBytes)+" of text the filter has not seen in a chat. Send less text, or the chat without privacy_veil.")
	errVeilMisplaced     = apierr.Invalid(http.StatusBadRequest, "privacy_veil_misplaced", "A sealed chat asks for the Privacy Veil in the seal's head, where the relay can't drop it, not in its body. Update morse-seal, or the client that sealed it.")
	errVeilRequired      = apierr.Invalid(http.StatusBadRequest, "privacy_veil_required", "This key requires the Privacy Veil, so privacy_veil may not be false.").Naming("key.privacy_veil")
	errVeilNotApplicable = apierr.Invalid(http.StatusBadRequest, "privacy_veil_not_applicable", "The Privacy Veil reads only chats the proxy can read, so it can't apply to an end-to-end encrypted chat or to this route, and a key that requires it serves only chats.")
)

func kib(n int) string {
	b, _ := json.Marshal(n >> 10)
	return string(b) + " KiB"
}

func veilAskRefusal(err error) error {
	return apierr.InvalidParameter(err.Error()).Naming(privacyVeilField)
}

func veilFieldRefusal(param string) error {
	return apierr.Invalid(http.StatusBadRequest, "privacy_veil_unsupported_field", "The Privacy Veil can't carry "+param+", which could hold text it would not read. Send the part as text or as a supported media part, or the chat without privacy_veil.").Naming(param)
}

// veilAsk is the chat's ask for the Veil, or nil when it asks for none. A sealed chat asks in its head; any other in
// its body; and a key's floor asks for every chat. A chat the worker cannot veil is refused, never served unveiled.
func (w *InProcess) veilAsk(o Opening, p protocol, req *chat.Request) (*privacyveil.Ask, error) {
	raw, inBody := req.Field(privacyVeilField)
	if o.cek != nil {
		if inBody && o.veilHead == nil {
			return nil, errVeilMisplaced
		}
		raw = o.veilHead
	}
	ask, err := privacyveil.ParseAsk(raw)
	if err != nil {
		return nil, veilAskRefusal(err)
	}
	if o.PrivacyVeil.Floor {
		if string(bytes.TrimSpace(raw)) == "false" {
			return nil, errVeilRequired
		}
		ask.On = true
	}
	switch {
	case !ask.On:
		return nil, nil
	case p.scheme != nil:
		return nil, errVeilNotApplicable
	case !o.PrivacyVeil.Enabled || w.privacyVeil == nil:
		return nil, errVeilUnavailable
	}
	return &ask, nil
}

// veilNotHere refuses a route the Veil cannot read when the caller's key requires the Veil or the seal's head asks for
// it. Only a chat's opening reads the head's ask, so served, such a request would go out unveiled.
func veilNotHere(o Opening) error {
	ask, err := privacyveil.ParseAsk(o.veilHead)
	switch {
	case err != nil:
		return veilAskRefusal(err)
	case o.PrivacyVeil.Floor || ask.On:
		return errVeilNotApplicable
	}
	return nil
}

// openedVeil is a veiled chat between /open and the end of its run: what to scan, then the veil it made.
type openedVeil struct {
	ask       privacyveil.Ask
	segments  []privacyveil.Segment
	cached    map[int][]privacyveil.Span
	pieces    []privacyveil.Piece
	namespace privacyveil.Namespace
	partition []byte
	unveiled  []string
	veil      *privacyveil.Veil
}

// planVeil takes the client's own text, before any framing, plans the pieces /run sends the filter, and refuses a
// chat whose uncached text passes the cap or that carries a part the Veil cannot see into.
func (w *InProcess) planVeil(o Opening, ask privacyveil.Ask, original *chat.Request) (*openedVeil, error) {
	texts, err := original.VeilTexts()
	if unveilable, ok := errors.AsType[*chat.ErrUnveilable](err); ok {
		return nil, veilFieldRefusal(unveilable.Param)
	}
	if err != nil {
		return nil, err
	}
	v := &openedVeil{ask: ask, cached: map[int][]privacyveil.Span{}, unveiled: original.UnveiledKinds()}
	v.namespace, v.partition = veilPartition(o)
	for _, t := range texts {
		v.segments = append(v.segments, privacyveil.Segment{Text: t.Text, Literal: t.Role == "user" || t.Role == "system"})
	}
	for i, s := range v.segments {
		if spans, hit := w.privacyVeil.Cache.Get(v.namespace, v.partition, s.Text); hit {
			v.cached[i] = spans
		}
	}
	v.pieces = privacyveil.Plan(v.segments, func(i int) bool { _, hit := v.cached[i]; return !hit })
	if privacyveil.Bytes(v.pieces) > w.privacyVeil.maxBytes() {
		w.privacyVeil.failed(VeilTooLarge)
		return nil, errVeilTooLarge
	}
	return v, nil
}

func veilPartition(o Opening) (privacyveil.Namespace, []byte) {
	if o.cek != nil {
		partition, err := base64.RawURLEncoding.DecodeString(o.veilPartition)
		if err != nil {
			return privacyveil.SealedPartition, nil
		}
		return privacyveil.SealedPartition, partition
	}
	return privacyveil.RelayPartition, o.PrivacyVeil.Partition
}

func (v *openedVeil) admission() *VeilAdmission {
	return &VeilAdmission{UncachedKiB: (privacyveil.Bytes(v.pieces) + 1023) / 1024, Pieces: len(v.pieces)}
}

// apply scans the chat, swaps every detail in the request it will send for its placeholder, and checks that no value
// is left in it. It fails closed: on any failure nothing is sent, and the reply is the refusal it writes.
func (o *openedChat) applyVeil(ctx context.Context, w *InProcess, rw http.ResponseWriter) (Measured, bool) {
	v, pv := o.veil, w.privacyVeil
	started := w.now()
	m := &VeilMeasure{}
	fail := func(f VeilFailure) (Measured, bool) {
		m.Failed, m.Millis = f, w.now().Sub(started).Milliseconds()
		pv.failed(f)
		refusal := errVeilUnavailable
		if f == VeilOverloaded || f == VeilUnreachable || f == VeilTimeout {
			rw.Header().Set("Retry-After", "5")
		}
		apierr.WriteError(rw, refusal)
		return Measured{Measurement: measure.Measurement{Outcome: measure.Failed, Unsent: true}, Unsampled: true, PrivacyVeil: m}, true
	}
	release, ok := pv.admit(privacyveil.Bytes(v.pieces))
	if !ok {
		return fail(VeilOverloaded)
	}
	defer release()
	scanCtx, cancel := context.WithTimeout(ctx, pv.deadline())
	defer cancel()
	scanned, err := privacyveil.Scan(scanCtx, pv.Filter, v.segments, v.cached, v.pieces)
	m.Calls, m.Tokens = scanned.Usage.Calls, scanned.Usage.Tokens
	pv.unknownLabels(scanned.Usage.UnknownLabels)
	switch {
	case err == nil:
	case errors.Is(err, privacyveil.ErrUnattested):
		return fail(VeilUnattested)
	case errors.Is(err, privacyveil.ErrSpan), errors.Is(err, privacyveil.ErrMalformed):
		return fail(VeilMalformed)
	case ctx.Err() != nil:
		return fail(VeilCut)
	case errors.Is(scanCtx.Err(), context.DeadlineExceeded):
		return fail(VeilTimeout)
	default:
		return fail(VeilUnreachable)
	}
	for i, spans := range scanned.Fresh {
		pv.Cache.Put(v.namespace, v.partition, v.segments[i].Text, spans)
	}
	veil := privacyveil.New(v.segments, scanned.Spans)
	veiled, err := o.call.Request.Veiled(veil.Substitute)
	if err != nil {
		return fail(VeilMalformed)
	}
	if veil.HoldsJSON(veiled.Forwarded()) {
		return fail(VeilSelfCheck)
	}
	o.call.Request, v.veil, m.Millis = veiled, veil, w.now().Sub(started).Milliseconds()
	o.veilMeasure = m
	rw.Header().Set(HeaderPrivacyVeil, v.header())
	return Measured{}, false
}

// egressRefused ends a run whose sender's final body still held a detail, so nothing was sent. The Veil failed on
// Morse's side, and the vendor's health is not judged by it.
func (o *openedChat) egressRefused(w *InProcess, rw http.ResponseWriter, ran Measured) Measured {
	w.privacyVeil.failed(VeilSelfCheck)
	rw.Header().Del(HeaderTier)
	rw.Header().Del(HeaderPrivacyVeil)
	apierr.WriteError(rw, errVeilUnavailable)
	m := VeilMeasure{Failed: VeilSelfCheck}
	if o.veilMeasure != nil {
		m = *o.veilMeasure
		m.Failed = VeilSelfCheck
	}
	return Measured{Measurement: measure.Measurement{Outcome: measure.Failed, Unsent: true}, Unsampled: true, PrivacyVeil: &m, FailedOver: ran.FailedOver, Late: ran.Late, Lingers: ran.Lingers}
}

func (v *openedVeil) header() string {
	if len(v.unveiled) == 0 {
		return "applied"
	}
	return `applied; unveiled="` + strings.Join(v.unveiled, " ") + `"`
}

// dropVeil lets go of the chat's text and its veil, which hold the details. The count after a run reads only the
// veiled call.
func (o *openedChat) dropVeil() {
	if o.veil != nil {
		o.veil.segments, o.veil.cached, o.veil.pieces, o.veil.veil = nil, nil, nil, nil
		o.veil = nil
	}
}
