package worker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/chat"
	"morse/backend/internal/enum"
	"morse/backend/internal/health"
	"morse/backend/internal/jobs"
	"morse/backend/internal/media"
	"morse/backend/internal/plans/limits"
)

// A Worker admits a request, then runs or submits it once under the relay's grant.
//
// Run and Submit answer every call with one reply and its measurement. A handle the worker cannot run, because
// it is unknown, already ran, or took another family's grant, or because a relay's worker refused the call
// with a reply of its own, gets a 503 and a failed, unserved measurement. A relay whose worker never answered,
// or whose answer was lost after it began, panics with http.ErrAbortHandler, so the relay's server drops the
// client's connection, and the relay settles at the hold, or by the job once the vendor accepted it.
type Worker interface {
	Open(ctx context.Context, o Opening) (Admission, error)
	OpenSealed(ctx context.Context, o SealedOpening) (SealedAdmission, error)
	Run(ctx context.Context, h Handle, g Grant, reply http.ResponseWriter) Measured
	// Submit runs a job's handle in two phases: the vendor's acceptance goes to accepted, which the relay
	// returns from once it holds the job, and only then does the queued reply go out.
	Submit(ctx context.Context, h Handle, g JobGrant, reply http.ResponseWriter, accepted func(media.Submitted)) Measured
	Cut(h Handle, reason measure.Cut)
	Poll(ctx context.Context, route, vendorID string) (jobs.Poll, error)
	Attestation(ctx context.Context) (Attested, error)
	// The vendor evidence a client may audit: an attestation report for its nonce, a receipt, and the attested
	// sessions a gateway lists and serves. A vendor error the client may be told about comes back as an
	// apierr.Error; any other error is the relay's to report.
	Attest(ctx context.Context, v Vendor, nonce string) (chat.Attestation, error)
	Receipt(ctx context.Context, v Vendor, id string) (json.RawMessage, error)
	Session(ctx context.Context, v Vendor, id string) (json.RawMessage, error)
	Sessions(ctx context.Context, v Vendor) ([]chat.ListedSession, error)
}

type Opening struct {
	Method  string
	Path    string
	Query   string
	Header  http.Header
	Body    io.Reader
	Cast    chat.Cast
	Launch  *chat.Launch
	Writing *chat.Writing
	cek     *[32]byte
}

func ContentHeaders(from http.Header) http.Header {
	to := http.Header{}
	names := []string{"Content-Type"}
	for _, s := range schemesNarrowestFirst {
		names = append(names, s.Headers...)
	}
	for _, name := range names {
		if values := from.Values(name); len(values) > 0 {
			to[http.CanonicalHeaderKey(name)] = values
		}
	}
	return to
}

type Handle struct{ id uint64 }

type Admission interface {
	Handle() Handle
	kind() admissionKind
}

type admitted struct{ handle Handle }

func (a admitted) Handle() Handle { return a.handle }

func (a *admitted) take(h Handle) { a.handle = h }

type ChatAdmission struct {
	admitted
	Route       string
	Attester    string
	PromptBound int
	PromptBytes limits.Kibibytes
	OutputAsked int
	Stream      bool
	Compaction  bool
	Character   chat.Character
}

func (ChatAdmission) kind() admissionKind { return admitsChat }

type MediaAdmission struct {
	admitted
	Route      string
	Units      int
	References int
}

func (MediaAdmission) kind() admissionKind { return admitsMedia }

type CallAdmission struct {
	admitted
	Route string
}

func (CallAdmission) kind() admissionKind { return admitsCall }

type ReadAdmission struct {
	admitted
	JobID string
}

func (ReadAdmission) kind() admissionKind { return admitsRead }

type LookupAdmission struct {
	admitted
	Limit  limits.SharedLimit
	Cached bool
}

func (LookupAdmission) kind() admissionKind { return admitsLookup }

type Grant interface{ kind() grantKind }

type ChatGrant struct {
	OutputLimit  int
	ReasoningCap int
	Budgeted     bool
	Figures      measure.RouteFigures
	Sample       bool
}

func (ChatGrant) kind() grantKind { return grantsChat }

type MediaGrant struct{ Units int }

func (MediaGrant) kind() grantKind { return grantsMedia }

type CallGrant struct{}

func (CallGrant) kind() grantKind { return grantsCall }

type JobGrant struct {
	ID        string
	CreatedAt time.Time
	Deadline  time.Time
	UploadURL string
}

type VideoReadGrant struct {
	Route  string
	Output media.Output
}

func (VideoReadGrant) kind() grantKind { return grantsVideoRead }

type ResearchReadGrant struct {
	Route     string
	VendorID  string
	Status    jobs.Status
	Failure   jobs.Failure
	CreatedAt time.Time
}

func (ResearchReadGrant) kind() grantKind { return grantsResearchRead }

type ResearchEventsGrant struct {
	Route    string
	VendorID string
	Status   jobs.Status
}

func (ResearchEventsGrant) kind() grantKind { return grantsResearchEvents }

type LookupGrant struct{}

func (LookupGrant) kind() grantKind { return grantsLookup }

type Measured struct {
	measure.Measurement
	Cut               measure.Cut
	Served            bool
	Delivered         int
	Downloaded        bool
	Cost              money.Reported
	SealedStatusClass int
	Health            health.Observation
	Follow            Follow
	Unsampled         bool                `json:"-"`
	Refusal           measure.RefusalCode `json:",omitempty"`
	Counted           <-chan Count        `json:"-"`
}

type Follow uint8

const (
	FollowNone Follow = iota
	FollowCount
	FollowSample
)

var followNames = enum.Names[Follow]{FollowNone: "none", FollowCount: "count", FollowSample: "sample"}

func (f Follow) MarshalText() ([]byte, error) { return followNames.MarshalText(f) }

func (f *Follow) UnmarshalText(text []byte) error { return followNames.UnmarshalText(f, text) }

type Count struct {
	measure.Measurement
	Counted bool
	Samples []measure.Sample
}
