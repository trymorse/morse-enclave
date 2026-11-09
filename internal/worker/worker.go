package worker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"morse/backend/internal/affinity"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/catalog"
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
	// The vendor evidence a client may audit: an attestation report for its nonce, in the format it asked for
	// where the route serves one, a receipt, and the attested sessions a gateway lists and serves. A vendor
	// error the client may be told about comes back as an apierr.Error; any other error is the relay's to
	// report.
	Attest(ctx context.Context, v Vendor, nonce string, f Format) (chat.Attestation, error)
	Receipt(ctx context.Context, v Vendor, id string) (json.RawMessage, error)
	Session(ctx context.Context, v Vendor, id string) (json.RawMessage, error)
	Sessions(ctx context.Context, v Vendor) ([]chat.ListedSession, error)
}

// Format is the attestation document a client asked for. Only a Tinfoil route reads it, and it serves its v3
// document for each, keeping the router's sigstore-code collateral only for FormatV3Code.
type Format uint8

const (
	FormatReport Format = iota
	// FormatV3 is Tinfoil's v3 document for the nonce, with AMD's collateral.
	FormatV3
	// FormatV3Code is the v3 document with the router's sigstore-code collateral kept.
	FormatV3Code
)

// Framing is what the proxy puts around a chat once it checked the caller may have it: a launch character's
// prompt, or the rules for one of the user's own characters (never both), and the character writer's examples.
type Framing struct {
	Launch  *chat.Launch
	Own     *chat.OwnFrame
	Writing *chat.Writing
}

type Opening struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   io.Reader
	Cast   chat.Cast
	Framing
	KeyCaller bool
	KeyFloor  catalog.Tier
	cek       *[32]byte
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
	Model      catalog.ModelID
	Candidates []catalog.EndpointID
	// Affinity is the conversation digest of an unsealed sk_ request (affinity.DigestOf), and zero for every other
	// request.
	Affinity    affinity.Digest `json:",omitzero"`
	MaxPrice    money.PriceCap  `json:",omitzero"`
	Sealable    bool
	OnBehalf    bool
	PromptSize  int
	PromptBytes limits.Kibibytes
	// TextMessages counts the messages of a chat whose prompt is text alone (chat.Request.PromptTexts) and whose body is
	// in Unicode normal form C, which a smaller backup's window can be judged on (proxy Chat.carries). It is zero for
	// any other chat.
	TextMessages int
	// PromptCounted is true when every part of every message is text, so PromptBytes counts all the model reads.
	PromptCounted bool
	OutputAsked   int
	Stream        bool
	Compaction    bool
	Character     chat.Character
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
	Endpoints    []catalog.EndpointID
	PromptBound  int
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

// Measured is one run's outcome. Endpoint is the endpoint that served or was tried last, and Health is that try's,
// with Retries counting every extra call of the whole walk, each try's own plus one per move, and Hedges summed.
// FailedOver lists each other endpoint the walk tried that failed before it began the client's reply, with an
// outcome that FailsOver, in the order they ended. VendorWait is the vendors' time before a streamed reply's first
// byte: from the walk's first call to the serving call's first byte. It is zero for a reply that did not stream, whose
// first byte the relay sees only once the vendor has finished. Lingers says the walk ended with another endpoint's
// try still running, and Late, when not nil, yields each such try that fails over as it ends and is closed once all
// have ended.
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
	Endpoint          catalog.EndpointID  `json:",omitempty"`
	// Unserved is a chat that no host served or began to reply to: the last endpoint tried failed before the client
	// saw a status, with an outcome that fails over and is not its own refusal to attest, and no cut ended it. A host's
	// refusal of the request, a prompt too long for its window among them, an unattested endpoint, and a cut before
	// the first byte are not unserved. Endpoint then names only the last one tried, which its health and breaker still
	// count.
	Unserved   bool          `json:",omitempty"`
	FailedOver []Try         `json:",omitempty"`
	VendorWait time.Duration `json:",omitempty"`
	Late       <-chan Try    `json:"-"`
	Lingers    bool          `json:",omitempty"`
	Counted    <-chan Count  `json:"-"`
}

type Try struct {
	Endpoint catalog.EndpointID
	Health   health.Observation
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
	Receipt chat.ProvenReceipt `json:",omitzero"`
}
