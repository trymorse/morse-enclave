package clip

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/media"
	"morse/backend/internal/upstream"
)

const (
	MaxClipBytes = 256 << 20
	ReceiveSlots = 16
)

var (
	errNoTicket     = apierr.Invalid(http.StatusNotFound, "not_found", "No upload waits at this address.")
	errNoTicketKey  = apierr.Error{Status: http.StatusServiceUnavailable, Type: "server_error", Code: "ticket_key_pending", Message: "This instance has not yet taken the key its fleet seals upload addresses under. Retry after the time in the Retry-After header."}
	errTicketLapsed = apierr.Invalid(http.StatusGone, "upload_expired", "This upload address has expired.")
	errNoLength     = apierr.Invalid(http.StatusLengthRequired, "length_required", "A clip upload must declare its Content-Length.")
	errBusy         = apierr.Error{Status: http.StatusServiceUnavailable, Type: "server_error", Code: "server_busy", Message: "The door is receiving as many clips as it holds at once. Retry after the time in the Retry-After header."}
	errUploadBroken = apierr.Invalid(http.StatusBadRequest, "invalid_request_body", "The clip did not arrive whole: its body ended early, ran past its Content-Length, or arrived too slowly.")
	errStoreFailed  = apierr.Error{Status: http.StatusBadGateway, Type: "upstream_error", Code: "store_failed", Message: "The sealed clip could not be stored."}
)

type Outcome string

const (
	Stored       Outcome = "stored"
	Refused      Outcome = "refused"
	Busy         Outcome = "busy"
	StoreFailed  Outcome = "store_failed"
	UploadBroken Outcome = "upload_broken"
)

type Receiver struct {
	Store   Store
	Tickets TicketKeys
	Client  *http.Client
	Most    int64
	Now     func() time.Time
	Observe func(Outcome)
	slots   chan struct{}
}

func NewReceiver(store Store, tickets TicketKeys, transport http.RoundTripper) *Receiver {
	return &Receiver{Store: store, Tickets: tickets, Client: &http.Client{Transport: transport}, Most: MaxClipBytes, Now: time.Now, Observe: func(Outcome) {}, slots: make(chan struct{}, ReceiveSlots)}
}

func (rc *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key, held := rc.Tickets()
	if !held {
		rc.Observe(Refused)
		apierr.SetRetryAfter(w, 5*time.Second)
		apierr.WriteError(w, errNoTicketKey)
		return
	}
	t, err := ParseTicket(key, r.PathValue("ticket"))
	now := rc.Now()
	var refusal *apierr.Error
	switch {
	case err != nil, !rc.Store.Holds(t.Store):
		refusal = &errNoTicket
	case !now.Before(t.Deadline):
		refusal = &errTicketLapsed
	case r.ContentLength < 0:
		refusal = &errNoLength
	case r.ContentLength > rc.Most:
		refusal = &apierr.ErrRequestTooLarge
	}
	if refusal != nil {
		rc.Observe(Refused)
		apierr.WriteError(w, *refusal)
		return
	}
	select {
	case rc.slots <- struct{}{}:
		defer func() { <-rc.slots }()
	default:
		rc.Observe(Busy)
		apierr.SetRetryAfter(w, 5*time.Second)
		apierr.WriteError(w, errBusy)
		return
	}
	etag, outcome := rc.store(r.Context(), t, r.Body, r.ContentLength)
	rc.Observe(outcome)
	switch outcome {
	case Stored:
		if etag != "" {
			w.Header().Set("ETag", etag)
		}
		w.WriteHeader(http.StatusOK)
	case UploadBroken:
		// why: net/http answers 200 for a handler that writes no status, even once the body read failed, and the
		// vendor counts a 2xx as its clip delivered.
		apierr.WriteError(w, errUploadBroken)
	default:
		apierr.WriteError(w, errStoreFailed)
	}
}

func (rc *Receiver) store(ctx context.Context, t Ticket, plain io.Reader, size int64) (string, Outcome) {
	ctx, cancel := context.WithDeadline(ctx, t.Deadline.Add(media.VideoUploadGrace))
	defer cancel()
	sealed, err := Seal(t.Key, t.Clip, plain, size)
	if err != nil {
		return "", StoreFailed
	}
	body := &upload{r: sealed, closed: make(chan struct{})}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, t.Store, body)
	if err != nil {
		return "", StoreFailed
	}
	req.ContentLength = SealedSize(size)
	req.Header.Set("Content-Type", "application/octet-stream")
	etag, stored := "", false
	if resp, err := upstream.Do(rc.Client, req); err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		etag, stored = resp.Header.Get("ETag"), resp.StatusCode/100 == 2
	}
	cancel()
	<-body.closed
	switch {
	case body.broken() != nil:
		return "", UploadBroken
	case !stored:
		return "", StoreFailed
	}
	return etag, Stored
}

// why: a Transport may close a request's body after RoundTrip returns (net/http RoundTripper), and the store's
// body reads the vendor's request, which must not be read once the handler returns.
type upload struct {
	r      io.Reader
	mu     sync.Mutex
	err    error
	once   sync.Once
	closed chan struct{}
}

func (u *upload) Read(p []byte) (int, error) {
	n, err := u.r.Read(p)
	if err != nil && err != io.EOF {
		u.mu.Lock()
		u.err = err
		u.mu.Unlock()
	}
	return n, err
}

func (u *upload) Close() error {
	u.once.Do(func() { close(u.closed) })
	return nil
}

func (u *upload) broken() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.err
}
