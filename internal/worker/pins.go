package worker

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/flight"
	"morse/backend/internal/phala"
)

const (
	pinListFor   = 5 * time.Second
	pinListRetry = time.Second
	pinListBound = 30 * time.Second
)

var errSessionNotListed = apierr.Invalid(http.StatusBadRequest, "e2ee_session_not_listed", "Each id in provider.aci_session_ids must be a session that GET /v1/aci/sessions lists for this model now. List the sessions again, audit them, and pin only those.")

type pinListKey struct {
	model    catalog.ModelID
	endpoint catalog.EndpointID
}

type pinLists struct {
	mu sync.Mutex
	by map[pinListKey]*flight.Cache[[]chat.ListedSession]
}

func (l *pinLists) get(key pinListKey, s chat.Sessioner) *flight.Cache[[]chat.ListedSession] {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.by == nil {
		l.by = map[pinListKey]*flight.Cache[[]chat.ListedSession]{}
	}
	c, ok := l.by[key]
	if !ok {
		c = &flight.Cache[[]chat.ListedSession]{Fetch: s.ListSessions, MaxAge: pinListFor, MinRefetch: pinListRetry, Timeout: pinListBound}
		l.by[key] = c
	}
	return c
}

// why: the list holds only the gateway's phala-direct sessions for this model, so a pin outside it may name a
// Chutes server or another model's; a list the gateway fails to give admits nothing.
func (w *InProcess) pinsListed(ctx context.Context, route chatRoute, req *chat.Request) error {
	v, ok := route.Upstream.(Verbatim)
	if !ok {
		return nil
	}
	s, ok := v.Route.(chat.Sessioner)
	if !ok {
		return nil
	}
	listed, err := w.pinLists.get(pinListKey{route.model, route.endpoint}, s).Current(ctx, w.now())
	var refusal apierr.Error
	switch {
	case errors.As(err, &refusal):
		return refusal
	case err != nil:
		return apierr.ErrUpstreamUnavailable
	}
	for _, id := range phala.PinnedSessions(req) {
		if !slices.ContainsFunc(listed, func(l chat.ListedSession) bool { return l.ID == id }) {
			return errSessionNotListed
		}
	}
	return nil
}

func (o Opening) context() context.Context {
	if o.ctx == nil {
		return context.Background()
	}
	return o.ctx
}

// why: only a sealed Phala chat may name aci_session_ids; every other route refuses the field, so the pins alone
// say the bytes reach the gateway and never the model.
func pinBytes(req *chat.Request) int {
	if len(phala.PinnedSessions(req)) == 0 {
		return 0
	}
	raw, _ := req.Field("provider")
	return max(len(raw)-len(phala.Constraint), 0)
}
