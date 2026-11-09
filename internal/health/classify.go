package health

import (
	"context"
	"errors"

	"morse/backend/internal/apierr"
	"morse/backend/internal/upstream"
)

type Cut uint8

const (
	NotCut Cut = iota
	CutByCaller
	CutByDeadline
	CutByShutdown
)

var cutOutcomes = [...]Outcome{CutByCaller: ClientCancel, CutByDeadline: Deadline, CutByShutdown: Shutdown}

type Evidence struct {
	Err   error
	Cut   Cut
	Began bool
}

var byCode = map[string]Outcome{
	apierr.ErrUpstreamBusy.Code:          UpstreamBusy,
	apierr.ErrUpstreamUnavailable.Code:   UpstreamUnavailable,
	apierr.ErrUpstreamRefused.Code:       UpstreamRefused,
	apierr.ErrUpstream.Code:              UpstreamError,
	apierr.ErrUpstreamRetention.Code:     Retention,
	apierr.ErrUnattested.Code:            Unattested,
	apierr.ErrContextLengthExceeded.Code: ContextOverflow,
	apierr.ErrContentFilter.Code:         ContentFilter,
	apierr.ErrInvalidRequest.Code:        ClientError,
	apierr.ErrRemoteMedia.Code:           ClientError,
	apierr.ErrRequestTooLarge.Code:       ClientError,
	apierr.ErrModelNotFound.Code:         ClientError,
	apierr.ErrInvalidBody.Code:           ClientError,
	apierr.ErrUnavailable.Code:           Shutdown,
}

var breaksMidstream = map[Outcome]bool{UpstreamBusy: true, UpstreamError: true, UpstreamUnavailable: true}

var failsOver = map[Outcome]bool{UpstreamBusy: true, UpstreamError: true, Unreachable: true, Stalled: true, UpstreamUnavailable: true, Unattested: true, ContextOverflow: true}

// tripsBreaker holds MidstreamBreak although it never fails over: the reply that broke stays with its client, but a host
// that breaks every stream after its first chunk is as broken as one that fails before it, and only an open circuit
// keeps the next turns, its home's among them, off it.
var tripsBreaker = map[Outcome]bool{UpstreamBusy: true, UpstreamError: true, Unreachable: true, Stalled: true, UpstreamUnavailable: true, MidstreamBreak: true, Unattested: true}

func (o Outcome) FailsOver() bool { return failsOver[o] }

func (o Outcome) TripsBreaker() bool { return tripsBreaker[o] }

func Classify(e Evidence) Outcome {
	var refusal apierr.Error
	cut := e.Cut != NotCut
	switch {
	case e.Err == nil && !cut:
		return OK
	case e.Err == nil:
		return cutOutcomes[e.Cut]
	case errors.Is(e.Err, upstream.ErrUnreachable):
		return Unreachable
	case errors.Is(e.Err, upstream.ErrStalled):
		return Stalled
	case errors.Is(e.Err, context.DeadlineExceeded):
		return Deadline
	case cut && errors.Is(e.Err, context.Canceled):
		return cutOutcomes[e.Cut]
	case errors.As(e.Err, &refusal):
		outcome := ofRefusal(refusal)
		if e.Began && breaksMidstream[outcome] {
			return MidstreamBreak
		}
		return outcome
	case cut:
		return cutOutcomes[e.Cut]
	case e.Began:
		return MidstreamBreak
	}
	return UpstreamError
}

func ofRefusal(refusal apierr.Error) Outcome {
	if outcome, listed := byCode[refusal.Code]; listed {
		return outcome
	}
	if refusal.Status/100 == 4 {
		return ClientError
	}
	return UpstreamError
}
