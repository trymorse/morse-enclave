package worker

import (
	"context"
	"errors"
	"os"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/health"
	"morse/backend/internal/upstream"
)

type ending uint8

const (
	completed ending = iota
	rejected
	failed
	cutByClient
	cutByDeadline
	cutByProxy
)

var endings = [...]struct {
	outcome measure.Outcome
	cut     measure.Cut
	health  health.Cut
}{
	completed:     {measure.Completed, measure.NotCut, health.NotCut},
	rejected:      {measure.Rejected, measure.NotCut, health.NotCut},
	failed:        {measure.Failed, measure.NotCut, health.NotCut},
	cutByClient:   {measure.Cancelled, measure.CutByClient, health.CutByCaller},
	cutByDeadline: {measure.Cancelled, measure.CutByDeadline, health.CutByDeadline},
	cutByProxy:    {measure.Cancelled, measure.CutByProxy, health.CutByShutdown},
}

func (e ending) outcome() measure.Outcome { return endings[e].outcome }

func (e ending) cut() measure.Cut { return endings[e].cut }

func (e ending) refusal(callErr error) measure.RefusalCode {
	if e != rejected {
		return measure.NoRefusal
	}
	return measure.RefusalCodeOf(callErr)
}

func (e ending) healthCut() health.Cut { return endings[e].health }

func cutOf(ctx context.Context, writeErr error) (end ending, cut bool) {
	cause := context.Cause(ctx)
	switch {
	case errors.Is(cause, ErrShutdown):
		return cutByProxy, true
	case errors.Is(cause, context.DeadlineExceeded), errors.Is(writeErr, os.ErrDeadlineExceeded):
		return cutByDeadline, true
	case writeErr != nil, errors.Is(cause, context.Canceled):
		return cutByClient, true
	}
	return 0, false
}

func endingOf(ctx context.Context, writeErr, callErr error) ending {
	if end, cut := cutOf(ctx, writeErr); cut && !errors.As(callErr, new(upstream.Refused)) {
		return end
	}
	return verdictOf(callErr)
}

func verdictOf(callErr error) ending {
	var refusal apierr.Error
	switch {
	case callErr == nil:
		return completed
	case errors.Is(callErr, upstream.ErrUnreachable), errors.Is(callErr, context.DeadlineExceeded):
		return failed
	case errors.As(callErr, &refusal):
		return rejected
	}
	return failed
}
