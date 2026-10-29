package worker

import (
	"context"
	"errors"
	"io"
	"net/http"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/lookup"
)

type openedLookup struct {
	cuts
	service, path, query string
}

func (w *InProcess) openLookup(o Opening, pathValue func(string) string) (Admission, error) {
	if w.lookup == nil {
		return nil, errNoSuchRoute
	}
	service, path := pathValue("service"), pathValue("path")
	l, err := w.lookup.Look(service, path, o.Query)
	if err != nil {
		return nil, err
	}
	ol := &openedLookup{cuts: newCuts(), service: service, path: path, query: o.Query}
	return LookupAdmission{admitted: admitted{w.keep(o, ol)}, Limit: l.Limit, Cached: l.Cached}, nil
}

func (o *openedLookup) cut(reason measure.Cut) { o.cuts.cut(reason, true) }

func (o *openedLookup) run(_ context.Context, w *InProcess, _ Handle, g Grant, reply http.ResponseWriter) Measured {
	if _, ok := g.(LookupGrant); !ok {
		return unrunnable(reply)
	}
	rw := newReplyWriter(reply)
	body, err := w.lookup.Get(o.cuts.run, o.service, o.path, o.query)
	var busy lookup.Busy
	switch {
	case err == nil:
		writeErr := writeJSONBody(rw, func(w io.Writer) error {
			_, err := w.Write(body)
			return err
		})
		end := endingOf(o.cuts.client, writeErr, nil)
		return Measured{Measurement: measure.Measurement{Outcome: end.outcome()}, Cut: end.cut(), Served: true}
	case errors.As(err, &busy):
		w.reports.LookupBusy(o.service)
		apierr.SetRetryAfter(rw, busy.RetryAfter)
		apierr.WriteError(rw, lookup.ErrBusy)
	case errors.Is(err, lookup.ErrUnavailable):
		w.reports.Failed(LookupPattern, err)
		apierr.WriteError(rw, lookup.ErrUnavailable)
	default:
		refuse(o.cuts.run, rw, err)
	}
	end := endingOf(o.cuts.client, nil, err)
	return Measured{Measurement: measure.Measurement{Outcome: end.outcome()}, Cut: end.cut(), Refusal: end.refusal(err)}
}
