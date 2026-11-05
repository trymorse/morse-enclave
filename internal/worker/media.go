package worker

import (
	"context"
	"io"
	"net/http"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/media"
	"morse/backend/internal/web"
)

type openedImages struct {
	cuts
	endpoint  catalog.EndpointID
	generator media.ImageGenerator
	req       *media.ImageRequest
}

func (w *InProcess) openImages(o Opening) (Admission, error) {
	req, err := media.ParseImageRequest(o.Body)
	if err != nil {
		return nil, contentRefusal(err)
	}
	generator, known := w.images[req.Model]
	if !known {
		return nil, apierr.ErrModelNotFound
	}
	if err := refuseProtocol(nil, protocolOf(o.Header.Get)); err != nil {
		return nil, err
	}
	if err := generator.CheckImages(req); err != nil {
		return nil, apierr.InvalidParameter(err.Error())
	}
	oi := &openedImages{cuts: newCuts(), endpoint: w.endpoints[req.Model], generator: generator, req: req}
	return MediaAdmission{admitted: admitted{w.keep(o, oi)}, Route: req.Model, Units: req.N, References: len(req.References())}, nil
}

func (o *openedImages) cut(reason measure.Cut) { o.cuts.cut(reason, false) }

func (o *openedImages) run(_ context.Context, w *InProcess, h Handle, g Grant, reply http.ResponseWriter) Measured {
	mg, ok := g.(MediaGrant)
	if !ok {
		return unrunnable(reply)
	}
	if mg.Units > 0 {
		o.req.N = min(o.req.N, mg.Units)
	}
	ctx, cancel := context.WithTimeout(o.cuts.run, media.ImageTimeout)
	defer cancel()
	rw := newReplyWriter(reply)
	opened := time.Now()
	var imgs media.Images
	var err error
	canceller, cancels := o.generator.(media.Canceller)
	if cancels {
		imgs, err = canceller.GenerateImagesUntil(ctx, o.cuts.client.Done(), o.req)
	} else {
		imgs, err = o.generator.GenerateImages(ctx, o.req)
	}
	returned := time.Now()
	delivered := 0
	if err == nil {
		delivered = len(imgs.List)
	}
	m := Measured{Served: err == nil, Delivered: delivered, Cost: imgs.Cost, Endpoint: o.endpoint}
	end := endingOf(o.cuts.client, nil, nil)
	cutForCaller := end == cutByClient && cancels
	if end != cutByClient {
		var writeErr error
		if err == nil {
			writeErr = writeJSONBody(rw, func(w io.Writer) error { return media.WriteImages(w, time.Now(), imgs.List) })
		}
		end = endingOf(o.cuts.client, writeErr, err)
		// A client that leaves once the images began going out has them, so it pays as if it stayed.
		if end == cutByClient && !rw.firstBody.IsZero() {
			end = completed
		}
	}
	m.Measurement.Outcome, m.Cut, m.Refusal = end.outcome(), end.cut(), end.refusal(err)
	m.Health = rw.observed(ctx, err, cutForCaller, opened, returned)
	if err != nil && rw.status == 0 {
		refuse(ctx, rw, err)
	}
	return m
}

func writeJSONBody(w http.ResponseWriter, write func(io.Writer) error) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	return write(w)
}

type openedCall struct {
	cuts
	endpoint catalog.EndpointID
	call     func(ctx context.Context) (func(io.Writer) error, error)
}

func (w *InProcess) openSearch(o Opening) (Admission, error) {
	req, err := web.ParseSearchRequest(o.Body)
	if err != nil {
		return nil, contentRefusal(err)
	}
	vendor, known := w.searches[req.Model]
	if !known {
		return nil, apierr.ErrModelNotFound
	}
	if err := refuseProtocol(nil, protocolOf(o.Header.Get)); err != nil {
		return nil, err
	}
	oc := &openedCall{cuts: newCuts(), endpoint: w.endpoints[req.Model], call: func(ctx context.Context) (func(io.Writer) error, error) {
		results, err := vendor.Search(ctx, req)
		return func(w io.Writer) error { return web.WriteResults(w, results) }, err
	}}
	return CallAdmission{admitted: admitted{w.keep(o, oc)}, Route: req.Model}, nil
}

func (w *InProcess) openFetch(o Opening) (Admission, error) {
	req, err := web.ParseFetchRequest(o.Body)
	if err != nil {
		return nil, contentRefusal(err)
	}
	vendor, known := w.fetches[req.Model]
	if !known {
		return nil, apierr.ErrModelNotFound
	}
	if err := refuseProtocol(nil, protocolOf(o.Header.Get)); err != nil {
		return nil, err
	}
	oc := &openedCall{cuts: newCuts(), endpoint: w.endpoints[req.Model], call: func(ctx context.Context) (func(io.Writer) error, error) {
		page, err := vendor.Fetch(ctx, req)
		return func(w io.Writer) error { return web.WritePage(w, page) }, err
	}}
	return CallAdmission{admitted: admitted{w.keep(o, oc)}, Route: req.Model}, nil
}

func (o *openedCall) cut(reason measure.Cut) { o.cuts.cut(reason, false) }

func (o *openedCall) run(_ context.Context, w *InProcess, h Handle, g Grant, reply http.ResponseWriter) Measured {
	if _, ok := g.(CallGrant); !ok {
		return unrunnable(reply)
	}
	ctx := o.cuts.run
	rw := newReplyWriter(reply)
	opened := time.Now()
	write, err := o.call(ctx)
	returned := time.Now()
	var writeErr error
	if err == nil {
		writeErr = writeJSONBody(rw, write)
	}
	end := endingOf(o.cuts.client, writeErr, err)
	m := Measured{Measurement: measure.Measurement{Outcome: end.outcome()}, Cut: end.cut(), Served: err == nil, Refusal: end.refusal(err), Endpoint: o.endpoint}
	m.Health = rw.observed(ctx, err, false, opened, returned)
	if err != nil && rw.status == 0 {
		refuse(ctx, rw, err)
	}
	return m
}
