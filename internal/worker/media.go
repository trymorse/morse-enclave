package worker

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/frameconsent"
	"morse/backend/internal/media"
	"morse/backend/internal/promptcheck"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/web"
)

type openedImages struct {
	cuts
	endpoint  catalog.EndpointID
	generator media.ImageGenerator
	screened  Screened
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
	if err := asRetiredImageNameWasServed(w.retired, generator.Spec(), req); err != nil {
		return nil, apierr.InvalidParameter(err.Error())
	}
	if err := generator.CheckImages(req); err != nil {
		return nil, apierr.InvalidParameter(err.Error())
	}
	oi := &openedImages{cuts: newCuts(), endpoint: w.endpoints[req.Model], generator: generator, screened: w.screened[req.Model], req: req}
	return MediaAdmission{admitted: admitted{w.keep(o, oi)}, Route: req.Model, Units: req.N, References: len(req.References()), Resolution: req.Size.Resolution, Frames: req.ReferenceDigests()}, nil
}

func asRetiredImageNameWasServed(retired map[string]string, spec media.ImageSpec, req *media.ImageRequest) error {
	to, isRetired := retired[req.Model]
	if !isRetired {
		return nil
	}
	if !spec.Seed {
		req.Seed = nil
	}
	if refs := len(req.ReferenceImages()); spec.MaxReferences > 0 && refs > spec.MaxReferences {
		return strictjson.Invalid(fmt.Sprintf("%s was retired; %s, which replaced it, takes at most %d reference images.", req.Model, to, spec.MaxReferences))
	}
	return nil
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
	err := o.unconsented(mg)
	if err == nil {
		err = w.screen(ctx, mg.PromptCheck, o.screened, promptcheck.Image, o.req.Prompt())
	}
	canceller, cancels := o.generator.(media.Canceller)
	switch {
	case err != nil:
	case cancels:
		imgs, err = canceller.GenerateImagesUntil(ctx, o.cuts.client.Done(), o.req)
	default:
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
		if end == cutByClient && rw.phase() == bodyBegun {
			end = completed
		}
	}
	m.Measurement.Outcome, m.Cut, m.Refusal = end.outcome(), end.cut(), end.refusal(err)
	m.Health = rw.observed(ctx, err, cutForCaller, opened, returned)
	if rw.unsent(err) {
		refuse(ctx, rw, err)
	}
	return m
}

func (o *openedImages) unconsented(g MediaGrant) error {
	gated, ok := o.generator.(media.FrameConsentGated)
	if !ok || !gated.FramesNeedConsent() {
		return nil
	}
	if image, missing := frameconsent.Missing(o.req.ReferenceDigests(), g.ConsentedFrames); missing {
		return frameconsent.RequiredImage(image)
	}
	return nil
}

func writeJSONBody(w http.ResponseWriter, write func(io.Writer) error) error {
	return writeBody(w, "application/json", write)
}

func writeBody(w http.ResponseWriter, contentType string, write func(io.Writer) error) error {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	return write(w)
}

type openedCall struct {
	cuts
	endpoint    catalog.EndpointID
	call        func(ctx context.Context) (func(io.Writer) error, error)
	contentType string
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
		writeErr = writeBody(rw, cmp.Or(o.contentType, "application/json"), write)
	}
	end := endingOf(o.cuts.client, writeErr, err)
	m := Measured{Measurement: measure.Measurement{Outcome: end.outcome()}, Cut: end.cut(), Served: err == nil, Refusal: end.refusal(err), Endpoint: o.endpoint}
	m.Health = rw.observed(ctx, err, false, opened, returned)
	if rw.unsent(err) {
		refuse(ctx, rw, err)
	}
	return m
}
