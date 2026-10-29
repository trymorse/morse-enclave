package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/jobs"
	"morse/backend/internal/media"
	"morse/backend/internal/research"
)

type openedVideo struct {
	cuts
	generator media.VideoGenerator
	req       *media.VideoRequest
}

func (w *InProcess) openVideo(o Opening) (Admission, error) {
	req, err := media.ParseVideoRequest(o.Body)
	if err != nil {
		return nil, contentRefusal(err)
	}
	generator, known := w.videos[req.Model]
	if !known {
		return nil, apierr.ErrModelNotFound
	}
	if err := refuseProtocol(nil, protocolOf(o.Header.Get)); err != nil {
		return nil, err
	}
	resolved, err := generator.ResolveVideo(*req)
	if err != nil {
		return nil, apierr.InvalidParameter(err.Error())
	}
	ov := &openedVideo{cuts: newCuts(), generator: generator, req: &resolved}
	return MediaAdmission{admitted: admitted{w.keep(o, ov)}, Route: req.Model, Units: resolved.Seconds}, nil
}

func (o *openedVideo) cut(reason measure.Cut) { o.cuts.cut(reason, false) }

func (o *openedVideo) submit(w *InProcess, g JobGrant, reply http.ResponseWriter, accepted func(media.Submitted)) Measured {
	queued := VideoView{ID: g.ID, Object: "video", Model: o.req.Model, Status: media.Statuses.String(jobs.Queued), CreatedAt: g.CreatedAt.Unix()}
	return submit(o.cuts, reply, queued, accepted, func(ctx context.Context) (media.Submitted, error) {
		ctx, cancel := context.WithTimeout(ctx, w.videoSubmit)
		defer cancel()
		return o.generator.SubmitVideo(ctx, o.req, media.Submission{Deadline: g.Deadline, UploadURL: g.UploadURL})
	})
}

type openedResearch struct {
	cuts
	vendor research.Researcher
	req    *research.Request
}

func (w *InProcess) openResearch(o Opening) (Admission, error) {
	req, err := research.ParseRequest(o.Body)
	if err != nil {
		return nil, contentRefusal(err)
	}
	vendor, known := w.researchers[req.Model]
	if !known {
		return nil, apierr.ErrModelNotFound
	}
	if err := refuseProtocol(nil, protocolOf(o.Header.Get)); err != nil {
		return nil, err
	}
	or := &openedResearch{cuts: newCuts(), vendor: vendor, req: req}
	return CallAdmission{admitted: admitted{w.keep(o, or)}, Route: req.Model}, nil
}

func (o *openedResearch) cut(reason measure.Cut) { o.cuts.cut(reason, false) }

func (o *openedResearch) submit(_ *InProcess, g JobGrant, reply http.ResponseWriter, accepted func(media.Submitted)) Measured {
	queued := ResearchView{ID: g.ID, Object: "research", Model: o.req.Model, Status: research.Statuses.String(jobs.Queued), CreatedAt: g.CreatedAt.Unix()}
	return submit(o.cuts, reply, queued, accepted, func(ctx context.Context) (media.Submitted, error) {
		ctx, cancel := context.WithTimeout(ctx, researchCallTimeout)
		defer cancel()
		runID, err := o.vendor.Start(ctx, o.req)
		return media.Submitted{VendorID: runID}, err
	})
}

const (
	researchCallTimeout = 30 * time.Second
	// Parallel closes a run's event stream after 570 seconds; this bounds a stream that never closes.
	researchEventsWindow = 10 * time.Minute
)

type openedRead struct {
	cuts
	id string
}

func (w *InProcess) openRead(o Opening, pathValue func(string) string) (Admission, error) {
	id := pathValue("id")
	return ReadAdmission{admitted: admitted{w.keep(o, &openedRead{cuts: newCuts(), id: id})}, JobID: id}, nil
}

func (o *openedRead) cut(reason measure.Cut) { o.cuts.cut(reason, true) }

func (o *openedRead) run(_ context.Context, w *InProcess, _ Handle, g Grant, reply http.ResponseWriter) Measured {
	rw := newReplyWriter(reply)
	switch g := g.(type) {
	case VideoReadGrant:
		return w.streamVideo(o.cuts.run, rw, g)
	case ResearchReadGrant:
		return w.readResearch(o.cuts.run, rw, o.id, g)
	case ResearchEventsGrant:
		return w.relayEvents(o.cuts.run, rw, g)
	}
	return unrunnable(rw)
}

func (w *InProcess) streamVideo(ctx context.Context, rw *replyWriter, g VideoReadGrant) Measured {
	rc, size, err := w.videos[g.Route].OpenVideo(ctx, g.Output)
	switch {
	case errors.Is(err, media.ErrVideoGone):
		apierr.WriteError(rw, ErrVideoExpired)
		return Measured{Measurement: measure.Measurement{Outcome: measure.Rejected}}
	case err != nil:
		apierr.WriteError(rw, apierr.ErrUpstream)
		return Measured{Measurement: measure.Measurement{Outcome: measure.Failed}}
	}
	defer rc.Close()
	rw.Header().Set("Content-Type", "video/mp4")
	rw.Header().Set("Cache-Control", "no-store")
	if size > 0 {
		rw.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	n, err := io.Copy(rw, rc)
	return Measured{Served: true, Downloaded: err == nil && (size <= 0 || n == size)}
}

func (w *InProcess) readResearch(ctx context.Context, rw *replyWriter, id string, g ResearchReadGrant) Measured {
	view := ResearchView{ID: id, Object: "research", Model: g.Route, Status: research.Statuses.String(g.Status), CreatedAt: g.CreatedAt.Unix()}
	if g.Status == jobs.Failed {
		view.Error = &JobError{Code: g.Failure.String(), Message: researchFailures[g.Failure]}
	}
	if g.Status == jobs.Completed {
		read, cancel := context.WithTimeout(ctx, researchCallTimeout)
		defer cancel()
		output, err := w.researchers[g.Route].Output(read, g.VendorID)
		if err != nil {
			refusal, _ := apierr.Refusal(err, research.ErrUpstream)
			apierr.WriteError(rw, refusal)
			return Measured{Measurement: measure.Measurement{Outcome: measure.Failed}}
		}
		view.Output = &output
	}
	rw.Header().Set("Cache-Control", "no-store")
	apierr.WriteJSON(rw, http.StatusOK, view)
	return Measured{Served: true}
}

func (w *InProcess) relayEvents(ctx context.Context, rw *replyWriter, g ResearchEventsGrant) Measured {
	relay := &eventStream{w: rw, rc: http.NewResponseController(rw)}
	if !g.Status.Active() {
		relay.researchEvent(research.State(g.Status))
		return Measured{Served: true}
	}
	ctx, cancel := context.WithTimeout(ctx, researchEventsWindow)
	defer cancel()
	stream, err := w.researchers[g.Route].Watch(ctx, g.VendorID)
	if err != nil {
		refusal, _ := apierr.Refusal(err, research.ErrUpstream)
		apierr.WriteError(rw, refusal)
		return Measured{Measurement: measure.Measurement{Outcome: measure.Failed}}
	}
	defer stream.Close()
	relayResearch(ctx, relay, stream, w.keepaliveEvery)
	return Measured{Served: true}
}

func relayResearch(ctx context.Context, relay *eventStream, stream research.Stream, keepalive time.Duration) {
	events := make(chan research.Event)
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		stream.Each(func(e research.Event) error {
			select {
			case events <- e:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	relay.start()
	if relay.flush() != nil {
		return
	}
	defer relay.keepAlive(ctx, keepalive)()
	for {
		var err error
		select {
		case e := <-events:
			err = relay.researchEvent(e)
		case <-ended:
			return
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (s *eventStream) researchEvent(e research.Event) error {
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return s.event(bytes.NewReader(data))
}

func submit(c cuts, reply http.ResponseWriter, queued any, accepted func(media.Submitted), start func(ctx context.Context) (media.Submitted, error)) Measured {
	ctx := c.run
	rw := newReplyWriter(reply)
	opened := time.Now()
	sub, err := start(ctx)
	returned := time.Now()
	var writeErr error
	if err == nil {
		accepted(sub)
		writeErr = writeJSONBody(rw, func(w io.Writer) error { return json.NewEncoder(w).Encode(queued) })
	}
	end := endingOf(c.client, writeErr, err)
	m := Measured{Measurement: measure.Measurement{Outcome: end.outcome()}, Cut: end.cut(), Served: err == nil, Refusal: end.refusal(err)}
	m.Health = rw.observed(ctx, err, false, opened, returned)
	if err != nil && rw.status == 0 {
		refuse(ctx, rw, err)
	}
	return m
}
