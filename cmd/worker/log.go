package main

import (
	"context"
	"errors"
	"io"
	stdlog "log"
	"log/slog"
	"slices"
	"strings"
	"time"

	"morse/backend/internal/attestation"
	"morse/backend/internal/attested"
	"morse/backend/internal/chat"
	"morse/backend/internal/health"
)

type message uint8

const (
	configInvalid message = iota
	listening
	shuttingDown
	serveFailed
	routeFailed
	lookupVendorBusy
	vendorRefused
	upstreamErrorChunk
	unknownReplyField
	researchUnwrapped
	upstreamAttested
	upstreamRefused
	upstreamUnpinned
	upstreamRefreshFailed
)

var messages = [...]struct {
	text  string
	level slog.Level
}{
	configInvalid:         {"config invalid", slog.LevelError},
	listening:             {"listening", slog.LevelInfo},
	shuttingDown:          {"shutting down", slog.LevelInfo},
	serveFailed:           {"serve failed", slog.LevelError},
	routeFailed:           {"route failed", slog.LevelWarn},
	lookupVendorBusy:      {"lookup vendor busy", slog.LevelWarn},
	vendorRefused:         {"vendor refused", slog.LevelWarn},
	upstreamErrorChunk:    {"upstream error chunk", slog.LevelWarn},
	unknownReplyField:     {"e2ee reply carried a field the gate does not know", slog.LevelWarn},
	researchUnwrapped:     {"parallel research report unwrapped from its answer object", slog.LevelWarn},
	upstreamAttested:      {"upstream attested", slog.LevelInfo},
	upstreamRefused:       {"upstream refused", slog.LevelWarn},
	upstreamUnpinned:      {"upstream unpinned", slog.LevelError},
	upstreamRefreshFailed: {"upstream attestation refresh failed", slog.LevelWarn},
}

type fields struct {
	Route      string
	Scope      string
	Service    string
	Outcome    *health.Outcome
	Status     int
	Code       *chat.ErrorCode
	Duration   time.Duration
	Count      int
	Generation uint64
	Reason     string
	Drift      string
}

const unlisted = "unlisted"

type logger struct {
	out   *slog.Logger
	names []string
}

func newLogger(w io.Writer, names []string) *logger {
	return &logger{out: slog.New(slog.NewJSONHandler(w, nil)), names: names}
}

func (l *logger) listed(name string) string {
	if slices.Contains(l.names, name) {
		return name
	}
	return unlisted
}

func (l *logger) log(m message, f fields) {
	attrs := []slog.Attr{}
	if f.Route != "" {
		attrs = append(attrs, slog.String("route", l.listed(f.Route)))
	}
	if f.Scope != "" {
		attrs = append(attrs, slog.String("scope", l.listed(f.Scope)))
	}
	if f.Service != "" {
		attrs = append(attrs, slog.String("service", l.listed(f.Service)))
	}
	if f.Outcome != nil {
		attrs = append(attrs, slog.String("outcome", f.Outcome.String()))
	}
	if f.Status != 0 {
		attrs = append(attrs, slog.Int("status", f.Status))
	}
	if f.Code != nil {
		attrs = append(attrs, slog.String("code", f.Code.String()))
	}
	if f.Duration != 0 {
		attrs = append(attrs, slog.Int64("duration_ms", f.Duration.Milliseconds()))
	}
	if f.Count != 0 {
		attrs = append(attrs, slog.Int("count", f.Count))
	}
	if f.Generation != 0 {
		attrs = append(attrs, slog.Uint64("generation", f.Generation))
	}
	if f.Reason != "" {
		attrs = append(attrs, slog.String("reason", f.Reason))
	}
	if f.Drift != "" {
		attrs = append(attrs, slog.String("drift", f.Drift))
	}
	l.out.LogAttrs(context.Background(), messages[m].level, messages[m].text, attrs...)
}

func (l *logger) configFailed(err error) {
	l.out.LogAttrs(context.Background(), messages[configInvalid].level, messages[configInvalid].text, slog.String("err", err.Error()))
}

func (l *logger) Failed(route string, err error) {
	outcome := health.Classify(health.Evidence{Err: err})
	l.log(routeFailed, fields{Route: route, Outcome: &outcome})
}

func (l *logger) LookupBusy(service string) { l.log(lookupVendorBusy, fields{Service: service}) }

func (l *logger) VendorRefused(model string, status int) {
	l.log(vendorRefused, fields{Route: model, Status: status})
}

func (l *logger) UpstreamErrorChunk(model string, code chat.ErrorCode) {
	l.log(upstreamErrorChunk, fields{Route: model, Code: &code})
}

func (l *logger) UnknownReplyField(model, _ string) { l.log(unknownReplyField, fields{Route: model}) }

var attestations = map[attested.Kind]message{
	attested.Anchored:           upstreamAttested,
	attested.Verified:           upstreamAttested,
	attested.Refused:            upstreamRefused,
	attested.Unlisted:           upstreamRefused,
	attested.EndpointRefused:    upstreamRefused,
	attested.GPUVerdictWithheld: upstreamRefused,
	attested.Unpinned:           upstreamUnpinned,
	attested.RefreshFailed:      upstreamRefreshFailed,
}

func is(target error) func(error) bool { return func(err error) bool { return errors.Is(err, target) } }

var unheldReasons = []struct {
	reason  string
	matches func(error) bool
}{
	{"lapsed", is(attested.ErrLapsed)},
	{"disowned", is(attested.ErrDisowned)},
	{"refused", is(attested.ErrReportRefused)},
	{"no_endpoint", is(attested.ErrNoEndpoint)},
	{"unjudged", attestation.Unjudged},
}

func reasonOf(err error) string {
	for _, r := range unheldReasons {
		if r.matches(err) {
			return r.reason
		}
	}
	return "fetch_failed"
}

func driftOf(err error) string {
	var refusal *attestation.AnchorRefusal
	if !errors.As(err, &refusal) {
		return ""
	}
	names := make([]string, len(refusal.Drifts))
	for i, d := range refusal.Drifts {
		names[i] = d.Field
	}
	slices.Sort(names)
	return strings.Join(slices.Compact(names), ",")
}

func (l *logger) attestation(ev attested.Event) {
	m, known := attestations[ev.Kind]
	if !known {
		return
	}
	f := fields{Scope: ev.Scope, Generation: ev.Generation, Count: len(ev.Keys)}
	if (m == upstreamUnpinned || m == upstreamRefreshFailed) && ev.Err != nil {
		f.Reason, f.Drift = reasonOf(ev.Err), driftOf(ev.Err)
	}
	l.log(m, f)
}

func discarded() *stdlog.Logger { return stdlog.New(io.Discard, "", 0) }
