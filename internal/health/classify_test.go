package health

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/apierr"
	"morse/backend/internal/upstream"
)

var sentinelOutcomes = map[string]struct {
	err  apierr.Error
	want Outcome
}{
	"ErrContextLengthExceeded": {apierr.ErrContextLengthExceeded, ClientError},
	"ErrContentFilter":         {apierr.ErrContentFilter, ContentFilter},
	"ErrInvalidRequest":        {apierr.ErrInvalidRequest, ClientError},
	"ErrMalformedRequest":      {apierr.ErrMalformedRequest, ClientError},
	"ErrRemoteMedia":           {apierr.ErrRemoteMedia, ClientError},
	"ErrRequestTooLarge":       {apierr.ErrRequestTooLarge, ClientError},
	"ErrUpstreamUnavailable":   {apierr.ErrUpstreamUnavailable, UpstreamUnavailable},
	"ErrUpstreamRefused":       {apierr.ErrUpstreamRefused, UpstreamRefused},
	"ErrUpstreamBusy":          {apierr.ErrUpstreamBusy, UpstreamBusy},
	"ErrUpstream":              {apierr.ErrUpstream, UpstreamError},
	"ErrUnattested":            {apierr.ErrUnattested, Unattested},
	"ErrUpstreamRetention":     {apierr.ErrUpstreamRetention, Retention},
	"ErrModelNotFound":         {apierr.ErrModelNotFound, ClientError},
	"ErrInvalidBody":           {apierr.ErrInvalidBody, ClientError},
	"ErrUnavailable":           {apierr.ErrUnavailable, Shutdown},
	"ErrShuttingDown":          {apierr.ErrShuttingDown, Shutdown},
}

func apierrSentinels(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "../apierr/apierr.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, decl := range file.Decls {
		vars, ok := decl.(*ast.GenDecl)
		if !ok || vars.Tok != token.VAR {
			continue
		}
		for _, spec := range vars.Specs {
			for _, name := range spec.(*ast.ValueSpec).Names {
				if strings.HasPrefix(name.Name, "Err") {
					names = append(names, name.Name)
				}
			}
		}
	}
	return names
}

func TestEveryApierrSentinelHasAClassOfItsOwnChoosing(t *testing.T) {
	declared := apierrSentinels(t)
	if len(declared) < 10 {
		t.Fatalf("found only %v in apierr; the walk is not seeing its sentinels", declared)
	}
	for _, name := range declared {
		c, ok := sentinelOutcomes[name]
		if !ok {
			t.Errorf("apierr.%s has no expected class here; add it to byCode and to this table", name)
			continue
		}
		if _, listed := byCode[c.err.Code]; !listed {
			t.Errorf("apierr.%s (%s) is classified by its status, not by a row in byCode", name, c.err.Code)
		}
		if got := Classify(Evidence{Err: fmt.Errorf("provider: %w", c.err)}); got != c.want {
			t.Errorf("apierr.%s is %s, want %s", name, got, c.want)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(sentinelOutcomes)) {
		if !slices.Contains(declared, name) {
			t.Errorf("this table names apierr.%s, which apierr no longer declares", name)
		}
	}
}

func TestClassifyRanksWhatTheProviderDidAboveWhoHungUp(t *testing.T) {
	truncated := errors.New("sse: stream ended without [DONE]")
	cancelled := fmt.Errorf("read: %w", context.Canceled)
	for name, c := range map[string]struct {
		evidence Evidence
		want     Outcome
	}{
		"a finished call": {Evidence{}, OK},
		"a call that returned no error after its client left":                 {Evidence{Cut: CutByCaller, Began: true}, ClientCancel},
		"a call that returned no error before any byte after its client left": {Evidence{Cut: CutByCaller}, ClientCancel},
		"a call that returned no error past the proxy's deadline":             {Evidence{Cut: CutByDeadline, Began: true}, Deadline},
		"a call that returned no error as the replica shut down":              {Evidence{Cut: CutByShutdown, Began: true}, Shutdown},
		"a vendor 503 as the client disconnects":                              {Evidence{Err: apierr.ErrUpstreamBusy, Cut: CutByCaller}, UpstreamBusy},
		"a vendor 5xx as the replica shuts down":                              {Evidence{Err: apierr.ErrUpstream, Cut: CutByShutdown}, UpstreamError},
		"a vendor error event after the first byte":                           {Evidence{Err: apierr.ErrUpstream, Began: true}, MidstreamBreak},
		"a vendor 429 event after the first byte":                             {Evidence{Err: apierr.ErrUpstreamBusy, Began: true}, MidstreamBreak},
		"a content filter after the first byte":                               {Evidence{Err: apierr.ErrContentFilter, Began: true}, ContentFilter},
		"sealed framing that broke after the first byte":                      {Evidence{Err: apierr.ErrUnattested, Began: true}, Unattested},
		"a missing retention header":                                          {Evidence{Err: apierr.ErrUpstreamRetention}, Retention},
		"an unlisted 4xx refusal":                                             {Evidence{Err: apierr.Error{Status: 400, Code: "new_shape_code"}}, ClientError},
		"a refusal built from the caller's cancellation":                      {Evidence{Err: fmt.Errorf("%w: %w", apierr.ErrUnattested, cancelled), Cut: CutByCaller, Began: true}, ClientCancel},
		"a refusal built from the shutdown cut":                               {Evidence{Err: fmt.Errorf("%w: %w", apierr.ErrUnattested, cancelled), Cut: CutByShutdown, Began: true}, Shutdown},
		"a refusal built from the proxy's deadline":                           {Evidence{Err: fmt.Errorf("%w: %w", apierr.ErrUnattested, context.DeadlineExceeded), Cut: CutByDeadline, Began: true}, Deadline},
		"a refusal built from an inner time limit":                            {Evidence{Err: fmt.Errorf("%w: %w", apierr.ErrUpstreamUnavailable, context.DeadlineExceeded)}, Deadline},
		"a refusal built from a cancellation nobody above asked for":          {Evidence{Err: fmt.Errorf("%w: %w", apierr.ErrUnattested, cancelled)}, Unattested},
		"a request never sent because the caller left":                        {Evidence{Err: fmt.Errorf("%w: %w", apierr.ErrUpstreamUnavailable, cancelled), Cut: CutByCaller}, ClientCancel},
		"a request never sent because the vendor could not be reached":        {Evidence{Err: fmt.Errorf("%w: %w", apierr.ErrUpstreamUnavailable, upstream.ErrUnreachable)}, Unreachable},
		"an unlisted 5xx refusal":                                             {Evidence{Err: apierr.Error{Status: 500, Code: "new_code"}}, UpstreamError},
		"a vendor 429 the endpoint refused":                                   {Evidence{Err: upstream.Refused{Status: 429, Err: apierr.ErrUpstreamBusy}}, UpstreamBusy},
		"a vendor 400 the endpoint refused":                                   {Evidence{Err: fmt.Errorf("chat: %w", upstream.Refused{Status: 400, Err: apierr.ErrContentFilter})}, ContentFilter},
		"a 200 the endpoint refused for its retention header":                 {Evidence{Err: upstream.Refused{Status: 200, Err: apierr.ErrUpstreamRetention}}, Retention},
		"a vendor 5xx the endpoint refused after the first byte":              {Evidence{Err: upstream.Refused{Status: 500, Err: apierr.ErrUpstream}, Began: true}, MidstreamBreak},
		"a vendor reply that is not usable":                                   {Evidence{Err: upstream.ErrMalformed}, UpstreamError},
		"a request that was never sent":                                       {Evidence{Err: apierr.ErrUpstreamUnavailable}, UpstreamUnavailable},
		"a connect failure":                                                   {Evidence{Err: upstream.ErrUnreachable}, Unreachable},
		"a connect failure as the client disconnects":                         {Evidence{Err: upstream.ErrUnreachable, Cut: CutByCaller}, Unreachable},
		"a stream given up before its first chunk":                            {Evidence{Err: upstream.ErrStalled}, Stalled},
		"a stream given up before its headers were written":                   {Evidence{Err: upstream.Stalled(fmt.Errorf("%w: %w", upstream.ErrNotSent, context.Canceled))}, Stalled},
		"the proxy's deadline before the first byte":                          {Evidence{Err: context.DeadlineExceeded, Cut: CutByDeadline}, Deadline},
		"the proxy's deadline mid-stream":                                     {Evidence{Err: truncated, Cut: CutByDeadline, Began: true}, Deadline},
		"an inner time limit with the request still alive":                    {Evidence{Err: fmt.Errorf("submit: %w", context.DeadlineExceeded)}, Deadline},
		"an inner time limit as the replica shuts down":                       {Evidence{Err: context.DeadlineExceeded, Cut: CutByShutdown}, Deadline},
		"a stream cut at shutdown":                                            {Evidence{Err: cancelled, Cut: CutByShutdown, Began: true}, Shutdown},
		"a call cut at shutdown before the first byte":                        {Evidence{Err: cancelled, Cut: CutByShutdown}, Shutdown},
		"a client that left mid-stream":                                       {Evidence{Err: cancelled, Cut: CutByCaller, Began: true}, ClientCancel},
		"a client that left before the first byte":                            {Evidence{Err: cancelled, Cut: CutByCaller}, ClientCancel},
		"a stream that ended without its terminator":                          {Evidence{Err: truncated, Began: true}, MidstreamBreak},
		"a reply the proxy could not decode":                                  {Evidence{Err: errors.New("decode")}, UpstreamError},
		"a cancellation nobody above the provider asked for":                  {Evidence{Err: cancelled}, UpstreamError},
	} {
		if got := Classify(c.evidence); got != c.want {
			t.Errorf("%s is %s, want %s", name, got, c.want)
		}
	}
}

func TestOnlyBusyAVendorErrorUnreachableAStallAVendorRefusalOfOurAccountAndAnUnattestedVendorFailOver(t *testing.T) {
	want := map[Outcome]bool{UpstreamBusy: true, UpstreamError: true, Unreachable: true, Stalled: true, UpstreamUnavailable: true, Unattested: true}
	for _, o := range Outcomes() {
		if o.FailsOver() != want[o] {
			t.Errorf("%s fails over: %t, want %t", o, o.FailsOver(), want[o])
		}
	}
}

func TestOnlyBusyAVendorErrorUnreachableAStallAVendorRefusalOfOurAccountAMidstreamBreakAndAnUnattestedVendorTripTheBreaker(t *testing.T) {
	want := map[Outcome]bool{UpstreamBusy: true, UpstreamError: true, Unreachable: true, Stalled: true, UpstreamUnavailable: true, MidstreamBreak: true, Unattested: true}
	for _, o := range Outcomes() {
		if o.TripsBreaker() != want[o] {
			t.Errorf("%s trips the breaker: %t, want %t", o, o.TripsBreaker(), want[o])
		}
	}
}

func TestAMalformedReplyTripsTheBreakerOnlyWhenItEndedOKOrItsOutcomeTripsItAlready(t *testing.T) {
	want := map[Outcome]bool{OK: true, UpstreamBusy: true, UpstreamError: true, Unreachable: true, Stalled: true, UpstreamUnavailable: true, MidstreamBreak: true, Unattested: true}
	for _, o := range Outcomes() {
		seen := Observation{Outcome: o, Malformed: true}
		if seen.TripsBreaker() != want[o] || seen.Healthy() {
			t.Errorf("a malformed %s trips the breaker %t and is healthy %t, want %t and false", o, seen.TripsBreaker(), seen.Healthy(), want[o])
		}
	}
	if ok := (Observation{Outcome: OK}); !ok.Healthy() || ok.TripsBreaker() {
		t.Errorf("a well-formed ok is healthy %t and trips the breaker %t, want true and false", ok.Healthy(), ok.TripsBreaker())
	}
}

func TestABareVendor403Or404IsUpstreamRefusedWhichNeitherFailsOverNorTripsTheBreaker(t *testing.T) {
	for _, status := range []int{403, 404} {
		o := Classify(Evidence{Err: apierr.SanitizedUpstreamError(status, nil)})
		if o != UpstreamRefused || o.FailsOver() || o.TripsBreaker() {
			t.Errorf("a bare %d is %s, fails over %t, trips the breaker %t; want upstream_refused, false, false", status, o, o.FailsOver(), o.TripsBreaker())
		}
	}
}

func TestABareVendor403Or404AfterTheFirstByteIsStillUpstreamRefusedAndTripsNoBreaker(t *testing.T) {
	for _, status := range []int{403, 404} {
		o := Classify(Evidence{Err: apierr.SanitizedUpstreamError(status, nil), Began: true})
		if o != UpstreamRefused || o.FailsOver() || o.TripsBreaker() {
			t.Errorf("a bare %d after the first byte is %s, fails over %t, trips the breaker %t; want upstream_refused, false, false", status, o, o.FailsOver(), o.TripsBreaker())
		}
	}
}
