package worker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/health"
	"morse/backend/internal/upstream"
)

func TestHowARequestEndedIsReadOnceFromTheCauseTheWriteAndTheCall(t *testing.T) {
	live := context.Background()
	byClient, cancelByClient := context.WithCancelCause(context.Background())
	cancelByClient(context.Canceled)
	byShutdown, cancelByShutdown := context.WithCancelCause(context.Background())
	cancelByShutdown(ErrShutdown)
	pastDeadline, cancelDeadline := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelDeadline()
	brokenPipe := errors.New("write: broken pipe")
	writeDeadline := fmt.Errorf("write tcp: %w", os.ErrDeadlineExceeded)
	vendorBusy := upstream.Refused{Status: 529, Err: apierr.ErrUpstreamBusy}
	for name, tc := range map[string]struct {
		ctx               context.Context
		writeErr, callErr error
		want              ending
	}{
		"stream finished":                             {live, nil, nil, completed},
		"upstream refused":                            {live, nil, apierr.ErrUpstreamBusy, rejected},
		"upstream failed":                             {live, nil, io.ErrUnexpectedEOF, failed},
		"client hung up":                              {byClient, nil, nil, cutByClient},
		"client hung up as the stream failed busy":    {byClient, nil, apierr.ErrUpstreamBusy, cutByClient},
		"client hung up after the vendor refused":     {byClient, nil, vendorBusy, rejected},
		"shutdown after the vendor refused":           {byShutdown, nil, vendorBusy, rejected},
		"MaxRequestDuration after the vendor refused": {pastDeadline, nil, vendorBusy, rejected},
		"client stopped reading":                      {live, brokenPipe, nil, cutByClient},
		"client stopped reading and the stream broke": {live, brokenPipe, io.ErrUnexpectedEOF, cutByClient},
		"shutdown cut the stream":                     {byShutdown, nil, nil, cutByProxy},
		"shutdown closed a connection mid-write":      {byShutdown, brokenPipe, nil, cutByProxy},
		"MaxRequestDuration cut the stream":           {pastDeadline, nil, nil, cutByDeadline},
		"a write failed at MaxRequestDuration":        {pastDeadline, writeDeadline, nil, cutByDeadline},
		"the write deadline fired before the context": {live, writeDeadline, nil, cutByDeadline},
	} {
		if got := endingOf(tc.ctx, tc.writeErr, tc.callErr); got != tc.want {
			t.Errorf("%s: ending %d, want %d", name, got, tc.want)
		}
	}
}

func TestEvidenceReadsTheServeContextsCause(t *testing.T) {
	shutdown, cut := context.WithCancelCause(context.Background())
	cut(ErrShutdown)
	left, leave := context.WithCancel(context.Background())
	leave()
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	underShutdown, cancelInner := context.WithDeadline(shutdown, time.Now().Add(time.Hour))
	defer cancelInner()
	broken := fmt.Errorf("read: %w", io.ErrUnexpectedEOF)
	gone := fmt.Errorf("write: %w", syscall.EPIPE)
	stalled := fmt.Errorf("write: %w", os.ErrDeadlineExceeded)
	for name, c := range map[string]struct {
		ctx      context.Context
		err      error
		writeErr error
		began    bool
		want     health.Outcome
	}{
		"a stream cut at shutdown":                           {underShutdown, broken, nil, true, health.Shutdown},
		"a stream the client left":                           {left, broken, nil, true, health.ClientCancel},
		"a stream past the request deadline":                 {expired, broken, nil, true, health.Deadline},
		"a stream that broke with its client there":          {context.Background(), broken, nil, true, health.MidstreamBreak},
		"a vendor 503 as the replica exits":                  {shutdown, apierr.ErrUpstreamBusy, nil, false, health.UpstreamBusy},
		"a call that returned no error as its client left":   {left, nil, nil, true, health.ClientCancel},
		"a write that failed before the context was told":    {context.Background(), gone, gone, true, health.ClientCancel},
		"a write that failed under a provider with no error": {context.Background(), nil, gone, true, health.ClientCancel},
		"a write past the write deadline":                    {context.Background(), stalled, stalled, true, health.Deadline},
		"a vendor 503 after a failed write":                  {context.Background(), apierr.ErrUpstreamBusy, gone, false, health.UpstreamBusy},
		"a call that finished with its client there":         {context.Background(), nil, nil, true, health.OK},
	} {
		if got := health.Classify(evidenceOf(c.ctx, c.err, c.writeErr, c.began)); got != c.want {
			t.Errorf("%s is %s, want %s", name, got, c.want)
		}
	}
}

func TestAClientCutOfARequestReasoningAtTheRouteDefaultOnAHidingRouteBillsItsThinkingTime(t *testing.T) {
	plain := streamBody("")
	defaulted := chat.Call{Request: parsed(t, plain), OutputLimit: 500, RouteEffort: "high"}
	e := served{reply: measure.Streamed{Events: 3}, thought: thought{duration: 2 * time.Second}}.evidence(cutByClient, defaulted, chatRoute{ChatTerms: catalog.ChatTerms{HidesReasoning: true}}, ChatGrant{ReasoningCap: 500, Figures: measure.RouteFigures{ThinkingRate: 100, ReplyBytesPerToken: 4}})
	if got := e.Measure().Tokens; got != (chat.Usage{PromptTokens: tokenFloorOf(plain), CompletionTokens: 3 + 200}) {
		t.Errorf("billed %+v, want the chunks plus 2s of thinking, since the upstream reasoned at the route's default effort", got)
	}
}
