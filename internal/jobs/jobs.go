package jobs

import (
	"errors"
	"fmt"
	"strconv"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/enum"
	"morse/backend/internal/health"
)

type Status uint8

const (
	Queued Status = iota
	Running
	Completed
	Failed
	Expired
)

var wireStatusNames = enum.Names[Status]{Queued: "queued", Running: "running", Completed: "completed", Failed: "failed", Expired: "expired"}

func (s Status) Active() bool { return s == Queued || s == Running }

func (s Status) MarshalText() ([]byte, error) { return wireStatusNames.MarshalText(s) }

func (s *Status) UnmarshalText(text []byte) error { return wireStatusNames.UnmarshalText(s, text) }

type Failure uint8

const (
	UpstreamError Failure = iota + 1
	ContentFilter
	Timeout
)

var failureNames = enum.Names[Failure]{UpstreamError: "upstream_error", ContentFilter: "content_filter", Timeout: "timeout"}

func ParseFailure(name string) (Failure, bool) { return failureNames.Parse(name) }

func (f Failure) String() string {
	if f == 0 {
		return ""
	}
	return failureNames.String(f)
}

func (f Failure) MarshalText() ([]byte, error) {
	switch {
	case f == 0:
		return nil, nil
	case failureNames.Valid(f):
		return failureNames.MarshalText(f)
	}
	return []byte(strconv.Itoa(int(f))), nil
}

func (f *Failure) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*f = 0
		return nil
	}
	if failureNames.UnmarshalText(f, text) == nil {
		return nil
	}
	n, err := strconv.ParseUint(string(text), 10, 8)
	if err != nil {
		return fmt.Errorf("%q is not one of %s", text, failureNames.List())
	}
	*f = Failure(n)
	return nil
}

func (f Failure) Outcome() measure.Outcome {
	if f == Timeout {
		return measure.Failed
	}
	return measure.Rejected
}

var refusals = map[Failure]measure.RefusalCode{UpstreamError: measure.RefusedUpstreamError, ContentFilter: measure.RefusedContentFilter}

func (f Failure) Refusal() measure.RefusalCode { return refusals[f] }

var healthOutcomes = map[Failure]health.Outcome{ContentFilter: health.ContentFilter, Timeout: health.Deadline}

func (f Failure) Health() health.Outcome {
	if outcome, listed := healthOutcomes[f]; listed {
		return outcome
	}
	return health.UpstreamError
}

type Poll struct {
	Status    Status
	Progress  int
	Failure   Failure
	Cost      money.Reported
	OutputURL string
}

var Unserved = Poll{Status: Failed, Failure: UpstreamError}

func FailedBy(err error) Poll {
	if errors.Is(err, apierr.ErrContentFilter) {
		return Poll{Status: Failed, Failure: ContentFilter}
	}
	return Unserved
}
