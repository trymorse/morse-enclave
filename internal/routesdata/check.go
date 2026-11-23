package routesdata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"morse/backend/internal/pinsig"
)

var ErrNoTime = errors.New("routesdata: no trusted time")

type Kind uint8

const (
	NothingOffered Kind = iota + 1
	Refused
	WouldLoad
)

type Event struct {
	Kind       Kind
	BootSHA256 string
	Offered    Admitted
	SameAsBoot bool
	Err        error
}

type Checker struct {
	Mode    Mode
	Image   Image
	Fetch   func(context.Context) (Offer, error)
	Now     func(context.Context) (time.Time, error)
	Observe func(Event)
}

func (c Checker) Check(ctx context.Context) {
	if c.Mode != Log {
		return
	}
	boot := sha256.Sum256(c.Image.Boot)
	event := Event{BootSHA256: hex.EncodeToString(boot[:])}
	admitted, err := c.admit(ctx)
	switch {
	case errors.Is(err, ErrNoOffer):
		event.Kind = NothingOffered
	case err != nil:
		event.Kind, event.Err = Refused, err
	default:
		admitted.File = nil
		event.Kind, event.Offered, event.SameAsBoot = WouldLoad, admitted, admitted.FileSHA256 == event.BootSHA256
	}
	c.Observe(event)
}

const (
	RecheckEvery   = 5 * time.Minute
	RecheckTimeout = 30 * time.Second
)

type Recheck struct {
	Every    time.Duration
	Timeout  time.Duration
	Panicked func(recovered any)
}

func (c Checker) Recheck(ctx context.Context, r Recheck) {
	if c.Mode != Log {
		return
	}
	tick := time.NewTicker(r.Every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			c.checkWithin(ctx, r)
		}
	}
}

func (c Checker) checkWithin(ctx context.Context, r Recheck) {
	defer func() {
		if recovered := recover(); recovered != nil {
			r.Panicked(recovered)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	c.Check(ctx)
}

func (e Event) Same(other Event) bool {
	return e.Kind == other.Kind && e.Refusal() == other.Refusal() && e.SameAsBoot == other.SameAsBoot &&
		e.Offered.Sequence == other.Offered.Sequence && e.Offered.StatementSHA256 == other.Offered.StatementSHA256 && e.Offered.FileSHA256 == other.Offered.FileSHA256
}

func (c Checker) admit(ctx context.Context) (Admitted, error) {
	offer, err := c.Fetch(ctx)
	if err != nil {
		return Admitted{}, err
	}
	now, err := c.Now(ctx)
	if err != nil {
		return Admitted{}, fmt.Errorf("%w: %w", ErrNoTime, err)
	}
	return c.Image.Admit(offer, now)
}

const (
	OutcomeNothingOffered = "nothing_offered"
	OutcomeRefused        = "refused"
	OutcomeWouldLoad      = "would_load"
)

var Outcomes = []string{OutcomeNothingOffered, OutcomeRefused, OutcomeWouldLoad}

func (e Event) Outcome() string {
	switch e.Kind {
	case NothingOffered:
		return OutcomeNothingOffered
	case WouldLoad:
		return OutcomeWouldLoad
	}
	return OutcomeRefused
}

var refusals = []struct {
	name string
	errs []error
}{
	{"not_an_offer", []error{ErrNotOffer}},
	{"size", []error{ErrSize}},
	{"no_trusted_time", []error{ErrNoTime}},
	{"signature", []error{pinsig.ErrBundle, pinsig.ErrLog, pinsig.ErrBody, pinsig.ErrCertificate, pinsig.ErrSignature, pinsig.ErrIdentity}},
	{"statement", []error{pinsig.ErrStatement}},
	{"not_for_this_image_or_too_old", []error{pinsig.ErrAdmit}},
	{"outside_the_images_bounds", []error{ErrBounds}},
	{"does_not_load", []error{ErrLoad}},
}

const RefusalUnreadable = "host_unreadable"

func Refusals() []string {
	names := []string{RefusalUnreadable}
	for _, r := range refusals {
		names = append(names, r.name)
	}
	return names
}

func (e Event) Refusal() string {
	if e.Kind != Refused {
		return ""
	}
	for _, r := range refusals {
		for _, err := range r.errs {
			if errors.Is(e.Err, err) {
				return r.name
			}
		}
	}
	return RefusalUnreadable
}
