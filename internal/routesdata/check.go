package routesdata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

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

func (c Checker) admit(ctx context.Context) (Admitted, error) {
	offer, err := c.Fetch(ctx)
	if err != nil {
		return Admitted{}, err
	}
	now, err := c.Now(ctx)
	if err != nil {
		return Admitted{}, fmt.Errorf("routesdata: no trusted time: %w", err)
	}
	return c.Image.Admit(offer, now)
}
