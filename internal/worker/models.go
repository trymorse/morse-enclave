package worker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"morse/backend/internal/audio"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/media"
	"morse/backend/internal/research"
	"morse/backend/internal/tokenizer"
	"morse/backend/internal/web"
)

type Model struct {
	ID        catalog.ModelID
	Endpoint  catalog.EndpointID
	Tier      catalog.Tier
	Retention catalog.Retention
	Attester  string
	Order     int
	Serves    Serving
	// Place is how the endpoint serves under its name, and Beside are the endpoints that serve beside a named one: its
	// sealed fallbacks, which a sealed request names by protocol; its unnamed endpoints, which join the tier's
	// candidates and never a name's; and its on-behalf endpoints, tee endpoints through which the worker seals a
	// plaintext chat to the named sealed endpoint for its client, which join the plaintext candidates at tee.
	Place  catalog.Place
	Beside []Model
}

func (m Model) at(places ...catalog.Place) []Model {
	var at []Model
	for _, b := range m.Beside {
		if slices.Contains(places, b.Place) {
			at = append(at, b)
		}
	}
	return at
}

type Serving interface{ validate(catalog.Tier) error }

type Chat struct {
	catalog.ChatTerms
	Upstream             ChatUpstream
	Reasoning            chat.Reasoning
	ReasoningUncapped    bool
	SilentWhileReasoning bool
	// IgnoresOutputLimit marks a host that generates past the output limit it is sent, whose reply the worker counts
	// and ends at the limit (limitCut).
	IgnoresOutputLimit bool
	Counter            *tokenizer.Tokenizer
}

type ChatUpstream interface {
	Validate(catalog.Tier) error
	Speaks() *chat.Scheme
	attester() chat.Attester
	admit(o *openedChat, cast chat.Cast) error
	serve(ctx context.Context, w *InProcess, o *openedChat, a attempt, reply http.ResponseWriter) served
	count(a attempt, e measure.Evidence, got served) *pendingCount
	busyWaits() []time.Duration
	hedge() chat.Hedge
}

// Plain streams a chat in the clear. Hedge races a silent stream with a second call, to the next endpoint of the grant
// or else to this one, and gives a stalled one up; the zero Hedge does neither, as on a route whose first chunk waits
// for reasoning the client never sees.
type Plain struct {
	chat.Provider
	Attester  chat.Attester
	BusyWaits []time.Duration
	Hedge     chat.Hedge
}

type Verbatim struct{ Route chat.VerbatimRoute }

func (u Plain) Validate(tier catalog.Tier) error {
	switch {
	case u.Provider == nil:
		return errors.New("serves chat with no provider")
	case (u.Attester != nil) != tier.Attested():
		return fmt.Errorf("is tier %s and serves a provider with attester %v, which that tier does not serve", tier, u.Attester)
	}
	return catalog.Plaintext.Validate(tier)
}

func (Plain) Speaks() *chat.Scheme { return nil }

func (u Plain) attester() chat.Attester { return u.Attester }

func (u Plain) busyWaits() []time.Duration { return u.BusyWaits }

func (u Plain) hedge() chat.Hedge { return u.Hedge }

func (u Verbatim) Validate(tier catalog.Tier) error {
	if u.Route == nil {
		return errors.New("relays verbatim through no route")
	}
	return catalog.Verbatim.Validate(tier)
}

func (u Verbatim) Speaks() *chat.Scheme { return u.Route.Speaks() }

func (u Verbatim) attester() chat.Attester { return u.Route }

func (Verbatim) busyWaits() []time.Duration { return nil }

func (Verbatim) hedge() chat.Hedge { return chat.Hedge{} }

type Images struct{ media.ImageGenerator }

type Videos struct{ media.VideoGenerator }

type Search struct{ web.Searcher }

type Fetch struct{ web.Fetcher }

type Research struct{ research.Researcher }

// Transcription serves a transcription model. Attester attests it, and is set exactly on an attested tier.
type Transcription struct {
	audio.Transcriber
	Attester chat.Attester
}

func (c Chat) validate(tier catalog.Tier) error {
	if c.Upstream == nil {
		return errors.New("serves chat with no upstream")
	}
	return c.Upstream.Validate(tier)
}

func (i Images) validate(catalog.Tier) error {
	if i.ImageGenerator == nil {
		return errors.New("serves images with no generator")
	}
	return nil
}

func (v Videos) validate(catalog.Tier) error {
	if v.VideoGenerator == nil {
		return errors.New("serves videos with no generator")
	}
	return nil
}

func (s Search) validate(catalog.Tier) error {
	if s.Searcher == nil {
		return errors.New("serves search with no vendor")
	}
	return nil
}

func (f Fetch) validate(catalog.Tier) error {
	if f.Fetcher == nil {
		return errors.New("serves fetch with no vendor")
	}
	return nil
}

func (r Research) validate(catalog.Tier) error {
	if r.Researcher == nil {
		return errors.New("serves research with no vendor")
	}
	return nil
}

func (t Transcription) validate(tier catalog.Tier) error {
	switch {
	case t.Transcriber == nil:
		return errors.New("serves transcription with no vendor")
	case (t.Attester != nil) != tier.Attested():
		return fmt.Errorf("is tier %s and serves transcription with attester %v, which that tier does not serve", tier, t.Attester)
	}
	return nil
}

func (m Model) Validate() error {
	if m.Serves == nil {
		return errors.New("serves nothing")
	}
	if err := m.Serves.validate(m.Tier); err != nil {
		return err
	}
	served := map[catalog.EndpointID]bool{m.Endpoint: true}
	for _, b := range m.Beside {
		c, chats := b.Serves.(Chat)
		_, viaPlain := c.Upstream.(Plain)
		switch {
		case len(b.Beside) > 0:
			return fmt.Errorf("has %s with endpoints of its own; list them beside it", b.Place.Describe(b.Attester, b.Endpoint))
		case served[b.Endpoint]:
			return fmt.Errorf("has two vendors at endpoint %q", b.Endpoint)
		case b.Place == catalog.PlaceUnnamed && (!chats || b.Tier != m.Tier || b.Tier.Sealed()):
			return fmt.Errorf("has unnamed endpoint %q, which must serve chat at tier %s, outside e2ee", b.Endpoint, m.Tier)
		case b.Place == catalog.PlaceOnBehalf && (!chats || !viaPlain || b.Tier != catalog.OnBehalfTier || !m.Tier.Sealed()):
			return fmt.Errorf("has on-behalf endpoint %q, which must serve a plain chat at tier %s beside a sealed endpoint", b.Endpoint, catalog.OnBehalfTier)
		}
		if err := b.Validate(); err != nil {
			return fmt.Errorf("has %s that %w", b.Place.Describe(b.Attester, b.Endpoint), err)
		}
		served[b.Endpoint] = true
	}
	return nil
}
