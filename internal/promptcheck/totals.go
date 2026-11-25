package promptcheck

import (
	"maps"
	"slices"
	"sync"
	"time"

	"morse/backend/internal/enum"
)

type Kind uint8

const (
	Image Kind = iota + 1
	Video
)

var Kinds = enum.Names[Kind]{Image: "image", Video: "video"}

func (k Kind) String() string                { return Kinds.String(k) }
func (k Kind) MarshalText() ([]byte, error)  { return Kinds.MarshalText(k) }
func (k *Kind) UnmarshalText(b []byte) error { return Kinds.UnmarshalText(k, b) }

type Outcome uint8

const (
	Allowed Outcome = iota + 1
	Refused
	Unavailable
)

var Outcomes = enum.Names[Outcome]{Allowed: "allowed", Refused: "refused", Unavailable: "unavailable"}

func (o Outcome) String() string                { return Outcomes.String(o) }
func (o Outcome) MarshalText() ([]byte, error)  { return Outcomes.MarshalText(o) }
func (o *Outcome) UnmarshalText(b []byte) error { return Outcomes.UnmarshalText(o, b) }

type Total struct {
	Hour    time.Time `json:"hour"`
	Kind    Kind      `json:"kind"`
	Outcome Outcome   `json:"outcome"`
	N       int64     `json:"n"`
}

const keptHours = 24

type totalKey struct {
	hour    int64
	kind    Kind
	outcome Outcome
}

type Totals struct {
	mu sync.Mutex
	n  map[totalKey]int64
}

func (t *Totals) Add(now time.Time, kind Kind, outcome Outcome) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.n == nil {
		t.n = map[totalKey]int64{}
	}
	hour := now.Truncate(time.Hour).Unix()
	for k := range t.n {
		if k.hour < hour-keptHours*int64(time.Hour/time.Second) {
			delete(t.n, k)
		}
	}
	t.n[totalKey{hour, kind, outcome}]++
}

// why: an hour still open would move as each request ended, and so name the one refused. An ended hour with few
// refusals can still be matched to its rejected charges.
func (t *Totals) Ended(now time.Time) []Total {
	t.mu.Lock()
	defer t.mu.Unlock()
	open := now.Truncate(time.Hour).Unix()
	keys := slices.SortedFunc(maps.Keys(t.n), func(a, b totalKey) int {
		return slices.Compare([]int64{a.hour, int64(a.kind), int64(a.outcome)}, []int64{b.hour, int64(b.kind), int64(b.outcome)})
	})
	var ended []Total
	for _, k := range keys {
		if k.hour < open {
			ended = append(ended, Total{Hour: time.Unix(k.hour, 0).UTC(), Kind: k.kind, Outcome: k.outcome, N: t.n[k]})
		}
	}
	return ended
}
