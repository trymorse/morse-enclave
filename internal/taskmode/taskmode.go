// Package taskmode names a scheduled task's privacy mode and when its results notify, one type for the relay and the
// worker, so neither converts the other's.
package taskmode

import (
	"morse/backend/internal/catalog"
	"morse/backend/internal/enum"
)

// Mode is the privacy mode a task runs in, named as catalog.Tier names the tier its route must have.
type Mode uint8

const (
	Anon Mode = iota + 1
	Private
)

var modeNames = enum.Names[Mode]{Anon: "anon", Private: "private"}

var modeTiers = [...]catalog.Tier{Anon: catalog.Anon, Private: catalog.Private}

func (m Mode) String() string { return modeNames.String(m) }

func (m Mode) MarshalText() ([]byte, error) { return modeNames.MarshalText(m) }

func (m *Mode) UnmarshalText(text []byte) error { return modeNames.UnmarshalText(m, text) }

func Modes() []Mode { return modeNames.Values() }

// Tier is the tier a route must have to run a task of mode m.
func (m Mode) Tier() catalog.Tier {
	if !modeNames.Valid(m) {
		return 0
	}
	return modeTiers[m]
}

// Notify is when a run's result notifies: after every run, or only when the model finds something changed.
type Notify uint8

const (
	Every Notify = iota + 1
	Changes
)

var notifyNames = enum.Names[Notify]{Every: "every", Changes: "changes"}

func (n Notify) String() string { return notifyNames.String(n) }

func (n Notify) MarshalText() ([]byte, error) { return notifyNames.MarshalText(n) }

func (n *Notify) UnmarshalText(text []byte) error { return notifyNames.UnmarshalText(n, text) }

func Notifies() []Notify { return notifyNames.Values() }
