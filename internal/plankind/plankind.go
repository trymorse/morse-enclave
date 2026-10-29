package plankind

import (
	"strings"

	"morse/backend/internal/enum"
)

type Kind uint8

const (
	Free Kind = iota
	Pro
	Max
)

var names = enum.Names[Kind]{Free: "free", Pro: "pro", Max: "max"}

func Parse(name string) (Kind, bool) { return names.Parse(name) }

func All() []Kind { return names.Values() }

func (k Kind) Valid() bool { return names.Valid(k) }

func (k Kind) Title() string {
	name := k.String()
	return strings.ToUpper(name[:1]) + name[1:]
}

func (k Kind) String() string { return names.String(k) }

func (k Kind) MarshalText() ([]byte, error) { return names.MarshalText(k) }

func (k *Kind) UnmarshalText(text []byte) error { return names.UnmarshalText(k, text) }

func (k Kind) AtLeast(floor Kind) bool { return k >= floor }

func (k Kind) Paid() bool { return k != Free }

func List() string { return names.List() }
