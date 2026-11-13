// Package schedule reads a scheduled task's schedule and finds when it runs. The spec, its kinds, and the codes a
// refused spec carries are the contract the worker, the relay, and the web app's src/lib/schedule share.
package schedule

import (
	"time"

	"morse/backend/internal/enum"
)

// Kind is how the app built a schedule: a preset that compiles to cron, a cron of the user's own, or one run.
type Kind uint8

const (
	Once Kind = iota + 1
	Hourly
	Daily
	Weekdays
	Weekly
	Custom
)

var kindNames = enum.Names[Kind]{Once: "once", Hourly: "hourly", Daily: "daily", Weekdays: "weekdays", Weekly: "weekly", Custom: "custom"}

func (k Kind) String() string { return kindNames.String(k) }

func (k Kind) MarshalText() ([]byte, error) { return kindNames.MarshalText(k) }

func (k *Kind) UnmarshalText(text []byte) error { return kindNames.UnmarshalText(k, text) }

func Kinds() []Kind { return kindNames.Values() }

// Spec is a schedule as the bundle, the worker protocol, and the task routes carry it: Cron for every kind but Once,
// OnceLocal for Once alone, each exactly as the app sent it.
type Spec struct {
	Kind      Kind   `json:"kind"`
	Cron      string `json:"cron,omitempty"`
	OnceLocal string `json:"once_local,omitempty"`
	TZ        string `json:"tz"`
}

const (
	MaxCron = 100
	MaxTZ   = 64
	// OnceLayout is OnceLocal's form: a wall-clock date and time to the minute, in TZ.
	OnceLayout = "2006-01-02T15:04"
	// OnceLead is how far past now a one-time run must be when it is set.
	OnceLead = time.Minute
)

// Code is why a spec is refused, the first of these that applies in this order.
type Code string

const (
	CodeKind       Code = "kind"
	CodeFields     Code = "fields"
	CodeTZ         Code = "tz"
	CodeOnceFormat Code = "once_format"
	CodeOncePast   Code = "once_past"
	CodeCronSyntax Code = "cron_syntax"
	CodeCronRange  Code = "cron_range"
	CodeCronMinute Code = "cron_minute"
	CodeCronDays   Code = "cron_days"
	CodeCronShape  Code = "cron_shape"
	CodeCronNever  Code = "cron_never"
)

func Codes() []Code {
	return []Code{CodeKind, CodeFields, CodeTZ, CodeOnceFormat, CodeOncePast, CodeCronSyntax, CodeCronRange, CodeCronMinute, CodeCronDays, CodeCronShape, CodeCronNever}
}
