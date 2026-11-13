package taskrun

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/enum"
	"morse/backend/internal/schedule"
	"morse/backend/internal/seal"
	"morse/backend/internal/taskmode"
	"morse/backend/internal/taskseal"
)

const (
	BundleVersion   = 1
	MaxBody         = 96 << 10
	MaxKeys         = 4
	MaxNameRunes    = 80
	MaxPromptRunes  = 8000
	MaxSystemBytes  = 48 << 10
	MaxRouteBytes   = 128
	MaxLastRunes    = 4000
	MaxBundleAtRest = 128 << 10
	MaxChatPasses   = 6
	MaxSearches     = 6
	MaxReads        = 6
	MaxSources      = 20
	MaxPreviewRunes = 600
	RunLife         = 15 * time.Minute
	NoChange        = "NO_CHANGE"
	Object          = "task"
)

type Outcome uint8

const (
	OK Outcome = iota + 1
	Unchanged
	Failed
)

var outcomeNames = enum.Names[Outcome]{OK: "ok", Unchanged: "unchanged", Failed: "failed"}

func (o Outcome) String() string { return outcomeNames.String(o) }

func (o Outcome) MarshalText() ([]byte, error) { return outcomeNames.MarshalText(o) }

func (o *Outcome) UnmarshalText(text []byte) error { return outcomeNames.UnmarshalText(o, text) }

func Outcomes() []Outcome { return outcomeNames.Values() }

type PublicKey [32]byte

var keyEncoding = base64.RawURLEncoding.Strict()

func (k PublicKey) MarshalText() ([]byte, error) {
	return []byte(keyEncoding.EncodeToString(k[:])), nil
}

func (k *PublicKey) UnmarshalText(text []byte) error {
	raw, err := keyEncoding.DecodeString(string(text))
	if err != nil || len(raw) != len(k) {
		return fmt.Errorf("worker: a task key is 32 bytes in unpadded base64url, not %q", text)
	}
	copy(k[:], raw)
	return nil
}

type Bundle struct {
	V        int             `json:"v"`
	ID       string          `json:"id"`
	Chat     string          `json:"chat"`
	Name     string          `json:"name"`
	Prompt   string          `json:"prompt"`
	System   string          `json:"system"`
	Recalled string          `json:"recalled,omitempty"`
	Route    string          `json:"route"`
	Mode     taskmode.Mode   `json:"mode"`
	Notify   taskmode.Notify `json:"notify"`
	Schedule schedule.Spec   `json:"schedule"`
	Keys     []PublicKey     `json:"keys"`
	Last     *Last           `json:"last,omitempty"`
}

type Last struct {
	Run  string `json:"run"`
	At   int64  `json:"at"`
	Text string `json:"text"`
}

type Reply struct {
	Object string       `json:"object"`
	ID     string       `json:"id"`
	Keys   []seal.KeyID `json:"keys"`
}

type Result struct {
	Task     string        `json:"task"`
	Run      string        `json:"run"`
	Chat     string        `json:"chat"`
	RanAt    int64         `json:"ran_at"`
	Outcome  Outcome       `json:"outcome"`
	Route    string        `json:"route"`
	Mode     taskmode.Mode `json:"mode"`
	Prompt   string        `json:"prompt"`
	Content  string        `json:"content"`
	Recalled string        `json:"recalled,omitempty"`
	Sources  []Source      `json:"sources,omitempty"`
}

type Source struct {
	URL   string `json:"url"`
	Title string `json:"title"`
}

type Preview struct {
	Task  string `json:"task"`
	Run   string `json:"run"`
	Chat  string `json:"chat"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

type Meta struct {
	Route    string          `json:"route"`
	Mode     taskmode.Mode   `json:"mode"`
	Notify   taskmode.Notify `json:"notify"`
	Schedule schedule.Spec   `json:"schedule"`
}

func MetaOf(b Bundle) Meta {
	return Meta{Route: b.Route, Mode: b.Mode, Notify: b.Notify, Schedule: b.Schedule}
}

type Finished struct {
	Outcome  Outcome  `json:"outcome"`
	Refusal  string   `json:"refusal,omitempty"`
	Bundle   []byte   `json:"bundle,omitempty"`
	Revision int64    `json:"revision,omitempty"`
	Results  []Sealed `json:"results"`
	Previews []Sealed `json:"previews"`
	Steps    int      `json:"steps"`
}

type Sealed struct {
	Key    seal.KeyID `json:"key"`
	Sealed []byte     `json:"sealed"`
}

var (
	ErrInvalid         = apierr.Invalid(http.StatusBadRequest, "invalid_task", "The request does not have the shape this task route takes. A bundle is one strict JSON object with the fields and limits the task contract gives, ids are lowercase UUIDs, key ids are 16 lowercase hex digits, and limit is a whole number from 1 to 100.")
	ErrTooLarge        = apierr.Invalid(http.StatusRequestEntityTooLarge, "task_too_large", "A task's bundle is at most 98304 bytes. Send a shorter prompt, or a smaller memory snapshot in system.")
	ErrKeysInvalid     = apierr.Invalid(http.StatusBadRequest, "task_keys_invalid", "keys must hold 1 to 4 distinct X25519 public keys, each 32 bytes in unpadded base64url, none of them a low-order point.")
	ErrScheduleInvalid = apierr.Invalid(http.StatusBadRequest, "task_schedule_invalid", "The schedule is not one Morse runs: cron is 5 fields with a single minute, day of month and day of week not both set, and a preset's cron has its preset's shape; once carries once_local and no cron.")

	ErrEpochUnknown  = apierr.Invalid(http.StatusMisdirectedRequest, "task_epoch_unknown", "This worker holds no task key of that epoch. A device must seal the task again.")
	ErrBundleInvalid = apierr.Invalid(http.StatusBadRequest, "task_bundle_invalid", "The task's bundle does not open under this worker's task key, or what it holds is not a bundle.")
	ErrMetaMismatch  = apierr.Invalid(http.StatusBadRequest, "task_meta_mismatch", "The relay's route, mode, notify, or schedule for this task is not the bundle's.")
)

type EpochUnknown struct{ Holds taskseal.Epoch }

func (EpochUnknown) Error() string { return ErrEpochUnknown.Error() }

func (EpochUnknown) Unwrap() error { return ErrEpochUnknown }
