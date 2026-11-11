package worker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/catalog"
	"morse/backend/internal/enum"
	"morse/backend/internal/schedule"
	"morse/backend/internal/seal"
	"morse/backend/internal/taskmode"
	"morse/backend/internal/taskseal"
)

// Scheduled tasks on the worker: the routes a device seals a task's bundle to, the bundle, the admission the relay
// checks before the worker adopts it, the plaintexts a run seals to the task's devices, and the endpoints the relay
// drives a run through. The worker may not link internal/tasks, so the names it shares with it are its own here, and
// internal/tasks pins them to its own.

const (
	TasksPattern      = "POST /v1/tasks"
	TaskBundlePattern = "POST /v1/tasks/{id}/bundle"
)

const (
	taskAdoptPath  = "/task-adopt"
	taskOpenPath   = "/task-open"
	taskNextPath   = "/task-next"
	taskFinishPath = "/task-finish"
)

const (
	TaskBundleVersion  = 1
	MaxTaskBody        = 96 << 10
	MaxTaskKeys        = 4
	MaxTaskNameRunes   = 80
	MaxTaskPromptRunes = 8000
	MaxTaskSystemBytes = 48 << 10
	MaxTaskRouteBytes  = 128
	MaxTaskLastRunes   = 4000
	// MaxTaskBundleAtRest bounds a bundle as the relay stores it, so the worker cuts last.text until it fits.
	MaxTaskBundleAtRest  = 128 << 10
	MaxTaskChatPasses    = 6
	MaxTaskSearches      = 6
	MaxTaskSearchQueries = 3
	MaxTaskReads         = 6
	MaxTaskSources       = 20
	MaxTaskPreviewRunes  = 600
	// TaskRunLife is how long the worker keeps a run's state since the relay last called on the run.
	TaskRunLife = 15 * time.Minute
	// TaskNoChange is what a run with notify "changes" answers on its first line when nothing changed.
	TaskNoChange = "NO_CHANGE"
	TaskObject   = "task"
)

type TaskMode = taskmode.Mode

const (
	TaskAnon    = taskmode.Anon
	TaskPrivate = taskmode.Private
)

func TaskModes() []TaskMode { return taskmode.Modes() }

type TaskNotify = taskmode.Notify

const (
	TaskEvery   = taskmode.Every
	TaskChanges = taskmode.Changes
)

func TaskNotifies() []TaskNotify { return taskmode.Notifies() }

// TaskOutcome is how the worker ended a run. The relay records Skipped and Interrupted itself.
type TaskOutcome uint8

const (
	TaskOK TaskOutcome = iota + 1
	TaskUnchanged
	TaskFailed
)

var taskOutcomeNames = enum.Names[TaskOutcome]{TaskOK: "ok", TaskUnchanged: "unchanged", TaskFailed: "failed"}

func (o TaskOutcome) String() string { return taskOutcomeNames.String(o) }

func (o TaskOutcome) MarshalText() ([]byte, error) { return taskOutcomeNames.MarshalText(o) }

func (o *TaskOutcome) UnmarshalText(text []byte) error {
	return taskOutcomeNames.UnmarshalText(o, text)
}

func TaskOutcomes() []TaskOutcome { return taskOutcomeNames.Values() }

// TaskPublicKey is a device's X25519 delivery key, in unpadded base64url.
type TaskPublicKey [32]byte

var taskKeyEncoding = base64.RawURLEncoding.Strict()

func (k TaskPublicKey) MarshalText() ([]byte, error) {
	return []byte(taskKeyEncoding.EncodeToString(k[:])), nil
}

func (k *TaskPublicKey) UnmarshalText(text []byte) error {
	raw, err := taskKeyEncoding.DecodeString(string(text))
	if err != nil || len(raw) != len(k) {
		return fmt.Errorf("worker: a task key is 32 bytes in unpadded base64url, not %q", text)
	}
	copy(k[:], raw)
	return nil
}

// TaskBundle is the plaintext a device seals to POST /v1/tasks and POST /v1/tasks/{id}/bundle, and the worker keeps
// under the task key. Recalled and Last are the only fields it may leave out; none may be null.
type TaskBundle struct {
	V        int             `json:"v"`
	ID       string          `json:"id"`
	Chat     string          `json:"chat"`
	Name     string          `json:"name"`
	Prompt   string          `json:"prompt"`
	System   string          `json:"system"`
	Recalled string          `json:"recalled,omitempty"`
	Route    string          `json:"route"`
	Mode     TaskMode        `json:"mode"`
	Notify   TaskNotify      `json:"notify"`
	Schedule schedule.Spec   `json:"schedule"`
	Keys     []TaskPublicKey `json:"keys"`
	Last     *TaskLast       `json:"last,omitempty"`
}

// TaskLast is the task's latest ok result, which a run with notify "changes" compares its answer with.
type TaskLast struct {
	Run  string `json:"run"`
	At   int64  `json:"at"`
	Text string `json:"text"`
}

// TaskReply is what the sealed routes answer the device with, which the worker writes and seals under the
// request's key, so it says only what the worker knows.
type TaskReply struct {
	Object string       `json:"object"`
	ID     string       `json:"id"`
	Keys   []seal.KeyID `json:"keys"`
}

// TaskResult is a run's result as the worker seals it to each of the task's keys.
type TaskResult struct {
	Task     string       `json:"task"`
	Run      string       `json:"run"`
	Chat     string       `json:"chat"`
	RanAt    int64        `json:"ran_at"`
	Outcome  TaskOutcome  `json:"outcome"`
	Route    string       `json:"route"`
	Mode     TaskMode     `json:"mode"`
	Prompt   string       `json:"prompt"`
	Content  string       `json:"content"`
	Recalled string       `json:"recalled,omitempty"`
	Sources  []TaskSource `json:"sources,omitempty"`
}

// TaskSource is a page a run's web tools found.
type TaskSource struct {
	URL   string `json:"url"`
	Title string `json:"title"`
}

// TaskPreview is what a push shows of a run's result, sealed to the key of the subscription it goes to.
type TaskPreview struct {
	Task  string `json:"task"`
	Run   string `json:"run"`
	Chat  string `json:"chat"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

// TaskAdmission is a task's bundle as the worker opened it, with the fields the relay checks and keeps: the task's
// id and its devices' key ids, which the worker computes as seal.KeyIDOf of each key.
type TaskAdmission struct {
	admitted
	ID       string
	Route    string
	Mode     TaskMode
	Notify   TaskNotify
	Schedule schedule.Spec
	Keys     []seal.KeyID
}

func (TaskAdmission) kind() admissionKind { return admitsTask }

// TaskMeta is the relay's copy of what it scheduled a task by, which /task-open checks against the bundle.
type TaskMeta struct {
	Route    string        `json:"route"`
	Mode     TaskMode      `json:"mode"`
	Notify   TaskNotify    `json:"notify"`
	Schedule schedule.Spec `json:"schedule"`
}

// TaskWorker is the worker's side of scheduled tasks. The relay ends a run it gives up on with Cut(run, reason).
type TaskWorker interface {
	TaskAdopt(ctx context.Context, h Handle, rev int64) (TaskAdopted, error)
	TaskOpen(ctx context.Context, o TaskOpening) (TaskOpened, error)
	TaskNext(ctx context.Context, run Handle) (TaskStepped, error)
	TaskFinish(ctx context.Context, run Handle) (TaskFinished, error)
}

// TaskAdopted is a bundle the worker sealed under its task key, the key's epoch, and the reply for the device:
// sealed frames under the request's key for a sealed request, the JSON itself for an unsealed one.
type TaskAdopted struct {
	Bundle []byte `json:"bundle"`
	// Revision is the revision Bundle was sealed at, which the relay stores as its bundle_rev.
	Revision int64          `json:"revision"`
	Epoch    taskseal.Epoch `json:"epoch"`
	Reply    []byte         `json:"reply"`
}

type TaskOpening struct {
	Epoch  taskseal.Epoch `json:"epoch"`
	Task   string         `json:"task"`
	Run    string         `json:"run"`
	Bundle []byte         `json:"bundle"`
	// Revision is the task's bundle_rev, which Bundle opens only at.
	Revision int64    `json:"revision"`
	Meta     TaskMeta `json:"meta"`
}

// TaskStep is one upstream call of a run, admitted as a client's request would be: a ChatAdmission for a chat pass,
// a CallAdmission for a search or a page read. The relay charges and runs it through /run like any other handle.
type TaskStep struct {
	Kind      catalog.Kind
	Admission Admission
}

type TaskOpened struct {
	Run  Handle
	Step TaskStep
}

// TaskStepped is the run's next step, or Done when the run has its answer or can go no further.
type TaskStepped struct {
	Step TaskStep
	Done bool
}

type TaskFinished struct {
	Outcome  TaskOutcome  `json:"outcome"`
	Refusal  string       `json:"refusal,omitempty"`
	Bundle   []byte       `json:"bundle,omitempty"`
	Revision int64        `json:"revision,omitempty"`
	Results  []TaskSealed `json:"results"`
	Previews []TaskSealed `json:"previews"`
	Steps    int          `json:"steps"`
}

// TaskSealed is a result or a preview sealed to the device key Key names.
type TaskSealed struct {
	Key    seal.KeyID `json:"key"`
	Sealed []byte     `json:"sealed"`
}

type taskStepWire struct {
	Kind      catalog.Kind    `json:"kind"`
	Admission json.RawMessage `json:"admission"`
}

type taskOpenedWire struct {
	Run Handle `json:"run"`
	taskStepWire
}

type taskSteppedWire struct {
	Kind      *catalog.Kind   `json:"kind,omitempty"`
	Admission json.RawMessage `json:"admission,omitempty"`
	Done      bool            `json:"done,omitempty"`
}

type taskRunRequest struct {
	Run Handle `json:"run"`
}

var (
	ErrInvalidTask         = apierr.Invalid(http.StatusBadRequest, "invalid_task", "The request does not have the shape this task route takes. A bundle is one strict JSON object with the fields and limits the task contract gives, ids are lowercase UUIDs, key ids are 16 lowercase hex digits, and limit is a whole number from 1 to 100.")
	ErrTaskTooLarge        = apierr.Invalid(http.StatusRequestEntityTooLarge, "task_too_large", "A task's bundle is at most 98304 bytes. Send a shorter prompt, or a smaller memory snapshot in system.")
	ErrTaskKeysInvalid     = apierr.Invalid(http.StatusBadRequest, "task_keys_invalid", "keys must hold 1 to 4 distinct X25519 public keys, each 32 bytes in unpadded base64url, none of them a low-order point.")
	ErrTaskScheduleInvalid = apierr.Invalid(http.StatusBadRequest, "task_schedule_invalid", "The schedule is not one Morse runs: cron is 5 fields with a single minute, day of month and day of week not both set, and a preset's cron has its preset's shape; once carries once_local and no cron.")

	ErrTaskEpochUnknown  = apierr.Invalid(http.StatusMisdirectedRequest, "task_epoch_unknown", "This worker holds no task key of that epoch. A device must seal the task again.")
	ErrTaskBundleInvalid = apierr.Invalid(http.StatusBadRequest, "task_bundle_invalid", "The task's bundle does not open under this worker's task key, or what it holds is not a bundle.")
	ErrTaskMetaMismatch  = apierr.Invalid(http.StatusBadRequest, "task_meta_mismatch", "The relay's route, mode, notify, or schedule for this task is not the bundle's.")
)

// TaskEpochUnknown is ErrTaskEpochUnknown with Holds, the epoch the worker's task key has now, which its 421 names
// as "epoch".
type TaskEpochUnknown struct{ Holds taskseal.Epoch }

func (TaskEpochUnknown) Error() string { return ErrTaskEpochUnknown.Error() }

func (TaskEpochUnknown) Unwrap() error { return ErrTaskEpochUnknown }
