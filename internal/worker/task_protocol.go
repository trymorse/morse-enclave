package worker

import (
	"context"
	"encoding/json"

	"morse/backend/internal/catalog"
	"morse/backend/internal/schedule"
	"morse/backend/internal/seal"
	"morse/backend/internal/taskmode"
	"morse/backend/internal/taskseal"
	"morse/backend/internal/worker/taskrun"
)

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

type TaskAdmission struct {
	admitted
	ID       string
	Route    string
	Mode     taskmode.Mode
	Notify   taskmode.Notify
	Schedule schedule.Spec
	Keys     []seal.KeyID
}

func (TaskAdmission) kind() admissionKind { return admitsTask }

type TaskWorker interface {
	TaskAdopt(ctx context.Context, h Handle, rev int64) (TaskAdopted, error)
	TaskOpen(ctx context.Context, o TaskOpening) (TaskOpened, error)
	TaskNext(ctx context.Context, run Handle) (TaskStepped, error)
	TaskFinish(ctx context.Context, run Handle) (taskrun.Finished, error)
}

type TaskAdopted struct {
	Bundle   []byte         `json:"bundle"`
	Revision int64          `json:"revision"`
	Epoch    taskseal.Epoch `json:"epoch"`
	Reply    []byte         `json:"reply"`
}

type TaskOpening struct {
	Epoch    taskseal.Epoch `json:"epoch"`
	Task     string         `json:"task"`
	Run      string         `json:"run"`
	Bundle   []byte         `json:"bundle"`
	Revision int64          `json:"revision"`
	Meta     taskrun.Meta   `json:"meta"`
}

type TaskStep struct {
	Kind      catalog.Kind
	Admission Admission
}

type TaskOpened struct {
	Run  Handle
	Step TaskStep
}

type TaskStepped struct {
	Step TaskStep
	Done bool
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
