package door

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"morse/backend/internal/nitro/verify"
	"morse/backend/internal/taskseal"
)

const (
	taskPayloadType = "morse-task-keys-v1"
	taskKeysPath    = "/task-keys"
	taskSecretSize  = 32
)

// MaxTaskKeyAge bounds how long a task key may pass between enclaves. Past it the key is handed to no one and taken
// from no one, so the first restart after it makes a new key and devices seal the tasks again.
const MaxTaskKeyAge = 30 * 24 * time.Hour

// TaskKeys is the worker's task key as the door hands it: a taskseal.Holder.
type TaskKeys interface {
	Standing() taskseal.Standing
	Held() ([taskSecretSize]byte, time.Time, bool)
	Take(secret [taskSecretSize]byte, born time.Time) error
	Settle(why taskseal.SettleReason)
}

// TaskKeysAnswer is GET /door's task_keys: pending while the worker waits to take a key, then settled with its epoch, whether
// it took the key from a peer or made do with its own, and why it did.
type TaskKeysAnswer struct {
	Object string                `json:"object"`
	State  string                `json:"state"`
	Epoch  *taskseal.Epoch       `json:"epoch,omitempty"`
	Source string                `json:"source,omitempty"`
	Why    taskseal.SettleReason `json:"why,omitempty"`
}

const (
	TaskKeysPending = "pending"
	TaskKeysSettled = "settled"
	TaskKeysTaken   = "taken"
	TaskKeysOwn     = "own"
)

type TaskKeysSettle struct {
	Why taskseal.SettleReason `json:"why"`
}

type taskPayload struct {
	Type   string    `json:"type"`
	Secret []byte    `json:"secret"`
	Born   time.Time `json:"born"`
	Floor  uint64    `json:"floor"`
}

var TaskKey = HandedKey{Label: "task keys", PeerPath: taskKeysPath + "/handoff", HandoffPath: taskKeysPath + "/handoff", Path: taskKeysPath, payload: taskPayloadType}

// ServeTaskKeys has Register serve the task key's routes for keys. Call it before Register.
func (d *Door) ServeTaskKeys(keys TaskKeys) { d.tasks = keys }

func (d *Door) taskKeysAnswer() TaskKeysAnswer {
	s := d.tasks.Standing()
	if !s.Settled {
		return TaskKeysAnswer{Object: "task_keys", State: TaskKeysPending}
	}
	if s.Taken {
		return TaskKeysAnswer{Object: "task_keys", State: TaskKeysSettled, Epoch: &s.Epoch, Source: TaskKeysTaken}
	}
	return TaskKeysAnswer{Object: "task_keys", State: TaskKeysSettled, Epoch: &s.Epoch, Source: TaskKeysOwn, Why: s.Why}
}

func (d *Door) handTaskKeys(ctx context.Context, req Handoff) (Handed, *Refusal) {
	in, refused := d.admit(ctx, req.Pins)
	if refused != nil {
		return Handed{}, refused
	}
	secret, born, settled := d.tasks.Held()
	if !settled {
		return Handed{}, refuse(http.StatusConflict, "task_keys_pending", "this enclave has not settled on a task key to hand off")
	}
	return d.handOver(ctx, TaskKey, in, req, func() ([]byte, *Refusal) {
		if age := in.now.Sub(born); age > MaxTaskKeyAge {
			return nil, refuse(http.StatusUnprocessableEntity, "key_too_old", "the task key was born %s ago, past %s", age.Round(time.Hour), MaxTaskKeyAge)
		}
		body, err := json.Marshal(taskPayload{Type: taskPayloadType, Secret: secret[:], Born: born.UTC(), Floor: in.custody.floor})
		if err != nil {
			return nil, refuse(http.StatusInternalServerError, "unsealed", "%v", err)
		}
		return body, nil
	})
}

func (d *Door) takeTaskKeys(ctx context.Context, req Handed) *Refusal {
	got, refused := d.receive(ctx, TaskKey, req)
	if refused != nil {
		return refused
	}
	in := got.in
	p, refused := readTaskPayload(got.body)
	if refused != nil {
		return refused
	}
	if age := in.now.Sub(p.Born); age > MaxTaskKeyAge || age < -verify.MaxAhead {
		return refuse(http.StatusUnprocessableEntity, "key_too_old", "the task key was born %s before this enclave's time, outside 0 to %s", age.Round(time.Hour), MaxTaskKeyAge)
	}
	if in.statement.Sequence < p.Floor {
		return refuse(http.StatusUnprocessableEntity, "pins_below_sender", "the statement's sequence %d is below the sender's floor %d", in.statement.Sequence, p.Floor)
	}
	if err := d.tasks.Take([taskSecretSize]byte(p.Secret), p.Born.UTC()); err != nil {
		if errors.Is(err, taskseal.ErrSettled) {
			return refuse(http.StatusConflict, "task_keys_settled", "this enclave already settled on a task key")
		}
		return refuse(http.StatusInternalServerError, "untaken", "%v", err)
	}
	return nil
}

func readTaskPayload(body []byte) (taskPayload, *Refusal) {
	var p taskPayload
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil || p.Type != taskPayloadType || len(p.Secret) != taskSecretSize || p.Born.IsZero() {
		return taskPayload{}, refuse(http.StatusUnprocessableEntity, "payload_unreadable", "the blob holds no %s payload", taskPayloadType)
	}
	return p, nil
}

func (d *Door) registerTaskKeys(mux *http.ServeMux) {
	mux.HandleFunc("POST "+taskKeysPath+"/settle", func(w http.ResponseWriter, r *http.Request) {
		var req TaskKeysSettle
		if refused := readJSON(w, r, &req); refused != nil {
			writeJSON(w, refused.status, refused)
			return
		}
		if !req.Why.Valid() {
			refused := refuse(http.StatusBadRequest, "body_unreadable", "why is %q; want no_peer, key_expired, or no_handoff", req.Why)
			writeJSON(w, refused.status, refused)
			return
		}
		d.tasks.Settle(req.Why)
		writeJSON(w, http.StatusOK, d.taskKeysAnswer())
	})
	mux.HandleFunc("POST "+taskKeysPath+"/handoff", func(w http.ResponseWriter, r *http.Request) {
		var req Handoff
		if refused := readJSON(w, r, &req); refused != nil {
			writeJSON(w, refused.status, refused)
			return
		}
		handed, refused := d.handTaskKeys(r.Context(), req)
		if refused != nil {
			writeJSON(w, refused.status, refused)
			return
		}
		writeJSON(w, http.StatusOK, handed)
	})
	mux.HandleFunc("PUT "+taskKeysPath, func(w http.ResponseWriter, r *http.Request) {
		var req Handed
		if refused := readJSON(w, r, &req); refused != nil {
			writeJSON(w, refused.status, refused)
			return
		}
		if refused := d.takeTaskKeys(r.Context(), req); refused != nil {
			writeJSON(w, refused.status, refused)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
