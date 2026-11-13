package worker

import (
	"bytes"
	"context"
	"net/http"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/taskmode"
	"morse/backend/internal/taskseal"
	"morse/backend/internal/worker/taskrun"
)

var _ Worker = (*InProcess)(nil)

type taskRun = taskrun.Run[Admission]

func (w *InProcess) TaskAdopt(_ context.Context, h Handle, rev int64) (TaskAdopted, error) {
	t, cek := w.takeTask(h)
	if t == nil {
		return TaskAdopted{}, apierr.ErrUnavailable
	}
	key := w.sealing.tasks
	if key == nil {
		return TaskAdopted{}, errSealedUnavailable
	}
	rev, ok := w.sealing.floors.Reserve(t.task, rev)
	if !ok {
		return TaskAdopted{}, apierr.ErrInvalidBody
	}
	bundle, err := taskseal.SealBundle(key, t.task, uint64(rev), t.bundle)
	if err != nil {
		return TaskAdopted{}, apierr.ErrUnavailable
	}
	reply := t.reply
	if cek != nil {
		reply = sealedReplyOf(*cek, t.status, reply)
	}
	return TaskAdopted{Bundle: bundle, Revision: rev, Epoch: key.Epoch(), Reply: reply}, nil
}

func (w *InProcess) takeTask(h Handle) (*openedTask, *[32]byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.opened[h]
	if e == nil || e.phase != waiting {
		return nil, nil
	}
	t, ok := e.opened.(*openedTask)
	if !ok {
		return nil, nil
	}
	e.expire.Stop()
	delete(w.opened, h)
	return t, e.cek
}

type openedTask struct {
	task   taskrun.ID
	bundle []byte
	reply  []byte
	status int
}

func (*openedTask) cut(measure.Cut) {}

func (w *InProcess) openTask(o Opening, route taskrun.BundleRoute) (Admission, error) {
	b, err := taskrun.Read(o.Body, route)
	if err != nil {
		return nil, err
	}
	data, err := taskrun.AtRest(b)
	if err != nil {
		return nil, err
	}
	task, _ := taskrun.ParseID(b.ID)
	keys := taskrun.KeyIDs(b.Keys)
	t := &openedTask{task: task, bundle: data, reply: jsonx.Encode(taskrun.Reply{Object: taskrun.Object, ID: b.ID, Keys: keys}), status: route.Status()}
	return TaskAdmission{admitted: admitted{w.keep(o, t)}, ID: b.ID, Route: b.Route, Mode: b.Mode, Notify: b.Notify, Schedule: b.Schedule, Keys: keys}, nil
}

func (w *InProcess) TaskOpen(_ context.Context, o TaskOpening) (TaskOpened, error) {
	key := w.sealing.tasks
	if key == nil {
		return TaskOpened{}, errSealedUnavailable
	}
	if o.Epoch != key.Epoch() {
		return TaskOpened{}, taskrun.EpochUnknown{Holds: key.Epoch()}
	}
	if o.Revision < 0 {
		return TaskOpened{}, apierr.ErrInvalidBody
	}
	b, task, err := taskrun.OpenBundle(key, o.Task, o.Revision, o.Bundle)
	if err != nil {
		return TaskOpened{}, err
	}
	if o.Meta != taskrun.MetaOf(b) || !w.sealing.floors.Admit(task, o.Revision) {
		return TaskOpened{}, taskrun.ErrMetaMismatch
	}
	run, ok := taskrun.ParseID(o.Run)
	if !ok {
		return TaskOpened{}, apierr.ErrInvalidBody
	}
	if tier, served := w.tiers[b.Route]; !served || tier != b.Mode.Tier() || len(w.chats[b.Route].named) == 0 {
		return TaskOpened{}, apierr.ErrModelNotFound
	}
	r := taskrun.New(taskrun.Spec{
		Bundle: b, Task: task, Run: run, Revision: o.Revision, Tools: w.taskTools(b.Mode),
		Key: key, Floors: &w.sealing.floors, Now: w.now, Life: w.taskLife,
	}, taskSteps{w})
	w.mu.Lock()
	w.last++
	h := Handle{w.last}
	w.mu.Unlock()
	first, err := r.Start()
	if err != nil {
		return TaskOpened{}, err
	}
	w.mu.Lock()
	w.runs[h] = r
	w.mu.Unlock()
	r.Arm(func() { w.endRun(h, measure.CutByDeadline) })
	return TaskOpened{Run: h, Step: taskStepOf(first)}, nil
}

func (w *InProcess) taskTools(mode taskmode.Mode) taskrun.Tools {
	var tools taskrun.Tools
	routes, offered := taskrun.ToolRoutes(mode)
	if !offered {
		return tools
	}
	if _, ok := w.searches[routes.Search]; ok && w.tiers[routes.Search] >= mode.Tier() {
		tools.Search = routes.Search
	}
	if _, ok := w.fetches[routes.Fetch]; ok && w.tiers[routes.Fetch] >= mode.Tier() {
		tools.Fetch = routes.Fetch
	}
	return tools
}

func taskStepOf(s taskrun.Stepped[Admission]) TaskStep {
	return TaskStep{Kind: s.Kind, Admission: s.Admission}
}

func (w *InProcess) TaskNext(_ context.Context, h Handle) (TaskStepped, error) {
	r := w.runOf(h)
	if r == nil {
		return TaskStepped{}, apierr.ErrUnavailable
	}
	s, err := r.Next()
	if err != nil || s.Done {
		return TaskStepped{Done: s.Done}, err
	}
	return TaskStepped{Step: taskStepOf(s)}, nil
}

func (w *InProcess) TaskFinish(_ context.Context, h Handle) (taskrun.Finished, error) {
	r := w.takeRun(h)
	if r == nil {
		return taskrun.Finished{}, apierr.ErrUnavailable
	}
	return r.Finish()
}

func (w *InProcess) runOf(h Handle) *taskRun {
	w.mu.Lock()
	r := w.runs[h]
	w.mu.Unlock()
	if r == nil {
		return nil
	}
	if r.Expired() {
		w.endRun(h, measure.CutByDeadline)
		return nil
	}
	return r
}

func (w *InProcess) takeRun(h Handle) *taskRun {
	r := w.runOf(h)
	if r == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.runs[h] != r {
		return nil
	}
	delete(w.runs, h)
	return r
}

func (w *InProcess) endRun(h Handle, reason measure.Cut) bool {
	w.mu.Lock()
	r := w.runs[h]
	delete(w.runs, h)
	w.mu.Unlock()
	if r == nil {
		return false
	}
	r.End(reason)
	return true
}

type taskSteps struct{ w *InProcess }

func (t taskSteps) Open(s *taskrun.Step) (Admission, error) {
	header := http.Header{"Content-Type": {"application/json"}}
	o := Opening{Method: http.MethodPost, Header: header, Body: bytes.NewReader(s.Body())}
	var a Admission
	var err error
	switch s.Kind() {
	case catalog.KindChat:
		a, err = t.w.openChat(o, false)
	case catalog.KindSearch:
		a, err = t.w.openSearch(o)
	default:
		a, err = t.w.openFetch(o)
	}
	if err != nil {
		return nil, err
	}
	if !t.w.wrapStep(a, s) {
		t.w.Cut(a.Handle(), measure.CutByProxy)
		return nil, apierr.ErrUnavailable
	}
	return a, nil
}

func (t taskSteps) Cut(a Admission, reason measure.Cut) { t.w.Cut(a.Handle(), reason) }

type stepper interface {
	opened
	runs
}

type taskStep struct {
	step  *taskrun.Step
	inner stepper
}

func (w *InProcess) wrapStep(a Admission, s *taskrun.Step) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	e := w.opened[a.Handle()]
	if e == nil || e.phase != waiting {
		return false
	}
	inner, ok := e.opened.(stepper)
	if !ok {
		return false
	}
	e.opened = &taskStep{step: s, inner: inner}
	return true
}

func (s *taskStep) cut(reason measure.Cut) { s.inner.cut(reason) }

func (s *taskStep) run(ctx context.Context, w *InProcess, h Handle, g Grant, reply http.ResponseWriter) Measured {
	if !s.step.Start() {
		return unrunnable(reply)
	}
	c := taskrun.NewCapture(s.step.Kind() == catalog.KindChat)
	m := s.inner.run(ctx, w, h, g, c)
	s.step.Ran(c.Got(m.Served))
	c.Answer(reply)
	return m
}
