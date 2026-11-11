package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/taskseal"
	"morse/backend/internal/uuid"
)

// Scheduled tasks on the worker (contracts.md sections B to D). A device seals a task's bundle to a bundle route;
// openTask opens and checks it, and TaskAdopt seals it under the task key. At
// the task's time the relay opens a run with TaskOpen, which opens the bundle and admits the first chat pass, then
// runs each step through /run as it would a client's request, asking TaskNext for the step after it, until the run
// has its answer; TaskFinish seals the answer to each of the task's devices.

var _ Worker = (*InProcess)(nil)

// maxPassAttempts is how many times a chat pass is tried when it fails, beyond the retry without tools a vendor's 400
// to a pass with tools gets.
const maxPassAttempts = 2

// TaskAdopt seals the admitted bundle at the revision after both the one the relay names, its stored bundle_rev or 0
// for a new task, and the highest the worker has seen of the task.
func (w *InProcess) TaskAdopt(_ context.Context, h Handle, rev int64) (TaskAdopted, error) {
	t, cek := w.takeTask(h)
	if t == nil {
		return TaskAdopted{}, apierr.ErrUnavailable
	}
	key := w.sealing.tasks
	if key == nil {
		return TaskAdopted{}, errSealedUnavailable
	}
	rev, ok := w.sealing.floors.reserve(t.task, rev, false)
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

// bundleFloors is, of each task, the highest bundle revision the worker has opened or adopted, which /task-open
// refuses a bundle below, and the highest it has reserved to seal, which no later seal reuses. So once a device's
// bundle drops a key, the bundle from before it no longer runs here. A bundle /task-open opens raises the floor only
// once it authenticated. /task-adopt raises it before the relay stores the bundle: when that save fails, the relay
// answers task_save_failed, retryable, and the device's retry of the same bundle adopts at a fresh revision that the
// save then stores; only a retry that fails too leaves the stored bundle below the floor, and the task waits for a
// device to seal it again. A run's finish keeps the run's keys, so it reserves its revision without raising the
// floor, and a finish the relay never stores leaves the bundle it holds runnable; the next open of the finish's
// bundle raises the floor. It is memory only: an enclave has no storage the host cannot roll back, and a key handoff
// doesn't carry it, as two live enclaves diverge anyway. A restart clears it and each enclave keeps its own, so it
// refuses a replay only to an enclave that has already seen a newer revision of that task: it stops a buggy relay and
// any replay to the enclave that sealed the newer bundle, but not a relay that routes the replay to a restarted or
// another enclave.
type bundleFloors struct {
	mu sync.Mutex
	of map[[16]byte]bundleRevs
}

type bundleRevs struct{ floor, issued int64 }

// reserve is the revision a new bundle of task is sealed at, one past rev, the floor and every revision reserved
// before, so no two seals of a task share a revision. An adopt makes it the floor. A finish, of a run that opened at
// rev, reserves none unless the floor is still rev: that run seals no bundle once a newer one was adopted or opened.
// It reserves none for a negative rev or past the largest revision.
func (f *bundleFloors) reserve(task [16]byte, rev int64, finish bool) (int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.of[task]
	if rev < 0 || finish && r.floor != rev {
		return 0, false
	}
	top := max(rev, r.floor, r.issued)
	if top == math.MaxInt64 {
		return 0, false
	}
	if f.of == nil {
		f.of = map[[16]byte]bundleRevs{}
	}
	r.issued = top + 1
	if !finish {
		r.floor = r.issued
	}
	f.of[task] = r
	return r.issued, true
}

// admit raises the floor of task to rev, unless rev is below it.
func (f *bundleFloors) admit(task [16]byte, rev int64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.of[task]
	if rev < r.floor {
		return false
	}
	if f.of == nil {
		f.of = map[[16]byte]bundleRevs{}
	}
	r.floor = rev
	f.of[task] = r
	return true
}

// takeTask spends a task admission's handle, adopted or not, and answers what it opened and the request's content
// key, which a request opened sealed has.
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

func (w *InProcess) TaskOpen(_ context.Context, o TaskOpening) (TaskOpened, error) {
	key := w.sealing.tasks
	if key == nil {
		return TaskOpened{}, errSealedUnavailable
	}
	if o.Epoch != key.Epoch() {
		return TaskOpened{}, TaskEpochUnknown{Holds: key.Epoch()}
	}
	if o.Revision < 0 {
		return TaskOpened{}, apierr.ErrInvalidBody
	}
	b, task, err := openRunBundle(key, o)
	if err != nil {
		return TaskOpened{}, err
	}
	if o.Meta != metaOf(b) || !w.sealing.floors.admit(task, o.Revision) {
		return TaskOpened{}, ErrTaskMetaMismatch
	}
	run, ok := taskIDOf(o.Run)
	if !ok {
		return TaskOpened{}, apierr.ErrInvalidBody
	}
	if tier, served := w.tiers[b.Route]; !served || tier != b.Mode.Tier() || len(w.chats[b.Route].named) == 0 {
		return TaskOpened{}, apierr.ErrModelNotFound
	}
	r := w.newRun(b, task, run, o.Run)
	r.rev = o.Revision
	w.mu.Lock()
	w.last++
	r.handle = Handle{w.last}
	w.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.passStep()
	a, err := r.open(s)
	if err != nil {
		return TaskOpened{}, err
	}
	w.mu.Lock()
	w.runs[r.handle] = r
	w.mu.Unlock()
	r.expires = w.now().Add(w.taskLife)
	r.timer = time.AfterFunc(w.taskLife, func() { w.checkRun(r) })
	return TaskOpened{Run: r.handle, Step: TaskStep{Kind: s.kind, Admission: a}}, nil
}

// openRunBundle opens a run's bundle under the task key for the task the relay names, and reads it as only a worker
// holding that key wrote it: a bundle of that id, in a mode the worker runs, which decoding holds to the three it
// names.
func openRunBundle(key *taskseal.Key, o TaskOpening) (TaskBundle, [16]byte, error) {
	task, ok := taskIDOf(o.Task)
	if !ok {
		return TaskBundle{}, task, ErrTaskBundleInvalid
	}
	plain, err := taskseal.OpenBundle(key, task, uint64(o.Revision), o.Bundle)
	if err != nil {
		return TaskBundle{}, task, ErrTaskBundleInvalid
	}
	b, ok := decodeBundle(plain)
	if !ok || checkBundle(b, bundleRoute{}) != nil || b.ID != o.Task {
		return TaskBundle{}, task, ErrTaskBundleInvalid
	}
	return b, task, nil
}

func metaOf(b TaskBundle) TaskMeta {
	return TaskMeta{Route: b.Route, Mode: b.Mode, Notify: b.Notify, Schedule: b.Schedule}
}

func taskIDOf(s string) ([16]byte, bool) {
	if !isTaskID(s) {
		return [16]byte{}, false
	}
	return uuid.Parse(s)
}

func (w *InProcess) TaskNext(_ context.Context, h Handle) (TaskStepped, error) {
	r := w.runOf(h)
	if r == nil {
		return TaskStepped{}, apierr.ErrUnavailable
	}
	return r.next()
}

func (w *InProcess) TaskFinish(_ context.Context, h Handle) (TaskFinished, error) {
	r := w.takeRun(h)
	if r == nil {
		return TaskFinished{}, apierr.ErrUnavailable
	}
	f, live, err := r.finish()
	if live != nil {
		w.Cut(live.handle, measure.CutByProxy)
	}
	return f, err
}

// A taskRun is a run's state, kept from TaskOpen until TaskFinish, a cut of its handle, or TaskRunLife with no call
// on it, whichever comes first.
type taskRun struct {
	w      *InProcess
	handle Handle
	bundle TaskBundle
	// rev is the revision the run's bundle opened at.
	rev    int64
	task   [16]byte
	run    [16]byte
	runID  string
	system string
	// search and fetch are the routes web_search and read_page go through, "" for a tool the run doesn't offer.
	search, fetch string

	mu      sync.Mutex
	timer   *time.Timer
	expires time.Time
	ended   bool
	// turns are the run's turns after the prompt, and pending the calls of the last pass still to answer.
	turns   []taskTurn
	pending []*taskCall
	ids     map[string]bool
	// passes counts the chat passes served, attempts the failures of the pass in hand.
	passes, attempts int
	// textOnly is set once a vendor refused a pass with tools: no pass of the run sends them after.
	textOnly        bool
	searches, reads int
	// seen holds the pages read_page may open, by pageKey.
	seen    map[string]bool
	sources taskSources
	// step is the step issued last, steps how many steps ran.
	step  *taskStep
	steps int
	done  bool
	// answer is the run's answer, once a pass gave one; refusal the code that ended a run without one.
	answer   string
	answered bool
	refusal  string
}

func (w *InProcess) newRun(b TaskBundle, task, run [16]byte, runID string) *taskRun {
	r := &taskRun{w: w, bundle: b, task: task, run: run, runID: runID, seen: map[string]bool{}, ids: map[string]bool{}}
	if routes, tools := taskToolRoutes[b.Mode]; tools {
		if _, ok := w.searches[routes.search]; ok && w.tiers[routes.search] >= b.Mode.Tier() {
			r.search = routes.search
		}
		if _, ok := w.fetches[routes.fetch]; ok && w.tiers[routes.fetch] >= b.Mode.Tier() {
			r.fetch = routes.fetch
		}
	}
	r.system = taskSystem(b, w.now(), r.search != "" || r.fetch != "")
	for _, key := range urlsIn(b.Prompt) {
		r.seen[key] = true
	}
	return r
}

// runOf is the run h names, unless it ended or outlived TaskRunLife since the relay last called on it.
func (w *InProcess) runOf(h Handle) *taskRun {
	w.mu.Lock()
	r := w.runs[h]
	w.mu.Unlock()
	if r == nil {
		return nil
	}
	r.mu.Lock()
	expired := !w.now().Before(r.expires)
	r.mu.Unlock()
	if expired {
		w.endRun(h, measure.CutByDeadline)
		return nil
	}
	return r
}

// takeRun is runOf, taking the run out of the worker's keeping.
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

// endRun ends the run h names, if it names one: it frees the run's state and cuts the step it has in flight.
func (w *InProcess) endRun(h Handle, reason measure.Cut) bool {
	w.mu.Lock()
	r := w.runs[h]
	delete(w.runs, h)
	w.mu.Unlock()
	if r == nil {
		return false
	}
	if live := r.end(); live != nil {
		w.Cut(live.handle, reason)
	}
	return true
}

// checkRun is a run's timer: it ends a run no call touched for TaskRunLife, and waits on for one touched since.
func (w *InProcess) checkRun(r *taskRun) {
	r.mu.Lock()
	if r.ended {
		r.mu.Unlock()
		return
	}
	if left := r.expires.Sub(w.now()); left > 0 {
		r.timer.Reset(left)
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	w.endRun(r.handle, measure.CutByDeadline)
}

// end marks the run ended and answers its step in flight, which the caller cuts.
func (r *taskRun) end() *taskStep {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return nil
	}
	r.ended = true
	if r.timer != nil {
		r.timer.Stop()
	}
	if s := r.step; s != nil && s.state != stepRan {
		return s
	}
	return nil
}

func (r *taskRun) touch() {
	r.expires = r.w.now().Add(r.w.taskLife)
	if r.timer != nil {
		r.timer.Reset(r.w.taskLife)
	}
}

// starting marks s running, if it is still the step the run issued last.
func (r *taskRun) starting(s *taskStep) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended || r.step != s || s.state != stepIssued {
		return false
	}
	s.state = stepRunning
	r.steps++
	r.touch()
	return true
}

func (r *taskRun) ran(s *taskStep, got stepGot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s.state, s.got = stepRan, got
	if !r.ended {
		r.touch()
	}
}

func (r *taskRun) open(s *taskStep) (Admission, error) {
	header := http.Header{"Content-Type": {"application/json"}}
	o := Opening{Method: http.MethodPost, Header: header, Body: bytes.NewReader(s.body)}
	var a Admission
	var err error
	switch s.kind {
	case catalog.KindChat:
		a, err = r.w.openChat(o, false)
	case catalog.KindSearch:
		a, err = r.w.openSearch(o)
	default:
		a, err = r.w.openFetch(o)
	}
	if err != nil {
		return nil, err
	}
	if !r.w.wrapStep(a, s) {
		r.w.Cut(a.Handle(), measure.CutByProxy)
		return nil, apierr.ErrUnavailable
	}
	s.state = stepIssued
	r.step = s
	return a, nil
}

func stepped(s *taskStep, a Admission) TaskStepped {
	return TaskStepped{Step: TaskStep{Kind: s.kind, Admission: a}}
}

var done = TaskStepped{Done: true}

// next turns the step the run issued last into the one after it. A step that never ran, which the relay cut before
// /run or let lapse, is issued again under a new handle, counting against nothing.
func (r *taskRun) next() (TaskStepped, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return TaskStepped{}, apierr.ErrUnavailable
	}
	r.touch()
	s := r.step
	switch {
	case r.done:
		return done, nil
	case s == nil:
		r.fail("")
		return done, nil
	case s.state == stepIssued:
		r.w.Cut(s.handle, measure.CutByProxy)
		return r.reissue(s.again())
	case s.state == stepRunning:
		return TaskStepped{}, apierr.ErrUnavailable
	}
	r.step = nil
	if s.kind == catalog.KindChat {
		return r.afterPass(s)
	}
	r.answerStep(s)
	return r.advance()
}

func (r *taskRun) reissue(s *taskStep) (TaskStepped, error) {
	a, err := r.open(s)
	switch {
	case err == nil:
		return stepped(s, a), nil
	case s.kind == catalog.KindChat:
		r.fail(codeOfErr(err))
		return done, nil
	}
	r.answerCall(s.call, r.openFailed(s, err))
	return r.advance()
}

// afterPass moves on from a chat pass that ran: to its calls, to the run's end with its answer, or to the pass again.
func (r *taskRun) afterPass(s *taskStep) (TaskStepped, error) {
	g := s.got
	if g.served {
		calls := r.replayed(g.calls)
		if s.callable && len(calls) > 0 {
			r.passes++
			r.attempts = 0
			r.turns = append(r.turns, taskTurn{assistant: true, content: g.content, calls: calls})
			r.pending = calls
			return r.advance()
		}
		if answer := strings.TrimSpace(g.content); answer != "" {
			r.passes++
			r.done, r.answered, r.answer = true, true, answer
			return done, nil
		}
		if g.finish == "content_filter" {
			g.code = apierr.ErrContentFilter.Code
		}
	}
	if !g.served && g.status == http.StatusBadRequest && s.tools && !r.textOnly {
		r.textOnly = true
		return r.nextPass()
	}
	if r.attempts++; r.attempts < maxPassAttempts {
		return r.nextPass()
	}
	r.fail(g.code)
	return done, nil
}

func (r *taskRun) fail(code string) { r.done, r.refusal = true, code }

// nextPass issues the run's next chat pass: with the tools callable on every pass but the last, and on the last with
// their definitions alone when earlier passes called them; with none once a vendor refused a pass that had them.
func (r *taskRun) nextPass() (TaskStepped, error) {
	if r.passes >= MaxTaskChatPasses {
		r.fail("")
		return done, nil
	}
	s := r.passStep()
	a, err := r.open(s)
	if err != nil {
		r.fail(codeOfErr(err))
		return done, nil
	}
	return stepped(s, a), nil
}

func (r *taskRun) passStep() *taskStep {
	var shape passShape
	if !r.textOnly && (r.search != "" || r.fetch != "") {
		callable := r.passes+1 < MaxTaskChatPasses
		if callable || len(r.turns) > 0 {
			shape = passShape{tools: r.toolSpecs(), callable: callable}
		}
	}
	body := passBody(r.bundle.Route, r.bundle.Mode.Tier(), r.system, r.bundle.Prompt, r.turns, shape)
	return &taskStep{owner: r, kind: catalog.KindChat, body: body, tools: len(shape.tools) > 0, callable: shape.callable}
}

func (r *taskRun) toolSpecs() []json.RawMessage {
	var specs []json.RawMessage
	if r.search != "" {
		specs = append(specs, webSearchSpec(r.fetch != ""))
	}
	if r.fetch != "" {
		specs = append(specs, readPageSpec())
	}
	return specs
}

// replayed are a pass's calls as the run replays them: at most maxCallsPerPass, each with a name and arguments every
// vendor takes back and an id no other call of the run has, since some hosts number calls from 0 in every reply.
func (r *taskRun) replayed(calls []capturedCall) []*taskCall {
	var out []*taskCall
	for _, c := range calls[:min(len(calls), maxCallsPerPass)] {
		raw := string(c.args)
		if strings.TrimSpace(raw) == "" {
			raw = "{}"
		}
		args := raw
		if !jsonObject(args) {
			args = "{}"
		}
		out = append(out, &taskCall{id: r.callID(c.id), name: wireName(c.name, "unnamed_tool"), args: args, raw: raw})
	}
	return out
}

func (r *taskRun) callID(raw string) string {
	base := wireName(raw, fmt.Sprintf("call_%d", len(r.ids)))
	id := base
	for n := 2; r.ids[id]; n++ {
		suffix := fmt.Sprintf("_%d", n)
		id = base[:min(len(base), 64-len(suffix))] + suffix
	}
	r.ids[id] = true
	return id
}

// advance answers the pass's calls in order, issuing a step for each that runs, then the next pass.
func (r *taskRun) advance() (TaskStepped, error) {
	for len(r.pending) > 0 {
		c := r.pending[0]
		if !c.answered {
			s, result := r.callStep(c)
			if s != nil {
				a, err := r.open(s)
				if err == nil {
					r.count(s.kind)
					return stepped(s, a), nil
				}
				result = r.openFailed(s, err)
			}
			r.answerCall(c, result)
		}
		r.pending = r.pending[1:]
	}
	return r.nextPass()
}

func (r *taskRun) count(kind catalog.Kind) {
	if kind == catalog.KindSearch {
		r.searches++
	} else {
		r.reads++
	}
}

// callStep is the step that runs c, or, for a call that can't run, its result.
func (r *taskRun) callStep(c *taskCall) (*taskStep, string) {
	switch c.name {
	case webSearchName:
		if r.search == "" {
			break
		}
		if r.searches >= MaxTaskSearches {
			return nil, toolError(fmt.Sprintf("%s can run at most %d times per run", webSearchName, MaxTaskSearches))
		}
		args, problem := readSearchArgs(c.raw)
		if problem != "" {
			return nil, problem
		}
		body := jsonx.Encode(struct {
			Model string `json:"model"`
			searchArgs
		}{r.search, args})
		return &taskStep{owner: r, kind: catalog.KindSearch, body: body, call: c}, ""
	case readPageName:
		if r.fetch == "" {
			break
		}
		if r.reads >= MaxTaskReads {
			return nil, toolError(fmt.Sprintf("%s can run at most %d times per run", readPageName, MaxTaskReads))
		}
		raw, problem := readPageArgs(c.raw)
		if problem != "" {
			return nil, problem
		}
		u, problem := openable(raw)
		switch {
		case problem != "":
			return nil, problem
		case len(u.String()) > maxPageURL:
			return nil, toolError(fmt.Sprintf("%s opens URLs of up to %s characters", readPageName, thousands(maxPageURL)))
		case !wasShown(u, r.seen):
			return nil, toolError(readPageName + " can only open pages that the task's prompt or a search result showed in this run. Search first, then read one of the results.")
		}
		u.Fragment, u.RawFragment = "", ""
		body := jsonx.Encode(struct {
			Model string `json:"model"`
			URL   string `json:"url"`
		}{r.fetch, u.String()})
		return &taskStep{owner: r, kind: catalog.KindFetch, body: body, call: c, page: u}, ""
	}
	return nil, toolError(fmt.Sprintf("there is no tool %q in this task", c.name))
}

// openFailed is a call's result when the worker would not open its request.
func (r *taskRun) openFailed(s *taskStep, err error) string {
	if s.kind == catalog.KindSearch {
		return callFailed(webSearchName, nil, codeOfErr(err))
	}
	if code := codeOfErr(err); code == errInvalidURL.Code || code == "invalid_parameter" {
		return toolError("Couldn't read " + s.page.Hostname() + ": Morse won't send that URL to the reader")
	}
	return callFailed(readPageName, s.page, codeOfErr(err))
}

// answerStep gives the call a search or a page read answered what the model reads of its reply, and keeps the pages
// it found as the run's sources and as pages read_page may open.
func (r *taskRun) answerStep(s *taskStep) {
	if !s.got.served {
		r.answerCall(s.call, callFailed(s.call.name, s.page, s.got.code))
		return
	}
	if s.kind == catalog.KindSearch {
		out, found := searchOutput(s.got.body)
		r.sources.found = append(r.sources.found, found...)
		for _, source := range found {
			r.see(source.URL)
		}
		r.answerCall(s.call, out)
		return
	}
	out, source := pageOutput(s.page, s.got.body)
	if source != nil {
		r.sources.read = append(r.sources.read, *source)
		r.see(source.URL)
	}
	r.answerCall(s.call, out)
}

func (r *taskRun) see(raw string) {
	if key, ok := pageKey(raw); ok {
		r.seen[key] = true
	}
}

func (r *taskRun) answerCall(c *taskCall, result string) {
	c.result, c.answered = defang(result), true
	r.turns = append(r.turns, taskTurn{call: c})
}

func codeOfErr(err error) string {
	var refusal apierr.Error
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

// finish ends the run and seals its outcome. A chat pass that ran and answered, which the relay ended the run after
// without asking for the next step, still counts as the run's answer.
func (r *taskRun) finish() (TaskFinished, *taskStep, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ended = true
	if r.timer != nil {
		r.timer.Stop()
	}
	var live *taskStep
	if s := r.step; s != nil && !r.done {
		switch {
		case s.state != stepRan:
			live = s
		case s.kind == catalog.KindChat:
			r.settle(s)
		}
	}
	f, err := r.sealed(r.w.now())
	return f, live, err
}

func (r *taskRun) settle(s *taskStep) {
	g := s.got
	answer := strings.TrimSpace(g.content)
	switch {
	case g.served && answer != "" && !(s.callable && len(g.calls) > 0):
		r.done, r.answered, r.answer = true, true, answer
	case !g.served:
		r.refusal = g.code
	}
}
