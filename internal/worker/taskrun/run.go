package taskrun

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/taskseal"
)

const maxPassAttempts = 2

type Opener[A any] interface {
	Open(s *Step) (A, error)
	Cut(a A, reason measure.Cut)
}

type Spec struct {
	Bundle   Bundle
	Task     ID
	Run      ID
	Revision int64
	Tools    Tools
	Key      *taskseal.Key
	Floors   *Floors
	Now      func() time.Time
	Life     time.Duration
}

type Stepped[A any] struct {
	Kind      catalog.Kind
	Admission A
	Done      bool
}

type phase interface{ isPhase() }

type (
	running  struct{}
	answered struct{ answer string }
	failed   struct{ refusal string }
	ended    struct{}
)

func (running) isPhase()  {}
func (answered) isPhase() {}
func (failed) isPhase()   {}
func (ended) isPhase()    {}

type Run[A any] struct {
	spec   Spec
	opener Opener[A]
	system string

	mu       sync.Mutex
	timer    *time.Timer
	expires  time.Time
	phase    phase
	textOnly bool
	turns    []turn
	pending  []*toolCall
	ids      map[string]bool
	passes   int
	attempts int
	searches int
	reads    int
	seen     map[string]bool
	sources  sources
	step     *Step
	issued   A
	steps    int
}

func New[A any](spec Spec, opener Opener[A]) *Run[A] {
	r := &Run[A]{spec: spec, opener: opener, phase: running{}, seen: map[string]bool{}, ids: map[string]bool{}}
	r.system = system(spec.Bundle, spec.Now(), r.offersTools())
	for _, key := range urlsIn(spec.Bundle.Prompt) {
		r.seen[key] = true
	}
	return r
}

func (r *Run[A]) offersTools() bool { return r.spec.Tools.Search != "" || r.spec.Tools.Fetch != "" }

func (r *Run[A]) Start() (Stepped[A], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.passStep()
	a, err := r.open(s)
	if err != nil {
		return Stepped[A]{}, err
	}
	r.expires = r.spec.Now().Add(r.spec.Life)
	return stepped(s, a), nil
}

func (r *Run[A]) Arm(expire func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.timer = time.AfterFunc(r.spec.Life, func() { r.check(expire) })
}

func (r *Run[A]) Expired() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.spec.Now().Before(r.expires)
}

func (r *Run[A]) check(expire func()) {
	r.mu.Lock()
	if _, over := r.phase.(ended); over {
		r.mu.Unlock()
		return
	}
	if left := r.expires.Sub(r.spec.Now()); left > 0 {
		r.timer.Reset(left)
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	expire()
}

func (r *Run[A]) End(reason measure.Cut) {
	r.mu.Lock()
	if _, over := r.phase.(ended); over {
		r.mu.Unlock()
		return
	}
	live, cut := r.live()
	r.close()
	r.mu.Unlock()
	if cut {
		r.opener.Cut(live, reason)
	}
}

func (r *Run[A]) live() (A, bool) {
	if s := r.step; s != nil && s.state != stepRan {
		return r.issued, true
	}
	var none A
	return none, false
}

func (r *Run[A]) close() {
	r.phase = ended{}
	if r.timer != nil {
		r.timer.Stop()
	}
}

func (r *Run[A]) touch() {
	r.expires = r.spec.Now().Add(r.spec.Life)
	if r.timer != nil {
		r.timer.Reset(r.spec.Life)
	}
}

func (r *Run[A]) starting(s *Step) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, over := r.phase.(ended); over || r.step != s || s.state != stepIssued {
		return false
	}
	s.state = stepRunning
	r.steps++
	r.touch()
	return true
}

func (r *Run[A]) ran(s *Step, got Got) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s.state, s.got = stepRan, got
	if _, over := r.phase.(ended); !over {
		r.touch()
	}
}

func (r *Run[A]) open(s *Step) (A, error) {
	a, err := r.opener.Open(s)
	if err != nil {
		return a, err
	}
	s.state = stepIssued
	r.step, r.issued = s, a
	return a, nil
}

func stepped[A any](s *Step, a A) Stepped[A] { return Stepped[A]{Kind: s.kind, Admission: a} }

func (r *Run[A]) done() (Stepped[A], error) { return Stepped[A]{Done: true}, nil }

func (r *Run[A]) fail(code string) (Stepped[A], error) {
	r.phase = failed{code}
	return r.done()
}

func (r *Run[A]) Next() (Stepped[A], error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, over := r.phase.(ended); over {
		return Stepped[A]{}, apierr.ErrUnavailable
	}
	r.touch()
	if _, open := r.phase.(running); !open {
		return r.done()
	}
	s := r.step
	switch {
	case s == nil:
		return r.fail("")
	case s.state == stepIssued:
		r.opener.Cut(r.issued, measure.CutByProxy)
		return r.reissue(s.again())
	case s.state == stepRunning:
		return Stepped[A]{}, apierr.ErrUnavailable
	}
	r.step = nil
	if s.kind == catalog.KindChat {
		return r.afterPass(s)
	}
	r.answerStep(s)
	return r.advance()
}

func (r *Run[A]) reissue(s *Step) (Stepped[A], error) {
	a, err := r.open(s)
	switch {
	case err == nil:
		return stepped(s, a), nil
	case s.kind == catalog.KindChat:
		return r.fail(codeOfErr(err))
	}
	r.answerCall(s.call, callFailed(s.call.name, s.page, codeOfErr(err)))
	return r.advance()
}

func (r *Run[A]) afterPass(s *Step) (Stepped[A], error) {
	g := s.got
	if g.served {
		calls := r.replayed(g.calls)
		if s.callable && len(calls) > 0 {
			r.passes++
			r.attempts = 0
			r.turns = append(r.turns, turn{assistant: true, content: g.content, calls: calls})
			r.pending = calls
			return r.advance()
		}
		if answer := strings.TrimSpace(g.content); answer != "" {
			r.passes++
			r.phase = answered{answer}
			return r.done()
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
	return r.fail(g.code)
}

func (r *Run[A]) nextPass() (Stepped[A], error) {
	if r.passes >= MaxChatPasses {
		return r.fail("")
	}
	s := r.passStep()
	a, err := r.open(s)
	if err != nil {
		return r.fail(codeOfErr(err))
	}
	return stepped(s, a), nil
}

func (r *Run[A]) passStep() *Step {
	var shape passShape
	if !r.textOnly && r.offersTools() {
		callable := r.passes+1 < MaxChatPasses
		if callable || len(r.turns) > 0 {
			shape = passShape{tools: r.toolSpecs(), callable: callable}
		}
	}
	b := r.spec.Bundle
	body := passBody(b.Route, b.Mode.Tier(), r.system, b.Prompt, r.turns, shape)
	return &Step{owner: r, kind: catalog.KindChat, body: body, tools: len(shape.tools) > 0, callable: shape.callable}
}

func (r *Run[A]) toolSpecs() []json.RawMessage {
	var specs []json.RawMessage
	if r.spec.Tools.Search != "" {
		specs = append(specs, webSearchSpec(r.spec.Tools.Fetch != ""))
	}
	if r.spec.Tools.Fetch != "" {
		specs = append(specs, readPageSpec())
	}
	return specs
}

func (r *Run[A]) replayed(calls []capturedCall) []*toolCall {
	var out []*toolCall
	for _, c := range calls[:min(len(calls), maxCallsPerPass)] {
		raw := string(c.args)
		if strings.TrimSpace(raw) == "" {
			raw = "{}"
		}
		args := raw
		if !jsonObject(args) {
			args = "{}"
		}
		out = append(out, &toolCall{id: r.callID(c.id), name: wireName(c.name, "unnamed_tool"), args: args, raw: raw})
	}
	return out
}

func (r *Run[A]) callID(raw string) string {
	base := wireName(raw, fmt.Sprintf("call_%d", len(r.ids)))
	id := base
	for n := 2; r.ids[id]; n++ {
		suffix := fmt.Sprintf("_%d", n)
		id = base[:min(len(base), 64-len(suffix))] + suffix
	}
	r.ids[id] = true
	return id
}

func (r *Run[A]) advance() (Stepped[A], error) {
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
				result = callFailed(c.name, s.page, codeOfErr(err))
			}
			r.answerCall(c, result)
		}
		r.pending = r.pending[1:]
	}
	return r.nextPass()
}

func (r *Run[A]) count(kind catalog.Kind) {
	if kind == catalog.KindSearch {
		r.searches++
	} else {
		r.reads++
	}
}

func (r *Run[A]) callStep(c *toolCall) (*Step, string) {
	switch c.name {
	case webSearchName:
		if r.spec.Tools.Search == "" {
			break
		}
		if r.searches >= MaxSearches {
			return nil, toolError(fmt.Sprintf("%s can run at most %d times per run", webSearchName, MaxSearches))
		}
		args, problem := readSearchArgs(c.raw)
		if problem != "" {
			return nil, problem
		}
		body := jsonx.Encode(struct {
			Model string `json:"model"`
			searchArgs
		}{r.spec.Tools.Search, args})
		return &Step{owner: r, kind: catalog.KindSearch, body: body, call: c}, ""
	case readPageName:
		if r.spec.Tools.Fetch == "" {
			break
		}
		if r.reads >= MaxReads {
			return nil, toolError(fmt.Sprintf("%s can run at most %d times per run", readPageName, MaxReads))
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
		}{r.spec.Tools.Fetch, u.String()})
		return &Step{owner: r, kind: catalog.KindFetch, body: body, call: c, page: u}, ""
	}
	return nil, toolError(fmt.Sprintf("there is no tool %q in this task", c.name))
}

func (r *Run[A]) answerStep(s *Step) {
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

func (r *Run[A]) see(raw string) {
	if key, ok := pageKey(raw); ok {
		r.seen[key] = true
	}
}

func (r *Run[A]) answerCall(c *toolCall, result string) {
	c.result, c.answered = defang(result), true
	r.turns = append(r.turns, turn{call: c})
}

func codeOfErr(err error) string {
	var refusal apierr.Error
	if errors.As(err, &refusal) {
		return refusal.Code
	}
	return ""
}

func (r *Run[A]) Finish() (Finished, error) {
	r.mu.Lock()
	outcome := r.phase
	var live A
	var cut bool
	if _, open := outcome.(running); open {
		outcome = failed{}
		if s := r.step; s != nil {
			switch {
			case s.state != stepRan:
				live, cut = r.issued, true
			case s.kind == catalog.KindChat:
				outcome = settled(s)
			}
		}
	}
	r.close()
	f, err := r.sealed(outcome, r.spec.Now())
	r.mu.Unlock()
	if cut {
		r.opener.Cut(live, measure.CutByProxy)
	}
	return f, err
}

func settled(s *Step) phase {
	g := s.got
	answer := strings.TrimSpace(g.content)
	switch {
	case g.served && answer != "" && !(s.callable && len(g.calls) > 0):
		return answered{answer}
	case !g.served:
		return failed{g.code}
	}
	return failed{}
}

type stepState uint8

const (
	stepIssued stepState = iota
	stepRunning
	stepRan
)

type stepOwner interface {
	starting(s *Step) bool
	ran(s *Step, got Got)
}

type Step struct {
	owner    stepOwner
	kind     catalog.Kind
	body     []byte
	tools    bool
	callable bool
	call     *toolCall
	page     *url.URL
	state    stepState
	got      Got
}

func (s *Step) Kind() catalog.Kind { return s.kind }

func (s *Step) Body() []byte { return s.body }

func (s *Step) Start() bool { return s.owner.starting(s) }

func (s *Step) Ran(got Got) { s.owner.ran(s, got) }

func (s *Step) again() *Step {
	return &Step{owner: s.owner, kind: s.kind, body: s.body, tools: s.tools, callable: s.callable, call: s.call, page: s.page}
}
