package worker

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/compaction"
	"morse/backend/internal/health"
	"morse/backend/internal/plans/limits"
	"morse/backend/internal/tokenizer"
	"morse/backend/internal/upstream"
)

type chatRoute struct {
	catalog.ChatTerms
	Upstream          ChatUpstream
	Reasoning         chat.Reasoning
	ReasoningUncapped bool
	Counter           *tokenizer.Tokenizer
	model             catalog.ModelID
	endpoint          catalog.EndpointID
	attester          string
	speaks            *chat.Scheme
	tier              catalog.Tier
}

func (c Chat) route(model catalog.ModelID, vendor Model) chatRoute {
	return chatRoute{ChatTerms: c.ChatTerms, Upstream: c.Upstream, Reasoning: c.Reasoning, ReasoningUncapped: c.ReasoningUncapped, Counter: c.Counter, model: model, endpoint: vendor.Endpoint, attester: vendor.Attester, speaks: c.Upstream.Speaks(), tier: vendor.Tier}
}

func (r chatRoute) runsOnly(proposed []catalog.EndpointID) bool {
	return len(proposed) > 0 && !slices.ContainsFunc(proposed, func(id catalog.EndpointID) bool { return id != r.endpoint })
}

func vendorFor(vendors []chatRoute, p protocol) chatRoute {
	for _, v := range vendors[1:] {
		if v.speaks == p.scheme {
			return v
		}
	}
	return vendors[0]
}

func (r chatRoute) misserved(p protocol, compaction bool) error {
	if compaction && r.tier.Sealed() {
		return errCompactionSealed
	}
	return refuseProtocol(r.speaks, p)
}

func (r chatRoute) promptBound(size int) int {
	if r.ContextTokens > 0 {
		return min(size, r.ContextTokens)
	}
	return size
}

func (r chatRoute) clamp(granted, asked int) int {
	limit := min(granted, r.MaxOutputTokens)
	if asked > 0 {
		limit = min(limit, asked)
	}
	return max(limit, 0)
}

func askedOutput(req *chat.Request) int {
	if asked := req.OutputLimits(); len(asked) > 0 {
		return asked[0]
	}
	return 0
}

type openedChat struct {
	cuts
	route         chatRoute
	protocol      protocol
	call          chat.Call
	asked         int
	launch        *chat.Launch
	own           *chat.OwnFrame
	writing       *chat.Writing
	promptComment []byte
	character     chat.Character
	promptBytes   int
}

// played is the character the chat plays: the launch the proxy checked, the user's own character whose rules it
// checked, or the one whose prompt opens the client's system message.
func (o *openedChat) played(cast chat.Cast) chat.Character {
	if o.launch != nil {
		return o.launch.Character()
	}
	if o.own != nil {
		return o.own.Character()
	}
	text, _ := o.call.SystemText()
	return cast.Plays(text)
}

func (w *InProcess) openChat(o Opening, compaction bool) (Admission, error) {
	req, err := chat.ParseRequest(o.Body)
	if err != nil {
		return nil, contentRefusal(err)
	}
	vendors, known := w.chats[req.Model]
	if !known {
		return nil, apierr.ErrModelNotFound
	}
	p := protocolOf(o.Header.Get)
	route := vendorFor(vendors, p)
	if err := route.misserved(p, compaction); err != nil {
		return nil, err
	}
	if !route.tier.Sealed() {
		floor, err := floorOf(req)
		if err != nil {
			return nil, err
		}
		if err := route.refuseBelow(floor); err != nil {
			return nil, err
		}
	}
	if o.Launch != nil && !o.Cast.Casts(*o.Launch) {
		return nil, errLaunchNotCast
	}
	if o.Own != nil && (o.Launch != nil || o.Own.Base != o.Cast.Rules()) {
		return nil, errOwnNotCast
	}
	if o.Writing != nil {
		for _, e := range o.Writing.Examples {
			if !o.Cast.Casts(e.Launch) {
				return nil, errLaunchNotCast
			}
		}
	}
	oc := &openedChat{cuts: newCuts(), route: route, protocol: p, call: chat.Call{Request: req, RouteEffort: route.DefaultReasoningEffort, Efforts: route.ReasoningEfforts}, launch: o.Launch, own: o.Own, writing: o.Writing}
	if compaction {
		err = oc.compact(o.Cast)
	} else {
		err = route.Upstream.admit(oc, o.Cast)
	}
	if err != nil {
		return nil, err
	}
	return ChatAdmission{
		admitted: admitted{w.keep(o, oc)}, Model: route.model, Candidates: []catalog.EndpointID{route.endpoint},
		PromptBound: route.promptBound(oc.call.Size()), PromptBytes: limits.KibibytesCovering(oc.promptBytes), OutputAsked: oc.asked,
		Stream: req.Stream, Compaction: compaction, Character: oc.character,
	}, nil
}

var vendorFaults = map[health.Outcome]bool{health.UpstreamBusy: true, health.UpstreamUnavailable: true, health.UpstreamError: true}

func (o *openedChat) cut(reason measure.Cut) { o.cuts.cut(reason, true) }

func (o *openedChat) run(_ context.Context, w *InProcess, h Handle, g Grant, reply http.ResponseWriter) Measured {
	cg, ok := g.(ChatGrant)
	if !ok || !o.route.runsOnly(cg.Endpoints) {
		return unrunnable(reply)
	}
	o.call.OutputLimit = o.route.clamp(cg.OutputLimit, o.asked)
	ctx := o.cuts.run
	rw := newReplyWriter(reply)
	opened := time.Now()
	got := o.route.Upstream.serve(ctx, w, o, rw)
	returned := time.Now()
	end := endingOf(ctx, got.writeErr, got.callErr)
	if got.attempts.Refused {
		// The retry loop held a busy refusal, which Anthropic sends inside a 200 stream with no status, so no
		// upstream.Refused names it.
		end = verdictOf(got.callErr)
	}
	e := got.evidence(end, o.call, o.route, cg)
	m := Measured{Measurement: e.Measure(), Cut: end.cut(), Served: got.callErr == nil, Refusal: end.refusal(got.callErr), Endpoint: o.route.endpoint}
	m.Health = rw.observed(ctx, got.callErr, false, opened, returned)
	m.Health.Retries, m.Health.Hedges = got.attempts.Retries, got.attempts.Hedges
	if refused, ok := errors.AsType[upstream.Refused](got.callErr); ok && vendorFaults[m.Health.Outcome] {
		w.reports.VendorRefused(o.call.Model, refused.Status)
	}
	if chunk, ok := errors.AsType[chat.ErrorChunk](got.callErr); ok {
		w.reports.UpstreamErrorChunk(o.call.Model, chunk.Code)
	}
	if got.callErr != nil && rw.status == 0 {
		refuse(ctx, rw, got.callErr)
	}
	p := o.route.Upstream.count(o, e, got)
	switch {
	case p != nil && p.count != nil && e.NeedsCount():
		m.Follow, m.Counted = FollowCount, w.startCount(h, p, cg.Figures)
	case p != nil && cg.Sample && e.Outcome == measure.Completed:
		m.Follow, m.Counted = FollowSample, w.startSample(h, p)
	}
	return m
}

var (
	errCompactionSealed        = apierr.Invalid(http.StatusBadRequest, "compaction_not_sealable", "Compaction is refused on e2ee models, because the proxy adds the compaction instruction and cannot read or change a sealed body. Fetch the instruction from GET /v1/compaction and send it as the last sealed user message of an ordinary chat request.")
	errOpenToolCall            = apierr.Invalid(http.StatusBadRequest, "compaction_open_tool_call", "The last message calls tools whose results are not in the request. Compact up to a turn whose tool calls all have results.")
	errLaunchNotCast           = fmt.Errorf("%w: the launch prompt is not the cast's", apierr.ErrUnavailable)
	errOwnNotCast              = fmt.Errorf("%w: the own character's rules are not the cast's", apierr.ErrUnavailable)
	errLaunchPromptSent        = apierr.Invalid(http.StatusBadRequest, "character_prompt_sent", "With X-Character-Content the proxy writes the character's prompt into the chat, so the system message must not open with it.")
	errExamplesNotChat         = apierr.InvalidParameter("X-Writer-Examples goes on POST /v1/chat/completions alone.")
	errExamplesSealed          = apierr.InvalidParameter("X-Writer-Examples goes on a chat request to a model whose messages the proxy can read, which no e2ee model's are.")
	errLaunchSystemSealed      = apierr.Invalid(http.StatusBadRequest, "character_prompt_sent", "With X-Character-Content the proxy writes the sealed system message of an e2ee chat, so send the chat's own additions as a user message.")
	errCharacterMessageTooLong = apierr.Invalid(http.StatusBadRequest, "message_too_long", fmt.Sprintf("A character chat's latest user message may be at most %d tokens, counted at %d bytes of text a token: %d bytes. Send a shorter message.", limits.CharacterMessageTokens, limits.IncludedWindowBytesPerToken, limits.CharacterMessageBytes))
)

func (Plain) admit(o *openedChat, cast chat.Cast) error {
	if err := o.underLaunch(cast); err != nil {
		return err
	}
	if o.writing != nil {
		req, err := o.call.Request.WithExamples(o.writing.Examples)
		if err != nil {
			return err
		}
		o.call.Request = req
	}
	msgs, err := o.call.Messages()
	if err != nil {
		return err
	}
	o.character = o.played(cast)
	if o.character.Plays() && latestUserTextBytes(msgs) > limits.CharacterMessageBytes {
		return errCharacterMessageTooLong
	}
	o.asked = askedOutput(o.call.Request)
	o.promptBytes, err = o.call.PromptTextBytes()
	return err
}

func latestUserTextBytes(msgs []chat.Message) int {
	for _, m := range slices.Backward(msgs) {
		if m.Role == "user" {
			return m.TextBytes()
		}
	}
	return 0
}

// underLaunch opens a plaintext chat's system message with the launch's prompt, or puts the rules of the user's own
// character around it. A chat whose system message opens with a character's prompt already is refused: its client
// sent what the proxy writes.
func (o *openedChat) underLaunch(cast chat.Cast) error {
	if o.launch == nil && o.own == nil {
		return nil
	}
	text, _ := o.call.SystemText()
	switch played := cast.Plays(text).Kind; {
	case played == chat.CatalogCharacter, o.own != nil && played == chat.OwnCharacter:
		return errLaunchPromptSent
	}
	if o.own != nil {
		req, err := o.call.Request.UnderOwnFrame(*o.own)
		if err != nil {
			return err
		}
		o.call.Request = req
		return nil
	}
	req, err := o.call.Request.UnderSystemPrompt(o.launch.Prompt)
	if err != nil {
		return err
	}
	o.call.Request = req
	return nil
}

func (o *openedChat) compact(cast chat.Cast) error {
	if err := o.underLaunch(cast); err != nil {
		return err
	}
	o.asked = askedOutput(o.call.Request)
	compact, err := o.call.Request.AsCompaction(compaction.PromptWithin(o.asked))
	switch {
	case errors.Is(err, chat.ErrOpenToolCall):
		return errOpenToolCall
	case err != nil:
		return err
	}
	o.character = o.played(cast)
	if o.promptBytes, err = o.call.PromptTextBytes(); err != nil {
		return err
	}
	o.call.Request = compact
	return nil
}

func (u Plain) serve(ctx context.Context, w *InProcess, o *openedChat, reply http.ResponseWriter) served {
	var transcript *chat.Transcript
	if o.route.Counter != nil {
		transcript = chat.NewTranscript(transcriptLimit(o.call))
	}
	var clock *thinkingClock
	if o.route.HidesReasoning {
		clock = &thinkingClock{now: w.now}
	}
	var got served
	retry := chat.BusyRetry{Provider: u.Provider, Waits: u.BusyWaits, HedgeAfter: u.Hedge.Wait(o.promptBytes / limits.IncludedWindowBytesPerToken)}
	if o.call.Stream {
		got = stream(ctx, reply, http.NewResponseController(reply), retry, o.call, transcript, clock, w.keepaliveEvery)
	} else {
		got = complete(ctx, reply, retry, o.call, transcript, clock)
	}
	got.transcript = transcript
	return got
}

func (Plain) count(o *openedChat, e measure.Evidence, got served) *pendingCount {
	count := &pendingCount{route: o.call.Model, evidence: e, call: o.call}
	if got.transcript.Complete() {
		count.count, count.transcript = o.route.Counter.Count, got.transcript
	}
	return count
}

type served struct {
	reported          chat.Usage
	attempts          chat.Attempts
	reply             measure.Reply
	finish            chat.Finish
	host              chat.Host
	unanswered        bool
	writeErr, callErr error
	thought           thought
	transcript        *chat.Transcript
}

func (s served) evidence(end ending, c chat.Call, r chatRoute, g ChatGrant) measure.Evidence {
	attachments, attachmentBytes, err := c.Attachments()
	if err != nil {
		attachments, attachmentBytes = 0, 0
	}
	return measure.Evidence{
		Outcome:            end.outcome(),
		Cut:                end.cut(),
		Upstream:           s.reported,
		PromptBytes:        c.Size() - attachmentBytes,
		Attachments:        attachments,
		PromptBound:        r.promptBound(c.Size()),
		Budgeted:           g.Budgeted,
		Reply:              s.reply,
		Finish:             s.finish,
		ServedBy:           s.host,
		Unanswered:         s.unanswered,
		ReasoningRequested: c.Reasoned(r.Reasoning),
		HidesReasoning:     r.HidesReasoning,
		OutputLimit:        c.OutputLimit,
		ReplyBytesPerToken: g.Figures.ReplyBytesPerToken,
		ReasoningCap:       g.ReasoningCap,
		Thinking:           measure.ThinkingTime{Duration: s.thought.duration, Rate: g.Figures.ThinkingRate},
		ReasonedAgain:      s.thought.interleaved,
	}
}

type thought struct {
	duration    time.Duration
	interleaved bool
}

type thinkingClock struct {
	now                     func() time.Time
	firstEvent, firstAnswer time.Time
	interleaved             bool
}

func (t *thinkingClock) startAtCall() {
	if t != nil {
		t.firstEvent = t.now()
	}
}

func (t *thinkingClock) observe(d chat.Delta) {
	if t == nil {
		return
	}
	at := t.now()
	if t.firstEvent.IsZero() {
		t.firstEvent = at
	}
	switch {
	case d.Answers() && t.firstAnswer.IsZero():
		t.firstAnswer = at
	case d.Reasons() && !t.firstAnswer.IsZero():
		t.interleaved = true
	}
}

func (t *thinkingClock) thought() thought {
	if t == nil || t.firstEvent.IsZero() {
		return thought{}
	}
	return thought{duration: cmp.Or(t.firstAnswer, t.now()).Sub(t.firstEvent), interleaved: t.interleaved}
}

func stream(ctx context.Context, w http.ResponseWriter, rc *http.ResponseController, prov chat.BusyRetry, c chat.Call, transcript *chat.Transcript, clock *thinkingClock, keepalive time.Duration) served {
	sw := &sseWriter{eventStream: eventStream{w: w, rc: rc}, transcript: transcript, clock: clock}
	stop := func() {}
	if clock != nil {
		stop = sw.keepAlive(ctx, keepalive)
	}
	reported, attempts, err := prov.Stream(ctx, c, sw.emit)
	stop()
	if err == nil && sw.empty() {
		err = errEmptyReply
	}
	switch {
	case err == nil:
		sw.done()
	case sw.started && ctx.Err() == nil && sw.err == nil:
		sw.errorEvent()
	}
	return served{reported: reported, attempts: attempts, reply: measure.Streamed{Events: sw.delivered, VisibleBytes: sw.visible}, finish: sw.finish, host: sw.host, unanswered: unanswered(sw.finish, sw.sent), writeErr: sw.err, callErr: err, thought: clock.thought()}
}

func complete(ctx context.Context, w http.ResponseWriter, prov chat.BusyRetry, c chat.Call, transcript *chat.Transcript, clock *thinkingClock) served {
	clock.startAtCall()
	body, tokens, attempts, err := prov.Complete(ctx, c)
	if err != nil {
		return served{reported: tokens, attempts: attempts, reply: measure.Buffered{}, callErr: err, thought: clock.thought()}
	}
	w.Header().Set("Content-Type", "application/json")
	d := body.Delta()
	if unanswered(d.Finish, d.Delivered()) {
		body = body.MarkUnanswered()
	}
	written, writeErr := body.WriteTo(w)
	if written > 0 {
		transcript.Add(d)
	}
	return served{reported: tokens, attempts: attempts, reply: measure.Buffered{Bytes: int(written)}, finish: d.Finish, host: body.Host(), unanswered: unanswered(d.Finish, d.Delivered()), writeErr: writeErr}
}
