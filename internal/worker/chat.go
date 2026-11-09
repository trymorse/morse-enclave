package worker

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"morse/backend/internal/affinity"
	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/compaction"
	"morse/backend/internal/health"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/plans/limits"
	"morse/backend/internal/tokenizer"
	"morse/backend/internal/upstream"

	"golang.org/x/text/unicode/norm"
)

// HeaderTier names the tier of the endpoint that serves a chat reply. Failover moves a request only before its first
// byte, so the tier of the attempt that begins the reply is final.
const HeaderTier = "X-Tier"

type chatRoute struct {
	catalog.ChatTerms
	Upstream             ChatUpstream
	Reasoning            chat.Reasoning
	ReasoningUncapped    bool
	SilentWhileReasoning bool
	Counter              *tokenizer.Tokenizer
	model                catalog.ModelID
	endpoint             catalog.EndpointID
	attester             string
	speaks               *chat.Scheme
	tier                 catalog.Tier
	retention            catalog.Retention
	order                int
	aliased              bool
	// onBehalf marks a route derived from a sealed one for a key's plaintext chat, which the relay re-derives. seals marks
	// a declared on-behalf endpoint, a route of its own whose plaintext chat the worker seals to its sealed endpoint's
	// vendor.
	onBehalf bool
	seals    bool
}

func (c Chat) route(model catalog.ModelID, vendor Model) chatRoute {
	return chatRoute{ChatTerms: c.ChatTerms, Upstream: c.Upstream, Reasoning: c.Reasoning, ReasoningUncapped: c.ReasoningUncapped, SilentWhileReasoning: c.SilentWhileReasoning, Counter: c.Counter, model: model, endpoint: vendor.Endpoint, attester: vendor.Attester, speaks: c.Upstream.Speaks(), tier: vendor.Tier, retention: vendor.Retention, order: vendor.Order}
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
	routes        []chatRoute
	first         chatRoute
	protocol      protocol
	call          chat.Call
	asked         int
	launch        *chat.Launch
	own           *chat.OwnFrame
	writing       *chat.Writing
	promptComment []byte
	character     chat.Character
	promptBytes   int
	// afterCut is set while a reply sealed whole runs (see outlivesCut).
	afterCut *afterCut
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
	p := protocolOf(o.Header.Get)
	req, err := requestOf(o.Body, p)
	if err != nil {
		return nil, err
	}
	name, known := w.chats[req.Model]
	if !known {
		return nil, apierr.ErrModelNotFound
	}
	ask := askOf(p, o.KeyCaller, req)
	var digest affinity.Digest
	if o.inTheClear(ask) {
		digest = affinity.DigestOf(req)
	}
	var want providerAsk
	var wantErr error
	if p.scheme == nil {
		want, wantErr = floorOf(req)
	}
	routes, err := name.reach(p, ask, compaction, want, o.KeyFloor)
	if err != nil && ask == askLooksSealed {
		return nil, hintedHexOnly(err)
	}
	if err != nil {
		return nil, err
	}
	if p.scheme == nil {
		if wantErr != nil {
			return nil, wantErr
		}
		if routes, err = name.atFloor(routes, want.floor); err != nil {
			return nil, err
		}
		if routes, err = withoutUnsealable(routes, req); err != nil {
			return nil, err
		}
		if routes, err = want.narrow(name, routes, o.KeyFloor); err != nil {
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
	route := routes[0]
	oc := &openedChat{cuts: newCuts(), routes: routes, first: route, protocol: p, call: chat.Call{Request: req, RouteEffort: route.DefaultReasoningEffort, Efforts: route.ReasoningEfforts}, launch: o.Launch, own: o.Own, writing: o.Writing}
	if compaction {
		err = oc.compact(o.Cast)
	} else {
		err = route.Upstream.admit(oc, o.Cast)
	}
	if err == nil && route.onBehalf {
		err = unsealableRefusal(openaicompat.Unsealable(oc.call.Request))
	}
	if err != nil {
		return nil, err
	}
	return ChatAdmission{
		admitted: admitted{w.keep(o, oc)}, Model: name.model, Candidates: endpointsOf(routes), Affinity: digest, MaxPrice: want.maxPrice, Sealable: name.sealable(), OnBehalf: route.onBehalf,
		PromptSize: oc.call.Size(), PromptBytes: limits.KibibytesCovering(oc.promptBytes), TextMessages: textMessages(oc.call), PromptCounted: promptCounted(oc.call), OutputAsked: oc.asked,
		Stream: req.Stream, Compaction: compaction, Character: oc.character,
	}, nil
}

func promptCounted(c chat.Call) bool {
	msgs, err := c.Messages()
	if err != nil {
		return false
	}
	for _, m := range msgs {
		for _, p := range m.Parts() {
			if p.Text == nil {
				return false
			}
		}
	}
	return true
}

func textMessages(c chat.Call) int {
	msgs, err := c.Messages()
	if _, text := c.PromptTexts(); !text || err != nil || !norm.NFC.IsNormal(c.Verbatim()) {
		return 0
	}
	return len(msgs)
}

// requestOf reads a request from its body, or, when its scheme seals the body whole, from its clear headers:
// the body is then ciphertext the worker relays unread.
func requestOf(body io.Reader, p protocol) (*chat.Request, error) {
	if p.scheme == nil || !p.scheme.SealsBody {
		req, err := chat.ParseRequest(body)
		if err != nil {
			return nil, contentRefusal(err)
		}
		return req, nil
	}
	if p.err != nil {
		return nil, protocolRefusal(p.err)
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		return nil, contentRefusal(err)
	}
	sealed := p.params.(chat.BodySealed)
	return chat.SealedBodyRequest(raw, sealed.SealedModel(), sealed.OutputLimit()), nil
}

var vendorFaults = map[health.Outcome]bool{health.UpstreamBusy: true, health.UpstreamUnavailable: true, health.UpstreamRefused: true, health.UpstreamError: true}

// cut ends the run with its caller, but for a reply sealed whole, whose usage comes only after its last frame:
// that one reads on for cutGrace first.
func (o *openedChat) cut(reason measure.Cut) { o.cuts.cut(reason, !o.outlivesCut()) }

func (o *openedChat) outlivesCut() bool {
	return o.protocol.scheme != nil && o.protocol.scheme.SealsBody
}

type attempt struct {
	route       chatRoute
	call        chat.Call
	waits       []time.Duration
	promptBound int
	// hedgeAfter is how long the call may stay silent before a second call to the same endpoint races it, and
	// stallAfter before it is given up as stalled. Zero is never.
	hedgeAfter, stallAfter time.Duration
}

// attempt is the call on r. Only the last endpoint waits out a busy refusal, and only one whose hedge has no next
// endpoint to go to hedges in place.
func (o *openedChat) attempt(r chatRoute, g ChatGrant, last, hedgesInPlace bool) attempt {
	c := o.call
	c.RouteEffort, c.Efforts, c.OutputLimit = r.DefaultReasoningEffort, r.ReasoningEfforts, r.clamp(g.OutputLimit, o.asked)
	a := attempt{route: r, call: c, promptBound: g.PromptBound}
	if last {
		a.waits = r.Upstream.busyWaits()
	}
	h := r.hedge(c)
	a.stallAfter = h.Stall(o.promptTokens())
	if hedgesInPlace {
		a.hedgeAfter = h.Wait(o.promptTokens())
	}
	return a
}

// hedge is the route's Hedge for c. Only a stream hedges.
func (r chatRoute) hedge(c chat.Call) chat.Hedge {
	if !c.Stream {
		return chat.Hedge{}
	}
	return r.Upstream.hedge()
}

// promptTokens is the prompt's size in tokens at the bytes a token the included window counts.
func (o *openedChat) promptTokens() int { return o.promptBytes / limits.IncludedWindowBytesPerToken }

func (o *openedChat) run(_ context.Context, w *InProcess, h Handle, g Grant, reply http.ResponseWriter) Measured {
	cg, ok := g.(ChatGrant)
	if !ok {
		return unrunnable(reply)
	}
	granted, ok := o.granted(cg.Endpoints)
	if !ok || cg.PromptBound <= 0 {
		return unrunnable(reply)
	}
	ctx := o.cuts.run
	if o.outlivesCut() {
		o.afterCut = newAfterCut(ctx, o.cuts.client)
		defer o.afterCut.stop()
		ctx = o.afterCut.ctx
	}
	rw := newReplyWriter(reply)
	end := o.walk(ctx, w, granted, cg, rw)
	a, got, e, m := end.a, end.got, end.e, end.m
	unsent := got.callErr != nil && rw.status == 0
	m.Unserved = unsent && m.Cut == measure.NotCut && m.Health.Outcome.FailsOver() && m.Health.Outcome != health.Unattested && m.Health.Outcome != health.ContextOverflow
	if unsent {
		refuse(ctx, rw, got.callErr)
	}
	p := a.route.Upstream.count(a, e, got)
	switch {
	case got.unproven != nil && e.Outcome == measure.Completed:
		m.Follow, m.Counted = FollowCount, w.startProof(h, e, *got.unproven)
	case p != nil && p.count != nil && e.NeedsCount():
		m.Follow, m.Counted = FollowCount, w.startCount(h, p, cg.Figures)
	case p != nil && cg.Sample && e.Outcome == measure.Completed:
		m.Follow, m.Counted = FollowSample, w.startSample(h, p)
	}
	return m
}

func (o *openedChat) try(ctx context.Context, w *InProcess, a attempt, g ChatGrant, rw *replyWriter) (served, measure.Evidence, Measured) {
	opened := time.Now()
	got := a.route.Upstream.serve(ctx, w, o, a, rw)
	returned := time.Now()
	end := endingOf(ctx, got.writeErr, got.callErr)
	if got.attempts.Refused {
		// The retry loop held a busy refusal, which Anthropic sends inside a 200 stream with no status, so no
		// upstream.Refused names it.
		end = verdictOf(got.callErr)
	}
	e := got.evidence(end, a, g)
	m := Measured{Measurement: e.Measure(), Cut: end.cut(), Served: got.callErr == nil, Refusal: end.refusal(got.callErr), Endpoint: a.route.endpoint}
	m.Health = rw.observed(ctx, got.callErr, false, opened, returned)
	m.Health.Malformed = got.malformed && m.Health.Outcome == health.OK
	m.Health.Retries, m.Health.Hedges, m.Health.OutputTokens = got.attempts.Retries, got.attempts.Hedges, a.route.tokensAfterFirstByte(got.reported)
	refused, isRefusal := errors.AsType[upstream.Refused](got.callErr)
	if isRefusal && vendorFaults[m.Health.Outcome] {
		w.reports.VendorRefused(a.call.Model, refused.Status)
	}
	if isRefusal && m.Health.Outcome == health.ContextOverflow {
		m.Health.Window = refused.Window
	}
	if chunk, ok := errors.AsType[chat.ErrorChunk](got.callErr); ok {
		w.reports.UpstreamErrorChunk(a.call.Model, chunk.Code)
	}
	return got, e, m
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

// withoutUnsealable drops the on-behalf endpoints from a request they cannot carry through their seal, and refuses it only
// when no endpoint is left.
func withoutUnsealable(routes []chatRoute, req *chat.Request) ([]chatRoute, error) {
	if !slices.ContainsFunc(routes, func(r chatRoute) bool { return r.seals }) {
		return routes, nil
	}
	err := openaicompat.Unsealable(req)
	if err == nil {
		return routes, nil
	}
	kept := slices.DeleteFunc(slices.Clone(routes), func(r chatRoute) bool { return r.seals })
	if len(kept) == 0 {
		return nil, unsealableRefusal(err)
	}
	return kept, nil
}

func unsealableRefusal(err error) error {
	unsealable, ok := errors.AsType[*openaicompat.UnsealableField](err)
	if !ok {
		return err
	}
	return apierr.Invalid(http.StatusBadRequest, "unsealable_request", "Field "+unsealable.Name+" is refused in a plaintext request to an e2ee model, whose vendor's encryption would carry it in the clear. Send only system, user, and assistant messages with string content, or seal the request yourself.")
}

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

func (u Plain) serve(ctx context.Context, w *InProcess, o *openedChat, a attempt, reply http.ResponseWriter) served {
	var transcript *chat.Transcript
	if a.route.Counter != nil {
		transcript = chat.NewTranscript(transcriptLimit(a.call))
	}
	var clock *thinkingClock
	if a.route.HidesReasoning {
		clock = &thinkingClock{now: w.now}
	}
	var got served
	retry := chat.BusyRetry{Provider: u.Provider, Waits: a.waits, HedgeAfter: a.hedgeAfter, StallAfter: a.stallAfter}
	if a.call.Stream {
		got = stream(ctx, reply, http.NewResponseController(reply), retry, a.call, transcript, clock, w.keepaliveEvery)
	} else {
		got = complete(ctx, reply, retry, a.call, transcript, clock)
	}
	got.transcript = transcript
	return got
}

func (Plain) count(a attempt, e measure.Evidence, got served) *pendingCount {
	count := &pendingCount{route: a.call.Model, evidence: e, call: a.call}
	if got.transcript.Complete() {
		count.count, count.transcript = a.route.Counter.Count, got.transcript
	}
	return count
}

type served struct {
	reported          chat.Usage
	attempts          chat.Attempts
	reply             measure.Reply
	finish            chat.Finish
	unanswered        bool
	malformed         bool
	writeErr, callErr error
	thought           thought
	transcript        *chat.Transcript
	unproven          *unproven
}

func (s served) evidence(end ending, a attempt, g ChatGrant) measure.Evidence {
	c, r := a.call, a.route
	attachments, attachmentBytes, err := c.Attachments()
	if err != nil {
		attachments, attachmentBytes = 0, 0
	}
	return measure.Evidence{
		Outcome:            end.outcome(),
		Cut:                end.cut(),
		Unsent:             errors.Is(s.callErr, upstream.ErrNotSent),
		Upstream:           s.reported,
		PromptBytes:        c.Size() - attachmentBytes,
		Attachments:        attachments,
		PromptBound:        a.promptBound,
		Budgeted:           g.Budgeted,
		Reply:              s.reply,
		Finish:             s.finish,
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

func (r chatRoute) tokensAfterFirstByte(u chat.Usage) int {
	u = u.Normalized()
	if r.SilentWhileReasoning {
		return u.CompletionTokens - u.ReasoningTokens
	}
	return u.CompletionTokens
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
	return served{reported: reported, attempts: attempts, reply: measure.Streamed{Events: sw.delivered, VisibleBytes: sw.visible}, finish: sw.finish, unanswered: unanswered(sw.finish, sw.sent), malformed: sw.calls.Malformed(sw.finish, c.Stops()), writeErr: sw.err, callErr: err, thought: clock.thought()}
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
	var calls chat.ToolCalls
	if d.ToolCalled {
		calls.Add(body)
	}
	return served{reported: tokens, attempts: attempts, reply: measure.Buffered{Bytes: int(written)}, finish: d.Finish, unanswered: unanswered(d.Finish, d.Delivered()), malformed: calls.Malformed(d.Finish, c.Stops()), writeErr: writeErr}
}
