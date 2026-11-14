package worker

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
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
	"morse/backend/internal/dialect"
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
	IgnoresOutputLimit   bool
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
	return chatRoute{ChatTerms: c.ChatTerms, Upstream: c.Upstream, Reasoning: c.Reasoning, ReasoningUncapped: c.ReasoningUncapped, SilentWhileReasoning: c.SilentWhileReasoning, IgnoresOutputLimit: c.IgnoresOutputLimit, Counter: c.Counter, model: model, endpoint: vendor.Endpoint, attester: vendor.Attester, speaks: c.Upstream.Speaks(), tier: vendor.Tier, retention: vendor.Retention, order: vendor.Order}
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
	// veil is set on a chat that asked for the Privacy Veil, from /open until its run ends, and veilMeasure once it ran.
	veil        *openedVeil
	veilMeasure *VeilMeasure
	dialect     dialect.Dialect
	reply       func() dialect.Encoder
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

func (w *InProcess) openChat(o Opening, d dialect.Dialect, compaction bool) (Admission, error) {
	p := protocolOf(o.Header.Get)
	reply := func() dialect.Encoder { return dialect.ChatCompletions{} }
	if !d.Native() {
		decoded, err := w.decode(o, p, d)
		if err != nil {
			return nil, err
		}
		o.Body, reply = bytes.NewReader(decoded.Body), decoded.Reply
	}
	req, err := requestOf(o.Body, p)
	if err != nil {
		return nil, err
	}
	name, known := w.chats[req.Model]
	if !known {
		return nil, apierr.ErrModelNotFound
	}
	veilAsk, err := w.veilAsk(o, p, req)
	if err != nil {
		return nil, err
	}
	var want providerAsk
	var wantErr error
	if p.scheme == nil {
		req = req.Without(privacyVeilField)
		want, wantErr = floorOf(req)
	}
	ask := askOf(p, o.KeyCaller, req)
	var digest affinity.Digest
	if o.inTheClear(ask) {
		digest = affinity.DigestOf(req)
	}
	routes, err := name.reach(p, ask, compaction, want, o.KeyFloor)
	if err != nil && ask == askLooksSealed {
		return nil, hintedHexOnly(err)
	}
	if err != nil {
		return nil, err
	}
	var settings []string
	switch {
	case p.scheme != nil:
		if err = sealedQuantizations(req, p); err != nil {
			return nil, err
		}
	case wantErr != nil:
		return nil, wantErr
	default:
		if routes, err = narrowed(routes, plaintextNarrowings(name, req, want, o, compaction, &settings)); err != nil {
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
	oc := &openedChat{cuts: newCuts(), routes: routes, first: route, protocol: p, call: chat.Call{Request: req, RouteEffort: route.DefaultReasoningEffort, Efforts: route.ReasoningEfforts, Settings: settings}, launch: o.Launch, own: o.Own, writing: o.Writing, dialect: d, reply: reply}
	if compaction {
		err = oc.compact(o.Cast)
	} else {
		err = route.Upstream.admit(oc, o.Cast)
	}
	if err == nil && route.onBehalf {
		err = unsealableRefusal(openaicompat.Unsealable(oc.call.Request))
	}
	if err == nil && veilAsk != nil {
		oc.veil, err = w.planVeil(o, *veilAsk, req)
	}
	if err != nil {
		return nil, err
	}
	admission := ChatAdmission{
		admitted: admitted{w.keep(o, oc)}, Model: name.model, Candidates: endpointsOf(routes), Affinity: digest, MaxPrice: want.maxPrice, Sealable: name.sealable(), OnBehalf: route.onBehalf,
		PromptSize: oc.call.Size(), PromptBytes: limits.KibibytesCovering(oc.promptBytes), TextMessages: textMessages(oc.call), PromptCounted: promptCounted(oc.call), OutputAsked: oc.asked,
		Stream: req.Stream, Compaction: compaction, Character: oc.character,
	}
	if oc.veil != nil {
		admission.PrivacyVeil = oc.veil.admission()
	}
	return admission, nil
}

// A narrowing cuts a request's routes to those that can serve it, and refuses the request when it leaves none.
type narrowing func([]chatRoute) ([]chatRoute, error)

// narrowed runs each narrowing on what the one before left, and stops at the first refusal.
func narrowed(routes []chatRoute, steps []narrowing) ([]chatRoute, error) {
	var err error
	for _, step := range steps {
		if routes, err = step(routes); err != nil {
			return nil, err
		}
	}
	return routes, nil
}

// keeping is the narrowing that, when it applies, keeps the routes keep admits and refuses with refuse(routes) when it
// keeps none.
func keeping(applies bool, keep func(chatRoute) bool, refuse func([]chatRoute) error) narrowing {
	return func(routes []chatRoute) ([]chatRoute, error) {
		if !applies {
			return routes, nil
		}
		kept := slices.DeleteFunc(slices.Clone(routes), func(r chatRoute) bool { return !keep(r) })
		if len(kept) == 0 {
			return nil, refuse(routes)
		}
		return kept, nil
	}
}

// plaintextNarrowings are the narrowings of a plaintext chat, in the order they refuse. The last three apply to a key's
// chat alone, and the first of them reads the call's settings into settings. A sealed chat is forwarded verbatim, so
// none applies to it.
func plaintextNarrowings(name chatName, req *chat.Request, want providerAsk, o Opening, compaction bool, settings *[]string) []narrowing {
	steps := []narrowing{
		func(routes []chatRoute) ([]chatRoute, error) { return name.atFloor(routes, want.floor) },
		withoutUnsealable(req),
		func(routes []chatRoute) ([]chatRoute, error) { return want.narrow(name, routes, o.KeyFloor) },
	}
	if o.KeyCaller && !compaction {
		steps = append(steps, func(routes []chatRoute) ([]chatRoute, error) {
			var err error
			if *settings, err = openaicompat.SettingsOf(req, o.KeySettings); err != nil {
				return nil, err
			}
			return forwardingSettings(*settings)(routes)
		}, takingTools(req), readingImages(req))
	}
	return steps
}

// forwardingSettings keeps the routes whose provider sends a call's settings to its host, or every route when the call
// has none, and refuses the call when no route sends them.
func forwardingSettings(settings []string) narrowing {
	return keeping(len(settings) > 0, func(r chatRoute) bool {
		plain, ok := r.Upstream.(Plain)
		_, forwards := plain.Provider.(openaicompat.SettingsForwarder)
		return ok && forwards
	}, func([]chatRoute) error { return openaicompat.SettingsRefusal(settings[0]) })
}

// takingTools keeps the routes that send a key's chat its tools when the chat lets the model call one, and refuses the
// chat when every route of its model is served without tools (tools false). Such a route drops a chat's tools, so the
// model would answer in prose a call it was asked to make, and an agent waiting on a tool call would never see one. A
// chat whose tool_choice is "none" lets the model call nothing, so its tools are dropped as before.
func takingTools(req *chat.Request) narrowing {
	return keeping(callsTools(req), func(r chatRoute) bool { return !r.NoTools }, func([]chatRoute) error { return toolsRefusal(req.Model) })
}

// callsTools is whether a chat lets the model call a tool: it offers tools, or names a tool_choice that makes the model
// call one, and its tool_choice is not "none". A tools or tool_choice of the wrong shape counts, and is refused later.
func callsTools(req *chat.Request) bool {
	var tools []json.RawMessage
	var choice json.RawMessage
	toolsErr := req.Decode("tools", &tools)
	req.Decode("tool_choice", &choice)
	switch string(choice) {
	case `"none"`:
		return false
	case "", "null", `"auto"`:
		return toolsErr != nil || len(tools) > 0
	}
	return true
}

func toolsRefusal(model string) error {
	return apierr.Invalid(http.StatusBadRequest, "unsupported_parameter",
		"tools is refused: "+model+" is served without tools (GET /v1/models lists it with tools false), so the model could call none of them. "+
			"Send the request without tools, with tool_choice \"none\", or to a model that takes tools.").Naming("tools")
}

// readingImages keeps the routes whose model reads images when a key's chat sends one, and refuses the chat, naming
// what the model reads, when none does: its host would refuse the image in words that name neither, or drop it.
func readingImages(req *chat.Request) narrowing {
	return keeping(sendsImage(req), func(r chatRoute) bool { return r.Inputs.Reads(catalog.ModalityImage) }, func(routes []chatRoute) error {
		return apierr.Invalid(http.StatusBadRequest, "unsupported_input",
			fmt.Sprintf("This request's messages carry an image, and %s reads %s only (its input_modalities in GET /v1/models). Send the request without image parts, or to a model whose input_modalities include image.", req.Model, routes[0].Inputs)).Naming("messages")
	})
}

func sendsImage(req *chat.Request) bool {
	msgs, err := req.Messages()
	if err != nil {
		return false
	}
	for _, m := range msgs {
		for _, p := range m.Parts() {
			if p.Type == "image_url" || p.ImageURL() != nil {
				return true
			}
		}
	}
	return false
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
	// veil restores this call's reply. The attempt takes it when the walk starts the try, so a try that outlives the
	// run never reads the chat's veil after the run drops it.
	veil *replyVeil
}

// attempt is the call on r. Only the last endpoint waits out a busy refusal, and only one whose hedge has no next
// endpoint to go to hedges in place.
func (o *openedChat) attempt(r chatRoute, g ChatGrant, last, hedgesInPlace bool) attempt {
	c := o.call
	c.RouteEffort, c.Efforts, c.OutputLimit = r.DefaultReasoningEffort, r.ReasoningEfforts, r.clamp(g.OutputLimit, o.asked)
	a := attempt{route: r, call: c, promptBound: g.PromptBound, veil: o.veil.reply()}
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
	rw := newReplyWriter(o.dialect.Errors(reply))
	if o.veil != nil {
		defer o.dropVeil()
		if m, failed := o.applyVeil(ctx, w, rw); failed {
			return m
		}
		ctx = upstream.WithEgress(ctx, o.veil.veil.Egress)
	}
	end := o.walk(ctx, w, granted, cg, rw)
	a, got, e, m := end.a, end.got, end.e, end.m
	if errors.Is(got.callErr, upstream.ErrEgressRefused) && rw.status == 0 {
		return o.egressRefused(w, rw, m)
	}
	unsent := got.callErr != nil && rw.status == 0
	m.Unserved = unsent && m.Cut == measure.NotCut && m.Health.Outcome.FailsOver() && m.Health.Outcome != health.Unattested && m.Health.Outcome != health.ContextOverflow
	if unsent {
		rw.Header().Del(HeaderPrivacyVeil)
		refuse(ctx, rw, got.callErr)
	}
	m.PrivacyVeil = o.veilMeasure
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
	errNoMessages              = apierr.InvalidParameter("messages must hold at least one message: a chat with none gives the model nothing to answer.").Naming("messages")
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
func withoutUnsealable(req *chat.Request) narrowing {
	err := openaicompat.Unsealable(req)
	return keeping(err != nil, func(r chatRoute) bool { return !r.seals }, func([]chatRoute) error { return unsealableRefusal(err) })
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
	if len(msgs) == 0 {
		return errNoMessages
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
	rv := a.veil
	cut := newLimitCut(ctx, a.route, a.call)
	encoder := o.reply()
	if a.call.Stream {
		got = stream(ctx, reply, http.NewResponseController(reply), retry, a.call, transcript, clock, w.keepaliveEvery, rv, cut, encoder)
	} else {
		got = complete(ctx, reply, retry, a.call, transcript, clock, rv, cut, encoder)
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
	atLimit           bool
}

func (s served) evidence(end ending, a attempt, g ChatGrant) measure.Evidence {
	c, r := a.call, a.route
	attachments, attachmentBytes, err := c.Attachments()
	if err != nil {
		attachments, attachmentBytes = 0, 0
	}
	return measure.Evidence{
		SealedWhole:        errors.Is(err, chat.ErrSealedBody),
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
		AtLimit:            s.atLimit,
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

func stream(ctx context.Context, w http.ResponseWriter, rc *http.ResponseController, prov chat.BusyRetry, c chat.Call, transcript *chat.Transcript, clock *thinkingClock, keepalive time.Duration, rv *replyVeil, cut *limitCut, encoder dialect.Encoder) served {
	sw := &sseWriter{eventStream: eventStream{w: w, rc: rc}, encoder: encoder, transcript: transcript, clock: clock, veil: rv}
	stop := func() {}
	if clock != nil {
		stop = sw.keepAlive(ctx, keepalive)
	}
	reported, attempts, err := prov.Stream(ctx, c, cut.wrap(sw.emit))
	stop()
	err = stopped(err)
	if err == nil && sw.empty() {
		err = errEmptyReply
	}
	switch {
	case err == nil:
		sw.closeVeil()
		sw.done(reported)
	case sw.started && ctx.Err() == nil && sw.err == nil:
		sw.closeVeil()
		sw.errorEvent()
	}
	return served{reported: reported, attempts: attempts, reply: measure.Streamed{Events: sw.delivered, VisibleBytes: sw.visible}, finish: sw.finish, unanswered: unanswered(sw.finish, sw.sent), malformed: sw.calls.Malformed(sw.finish, c.Stops()), writeErr: sw.err, callErr: err, thought: clock.thought(), atLimit: cut.atLimit()}
}

func complete(ctx context.Context, w http.ResponseWriter, prov chat.BusyRetry, c chat.Call, transcript *chat.Transcript, clock *thinkingClock, rv *replyVeil, cut *limitCut, encoder dialect.Encoder) served {
	clock.startAtCall()
	body, tokens, attempts, err := whole(ctx, prov, c, cut)
	if err != nil {
		return served{reported: tokens, attempts: attempts, reply: measure.Buffered{}, callErr: err, thought: clock.thought()}
	}
	w.Header().Set("Content-Type", "application/json")
	d := body.Delta()
	if unanswered(d.Finish, d.Delivered()) {
		body = body.MarkUnanswered()
	}
	var calls chat.ToolCalls
	if d.ToolCalled {
		calls.Add(body)
	}
	vendorBytes := len(chunkBytes(body))
	body = rv.complete(body)
	n, writeErr := w.Write(encoder.Whole(body, tokens))
	written := int64(n)
	if written > 0 {
		transcript.Add(d)
	}
	measured := int(written)
	if rv != nil && written > 0 {
		measured = vendorBytes
	}
	return served{reported: tokens, attempts: attempts, reply: measure.Buffered{Bytes: measured}, finish: d.Finish, unanswered: unanswered(d.Finish, d.Delivered()), malformed: calls.Malformed(d.Finish, c.Stops()), writeErr: writeErr, atLimit: cut.atLimit()}
}

var errDialectSealed = apierr.InvalidParameter("This route takes a plaintext request only. Send an end-to-end encrypted chat to POST /v1/chat/completions.")

func (w *InProcess) decode(o Opening, p protocol, d dialect.Dialect) (dialect.Decoded, error) {
	if p.scheme != nil || p.err != nil {
		return dialect.Decoded{}, errDialectSealed
	}
	raw, err := io.ReadAll(o.Body)
	if err != nil {
		return dialect.Decoded{}, contentRefusal(err)
	}
	decoded, err := d.Decode(raw, func(model string) bool {
		_, known := w.chats[model]
		return known
	})
	if err != nil {
		return dialect.Decoded{}, contentRefusal(err)
	}
	return decoded, nil
}
