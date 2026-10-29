package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/billing/money"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/health"
	"morse/backend/internal/jobs"
	"morse/backend/internal/media"
	"morse/backend/internal/nitro"
	"morse/backend/internal/seal"
)

type queuedVideos struct{}

func (queuedVideos) ResolveVideo(req media.VideoRequest) (media.VideoRequest, error) {
	return (media.VideoSpec{MinSeconds: 1, MaxSeconds: 15, Resolutions: []string{"480p"}}).ResolveVideo(req)
}

func (queuedVideos) SubmitVideo(context.Context, *media.VideoRequest, media.Submission) (media.Submitted, error) {
	return media.Submitted{VendorID: "vendor-task"}, nil
}

func (queuedVideos) PollVideo(context.Context, string) (jobs.Poll, error) { return jobs.Poll{}, nil }

func (queuedVideos) OpenVideo(context.Context, media.Output) (io.ReadCloser, int64, error) {
	return nil, 0, errors.New("no content")
}

func overTheWire(t *testing.T, models map[string]Model) *Client {
	t.Helper()
	inner, err := NewInProcess(Config{Models: models})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(inner, "routes"))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, srv.Client())
}

type watchedReply struct {
	*httptest.ResponseRecorder
	mu      sync.Mutex
	written bool
}

func (w *watchedReply) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.written = true
	w.mu.Unlock()
	return w.ResponseRecorder.Write(p)
}

func (w *watchedReply) wrote() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.written
}

func TestAJobsReplyReachesTheRelayOnlyAfterTheRelayStoredTheJob(t *testing.T) {
	c := overTheWire(t, map[string]Model{"vid": {Tier: catalog.Private, Serves: Videos{queuedVideos{}}}})
	admitted, err := c.Open(context.Background(), Opening{Method: http.MethodPost, Path: "/v1/videos", Body: strings.NewReader(`{"model":"vid","prompt":"p","seconds":5}`)})
	if err != nil {
		t.Fatal(err)
	}
	reply := &watchedReply{ResponseRecorder: httptest.NewRecorder()}
	var stored string
	g := JobGrant{ID: "video_1", CreatedAt: time.Unix(1_792_216_730, 0), Deadline: time.Now().Add(time.Hour)}
	m := c.Submit(context.Background(), admitted.Handle(), g, reply, func(sub media.Submitted) {
		if reply.wrote() {
			t.Error("the reply reached the relay before the relay stored the job")
		}
		time.Sleep(20 * time.Millisecond)
		stored = sub.VendorID
	})
	if stored != "vendor-task" || !m.Served || reply.Code != http.StatusOK || !strings.Contains(reply.Body.String(), `"id":"video_1"`) {
		t.Errorf("stored %q, measured %+v, replied %d %s; want the vendor id stored and the queued view after it", stored, m, reply.Code, reply.Body)
	}
}

func TestAWorkerThatRefusesTheCallWithAReplyOfItsOwnAnswersUnavailableLikeAHandleItCannotRun(t *testing.T) {
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apierr.WriteError(w, apierr.ErrInvalidBody)
	}))
	t.Cleanup(refusing.Close)
	c := NewClient(refusing.URL, refusing.Client())
	reply := httptest.NewRecorder()
	m := c.Run(context.Background(), Handle{1}, ChatGrant{}, reply)
	if m.Served || m.Outcome != measure.Failed || m.Health.Outcome != health.UpstreamUnavailable || reply.Code != http.StatusServiceUnavailable {
		t.Errorf("measured %+v and replied %d, want it refused unserved", m, reply.Code)
	}
}

func TestAWorkerThatNeverAnswersTheCallAbortsTheRelaysHandlerSoTheRelaySettlesAtTheHold(t *testing.T) {
	unreachable := httptest.NewServer(http.NotFoundHandler())
	unreachable.Close()
	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Errorf("recovered %v, want http.ErrAbortHandler", recovered)
		}
	}()
	NewClient(unreachable.URL, unreachable.Client()).Run(context.Background(), Handle{1}, ChatGrant{}, httptest.NewRecorder())
	t.Error("a run no worker answered returned a measurement")
}

func TestARunThatEndsWithoutATrailerAbortsTheRelaysHandlerSoTheRelaySettlesAtTheHold(t *testing.T) {
	worker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", headerMeasured)
		io.WriteString(w, "data: partial\n\n")
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}))
	t.Cleanup(worker.Close)
	c := NewClient(worker.URL, worker.Client())
	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Errorf("recovered %v, want http.ErrAbortHandler", recovered)
		}
	}()
	c.Run(context.Background(), Handle{1}, ChatGrant{}, httptest.NewRecorder())
	t.Error("a run with no trailer returned a measurement")
}

func TestAnOpenedRequestRunsOnceOverTheWire(t *testing.T) {
	c := overTheWire(t, map[string]Model{"vid": {Tier: catalog.Private, Serves: Videos{queuedVideos{}}}})
	admitted, err := c.Open(context.Background(), Opening{Method: http.MethodPost, Path: "/v1/videos", Body: strings.NewReader(`{"model":"vid","prompt":"p","seconds":5}`)})
	if err != nil {
		t.Fatal(err)
	}
	g := JobGrant{ID: "video_1", Deadline: time.Now().Add(time.Hour)}
	accepted := func(media.Submitted) {}
	c.Submit(context.Background(), admitted.Handle(), g, httptest.NewRecorder(), accepted)
	again := httptest.NewRecorder()
	if m := c.Submit(context.Background(), admitted.Handle(), g, again, accepted); m.Served || m.Outcome != measure.Failed || again.Code != http.StatusServiceUnavailable {
		t.Errorf("a second run measured %+v and replied %d, want it refused unserved", m, again.Code)
	}
}

func TestEveryEnumerationOnTheWireCrossesByNameAndComesBackUnchanged(t *testing.T) {
	m := Measured{Measurement: measure.Measurement{Outcome: measure.Rejected, Sides: measure.Sides{Prompt: measure.MethodCounted, Completion: measure.MethodReplyBytes, Hidden: measure.MethodThinkingTime}},
		Cut: measure.CutByProxy, Health: health.Observation{Path: health.PathCompact, Outcome: health.Shutdown}}
	c := Count{Samples: []measure.Sample{{Route: "m", Figure: measure.FigureThinkingRate, Value: 2.5}}}
	p := jobs.Poll{Status: jobs.Running, Failure: jobs.Timeout}
	g := ResearchReadGrant{Status: jobs.Failed}
	for name, v := range map[string]struct {
		value any
		names []string
	}{
		"measured": {m, []string{`"rejected"`, `"counted"`, `"reply_bytes"`, `"thinking_time"`, `"proxy"`, `"compact"`, `"shutdown"`}},
		"count":    {c, []string{`"thinking_rate"`}},
		"poll":     {p, []string{`"running"`, `"timeout"`}},
		"grant":    {g, []string{`"failed"`, `"Failure":""`}},
	} {
		data, err := json.Marshal(v.value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, want := range v.names {
			if !strings.Contains(string(data), want) {
				t.Errorf("%s crossed as %s, want %s in it", name, data, want)
			}
		}
		back := reflect.New(reflect.TypeOf(v.value))
		if err := json.Unmarshal(data, back.Interface()); err != nil || !reflect.DeepEqual(back.Elem().Interface(), v.value) {
			t.Errorf("%s came back as %+v, %v; want %+v", name, back.Elem().Interface(), err, v.value)
		}
	}
	var unknown Measured
	if err := json.Unmarshal([]byte(`{"Outcome":"ascended"}`), &unknown); err == nil {
		t.Error("an outcome this tree does not name was read as a number instead of refused")
	}
	unlisted := jobs.Poll{Status: jobs.Failed, Failure: jobs.Timeout + 1}
	data, _ := json.Marshal(unlisted)
	var back jobs.Poll
	if err := json.Unmarshal(data, &back); err != nil || back != unlisted {
		t.Errorf("a failure code this build does not list crossed as %s and came back %+v, %v; want it kept", data, back, err)
	}
}

type countedVideos struct {
	queuedVideos
	submits *int
}

func (v countedVideos) SubmitVideo(ctx context.Context, req *media.VideoRequest, s media.Submission) (media.Submitted, error) {
	*v.submits++
	return v.queuedVideos.SubmitVideo(ctx, req, s)
}

func TestARunWithAnotherFamilysGrantIsRefusedUnserved(t *testing.T) {
	var submits int
	w, err := NewInProcess(Config{Models: map[string]Model{
		"m":   {Tier: catalog.Private, Serves: Chat{Upstream: Plain{Provider: panickingProvider{}}}},
		"vid": {Tier: catalog.Private, Serves: Videos{countedVideos{submits: &submits}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	submitted := func(sub media.Submitted) { t.Errorf("the relay was handed %+v for a chat", sub) }
	for _, c := range []struct {
		path, body string
		run        func(h Handle, reply http.ResponseWriter) Measured
	}{
		{"/v1/chat/completions", streamBody(""), func(h Handle, reply http.ResponseWriter) Measured {
			return w.Submit(context.Background(), h, JobGrant{ID: "video_1"}, reply, submitted)
		}},
		{"/v1/videos", `{"model":"vid","prompt":"p","seconds":5}`, func(h Handle, reply http.ResponseWriter) Measured {
			return w.Run(context.Background(), h, ChatGrant{OutputLimit: 10}, reply)
		}},
		{"/v1/videos", `{"model":"vid","prompt":"p","seconds":5}`, func(h Handle, reply http.ResponseWriter) Measured {
			return w.Run(context.Background(), h, MediaGrant{Units: 1}, reply)
		}},
	} {
		admitted, err := w.Open(context.Background(), Opening{Method: http.MethodPost, Path: c.path, Body: strings.NewReader(c.body)})
		if err != nil {
			t.Fatal(err)
		}
		reply := httptest.NewRecorder()
		if m := c.run(admitted.Handle(), reply); m.Served || m.Outcome != measure.Failed || reply.Code != http.StatusServiceUnavailable {
			t.Errorf("%s run under another family's grant: measured %+v and replied %d, want it refused unserved", c.path, m, reply.Code)
		}
	}
	if submits != 0 {
		t.Errorf("the vendor took %d submissions", submits)
	}
}

func TestAPlainOpenNeverOpensASealedBodyWhateverItsContentType(t *testing.T) {
	id, err := seal.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	inner, err := NewInProcess(Config{Models: map[string]Model{"vid": {Tier: catalog.Private, Serves: Videos{queuedVideos{}}}}, Sealing: Sealing{Identity: id, Attester: nitro.Dev{}, Environment: "dev"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(NewServer(inner, "routes"))
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL, srv.Client())
	sealedVideo := func() []byte {
		sealed, _, err := seal.Seal([][]byte{id.PublicKey()}, seal.Head{Method: http.MethodPost, Path: "/v1/videos", Headers: map[string]string{"Content-Type": "application/json"}, TS: time.Now().Unix()}, []byte(`{"model":"vid","prompt":"p","seconds":5}`))
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	header := ContentHeaders(http.Header{"Content-Type": {SealedContentType}})
	if admitted, err := c.Open(context.Background(), Opening{Method: http.MethodPost, Path: "/v1/chat/completions", Header: header, Body: bytes.NewReader(sealedVideo())}); err == nil {
		t.Errorf("a plain open of /v1/chat/completions admitted %T %+v from a sealed /v1/videos", admitted, admitted)
	}
	if opened, err := c.OpenSealed(context.Background(), SealedOpening{Body: sealedVideo()}); err != nil || opened.Pattern != "POST /v1/videos" {
		t.Errorf("a sealed /v1/videos opened sealed: %+v %v, want POST /v1/videos", opened, err)
	}
}

const relayedBody = "data: hi\n\n"

func workerSending(t *testing.T, sent Measured, edit func(trailer map[string]any)) *Client {
	t.Helper()
	data, err := json.Marshal(sent)
	if err != nil {
		t.Fatal(err)
	}
	var trailer map[string]any
	if err := json.Unmarshal(data, &trailer); err != nil {
		t.Fatal(err)
	}
	edit(trailer)
	if data, err = json.Marshal(trailer); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/run":
			w.Header().Set("Trailer", headerMeasured)
			io.WriteString(w, relayedBody)
			w.Header().Set(headerMeasured, string(data))
		case "/count":
			json.NewEncoder(w).Encode(Count{Counted: true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL, srv.Client())
}

func billedRun() Measured {
	return Measured{
		Measurement: measure.Measurement{Outcome: measure.Completed, Tokens: chat.Usage{PromptTokens: 9, CompletionTokens: 2}},
		Cut:         measure.CutByClient, Served: true, Delivered: 3, Cost: money.ReportedCost(640),
		Health: health.Observation{Outcome: health.OK, Duration: time.Second, Retries: 1}, Follow: FollowCount,
	}
}

func TestARelayReadsATrailerWhoseHealthOutcomeItDoesNotKnowWithItsBillingAndNoHealthSample(t *testing.T) {
	sent := billedRun()
	c := workerSending(t, sent, func(trailer map[string]any) { trailer["Health"].(map[string]any)["Outcome"] = "a_later_outcome" })
	reply := httptest.NewRecorder()
	m := c.Run(context.Background(), Handle{1}, ChatGrant{}, reply)
	counted := <-m.Counted
	m.Counted = nil
	want := sent
	want.Health, want.Unsampled = health.Observation{}, true
	if reply.Body.String() != relayedBody || !reflect.DeepEqual(m, want) || !counted.Counted {
		t.Errorf("relayed %q, measured %+v and counted %+v; want the body, %+v, and the count", reply.Body, m, counted, want)
	}
}

func TestARelayAbortsOnATrailerWhoseCutItDoesNotKnow(t *testing.T) {
	c := workerSending(t, billedRun(), func(trailer map[string]any) { trailer["Cut"] = "sideways" })
	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Errorf("recovered %v, want http.ErrAbortHandler", recovered)
		}
	}()
	c.Run(context.Background(), Handle{1}, ChatGrant{}, httptest.NewRecorder())
	t.Error("a trailer with a cut this tree does not name returned a measurement")
}

func TestEveryKindOnTheWireHasADecoder(t *testing.T) {
	for _, k := range admissionKindNames.Values() {
		if admissionOfKind[k] == nil {
			t.Errorf("admission kind %s has no decoder", admissionKindNames.String(k))
		}
	}
	for _, k := range grantKindNames.Values() {
		if grantOfKind[k] == nil {
			t.Errorf("grant kind %s has no decoder", grantKindNames.String(k))
		}
	}
}

func TestTheOpeningCrossesTheWireWithItsNSFWPromptsNamed(t *testing.T) {
	cast := chat.NewCast([]chat.PromptHash{chat.HashPrompt("noah", "You are Noah, NSFW.", true), chat.HashPrompt("noah", "You are Noah.", false)}, "Rules {name}.")
	launch := &chat.Launch{ID: "noah", Prompt: "You are Noah."}
	writing := &chat.Writing{Examples: []chat.Example{{Launch: *launch, Name: "Noah"}}}
	header := http.Header{}
	setOpening(header, cast, launch, writing)
	got, err := openingOf(header)
	want := openingWire{Prompts: cast.Prompts(), Rules: cast.Rules(), Launch: launch, Writing: writing}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("the opening came back as %+v (%v), want %+v", got, err, want)
	}
}

func TestAnOpeningWithALaunchOrAnExampleThatNamesNoCharacterIsMalformed(t *testing.T) {
	for _, o := range []struct {
		launch  *chat.Launch
		writing *chat.Writing
	}{
		{launch: &chat.Launch{Prompt: "You are Noah."}},
		{writing: &chat.Writing{Examples: []chat.Example{{Launch: chat.Launch{Prompt: "You are Noah."}}}}},
	} {
		header := http.Header{}
		setOpening(header, chat.Cast{}, o.launch, o.writing)
		if _, err := openingOf(header); err == nil {
			t.Errorf("an opening of %+v %+v was taken", o.launch, o.writing)
		}
	}
}
