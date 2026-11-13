package taskrun

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"morse/backend/internal/apierr"
	"morse/backend/internal/billing/measure"
	"morse/backend/internal/schedule"
	"morse/backend/internal/taskmode"
	"morse/backend/internal/taskseal"
)

const (
	taskID     = "0b7c4e1a-5d2f-4c8e-9a61-3f2d8e9b1c47"
	taskChatID = "5f3e2d1c-8b7a-4c69-9e5d-2a1b0c9d8e7f"
	taskRunID  = "e1a2b3c4-d5e6-4f70-8192-a3b4c5d6e7f8"
)

type countingOpener struct {
	mu     sync.Mutex
	opened int
	cut    []int
}

func (o *countingOpener) Open(*Step) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.opened++
	return o.opened, nil
}

func (o *countingOpener) Cut(a int, _ measure.Cut) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cut = append(o.cut, a)
}

func deviceKey(t *testing.T) PublicKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return PublicKey(k.PublicKey().Bytes())
}

func testBundle(t *testing.T) Bundle {
	return Bundle{
		V: BundleVersion, ID: taskID, Chat: taskChatID, Name: "Morning brief", Prompt: "Brief me.", Route: "chat-route",
		Mode: taskmode.Private, Notify: taskmode.Every, Schedule: schedule.Spec{Kind: schedule.Daily, Cron: "30 7 * * *", TZ: "UTC"},
		Keys: []PublicKey{deviceKey(t)},
	}
}

func testRun(t *testing.T, b Bundle, o *countingOpener) *Run[int] {
	t.Helper()
	task, _ := ParseID(b.ID)
	run, _ := ParseID(taskRunID)
	now := time.Unix(1793020570, 0)
	return New(Spec{
		Bundle: b, Task: task, Run: run, Key: taskseal.NewKey(), Floors: &Floors{},
		Now: func() time.Time { return now }, Life: RunLife,
	}, Opener[int](o))
}

func TestOnlyTheStepARunIssuedLastAndHasNotRunMayStart(t *testing.T) {
	r := testRun(t, testBundle(t), &countingOpener{})
	if _, err := r.Start(); err != nil {
		t.Fatal(err)
	}
	current := r.step
	if current.again().Start() {
		t.Error("a step the run did not issue last started")
	}
	if !current.Start() {
		t.Fatal("the run's step did not start")
	}
	if current.Start() {
		t.Error("a step started twice")
	}
	if r.steps != 1 {
		t.Errorf("counted %d steps", r.steps)
	}
}

func TestARunThatEndedIssuesNoStepAndCutsTheOneInFlight(t *testing.T) {
	o := &countingOpener{}
	r := testRun(t, testBundle(t), o)
	first, err := r.Start()
	if err != nil {
		t.Fatal(err)
	}
	r.End(measure.CutByDeadline)
	r.End(measure.CutByDeadline)
	if len(o.cut) != 1 || o.cut[0] != first.Admission {
		t.Errorf("cut %v, want the first step's admission %d once", o.cut, first.Admission)
	}
	if _, err := r.Next(); err != apierr.ErrUnavailable {
		t.Errorf("an ended run's next step: %v", err)
	}
	if r.step.Start() {
		t.Error("an ended run's step started")
	}
}

func TestARunWhoseBundleNoLongerFitsWithItsLastStillDeliversItsResults(t *testing.T) {
	b := testBundle(t)
	b.System = strings.Repeat("x", taskseal.MaxBundleJSON)
	r := testRun(t, b, &countingOpener{})
	if _, err := r.Start(); err != nil {
		t.Fatal(err)
	}
	s := r.step
	if !s.Start() {
		t.Fatal("the pass did not start")
	}
	s.Ran(Got{served: true, status: 200, content: "done"})
	f, err := r.Finish()
	if err != nil || f.Outcome != OK || len(f.Results) != len(b.Keys) || len(f.Previews) != len(b.Keys) || f.Bundle != nil {
		t.Fatalf("finished %+v, %v, want ok with a result and a preview for each key and no bundle", f, err)
	}
}

func TestEachReservationOfOneTaskGetsItsOwnRevision(t *testing.T) {
	var floors Floors
	task := ID{1}
	const n = 64
	revs := make(chan int64, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			rev, _ := floors.Reserve(task, 0)
			revs <- rev
		})
	}
	wg.Wait()
	close(revs)
	seen := map[int64]bool{}
	for rev := range revs {
		if seen[rev] || rev < 1 || rev > n {
			t.Errorf("revision %d reserved twice or out of 1 to %d", rev, n)
		}
		seen[rev] = true
	}
	if _, ok := floors.reserve(task, n-1, true); ok {
		t.Error("a finish of a run opened below the floor reserved a revision")
	}
}

func TestNoChangeIsReadFromTheAnswersFirstLineAlone(t *testing.T) {
	for _, c := range []struct {
		answer, rest string
		unchanged    bool
	}{
		{"NO_CHANGE", "", true},
		{"NO_CHANGE\nPrices held at $1,999.", "Prices held at $1,999.", true},
		{"\n  NO_CHANGE  \r\n\n  The second card is still $899.\n", "The second card is still $899.", true},
		{"NO_CHANGE.", "", false},
		{"**NO_CHANGE**", "", false},
		{"No change: NO_CHANGE", "", false},
		{"no_change", "", false},
		{"NO_CHANGE but the first card dropped to $1,899.", "", false},
		{"The first card dropped.\nNO_CHANGE", "", false},
	} {
		rest, unchanged := noChange(c.answer)
		if unchanged != c.unchanged || rest != c.rest {
			t.Errorf("%q reads as unchanged %t with %q, want %t with %q", c.answer, unchanged, rest, c.unchanged, c.rest)
		}
	}
}

func TestAPreviewWhoseJSONWouldOverflowItsEnvelopeIsCutShorter(t *testing.T) {
	b := Bundle{ID: taskID, Chat: taskChatID, Name: strings.Repeat(" ", MaxNameRunes)}
	data := previewOf(b, taskRunID, strings.Repeat(" x", 600))
	var p Preview
	if err := json.Unmarshal(data, &p); err != nil || len(data) > taskseal.MaxPreviewJSON || !strings.HasSuffix(p.Body, "…") {
		t.Fatalf("%d bytes: %s (%v)", len(data), data, err)
	}
	if one := previewOf(b, taskRunID, "short  and\n\tspaced "); !strings.Contains(string(one), `"body":"short and spaced"`) {
		t.Errorf("a short answer's preview is %s", one)
	}
}

func TestAPreviewIsCutToSixHundredRunesEvenWhenItsJSONWouldFit(t *testing.T) {
	b := Bundle{ID: taskID, Chat: taskChatID, Name: "Morning brief"}
	var p Preview
	if err := json.Unmarshal(previewOf(b, taskRunID, strings.Repeat("ab ", 300)), &p); err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(p.Body); n != MaxPreviewRunes || !strings.HasSuffix(p.Body, "b…") {
		t.Errorf("the preview is %d runes ending %q", n, p.Body[len(p.Body)-8:])
	}
	if err := json.Unmarshal(previewOf(b, taskRunID, strings.Repeat("x", MaxPreviewRunes)), &p); err != nil || utf8.RuneCountInString(p.Body) != MaxPreviewRunes || strings.HasSuffix(p.Body, "…") {
		t.Errorf("a preview of exactly %d runes is cut: %d runes", MaxPreviewRunes, utf8.RuneCountInString(p.Body))
	}
}

func contentDelta(text string) string {
	content, _ := json.Marshal(text)
	return `{"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":` + string(content) + `}}]}`
}

func toolCallDelta(index int, id, name, args string) string {
	a, _ := json.Marshal(args)
	return fmt.Sprintf(`{"id":"c","choices":[{"index":0,"delta":{"tool_calls":[{"index":%d,"id":%q,"type":"function","function":{"name":%q,"arguments":%s}}]}}]}`, index, id, name, a)
}

func finishChunk(reason string) string {
	return `{"id":"c","choices":[{"index":0,"delta":{},"finish_reason":"` + reason + `"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`
}

func TestTheStepsCaptureReadsAStreamWhateverWritesItIsCutInto(t *testing.T) {
	c := NewCapture(true)
	c.Header().Set("Content-Type", "text/event-stream")
	stream := strings.Join([]string{
		": keepalive\n\n",
		"data: " + contentDelta("Hel") + "\n\n",
		"data: " + contentDelta("lo") + "\n\n",
		"data: " + toolCallDelta(0, "call_a", "web_search", `{"que`) + "\n\n",
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ries\":[\"x\"]}"}}]}}]}` + "\n\n",
		`data: {"choices":[{"index":0,"delta":{"tool_calls":[{"id":"call_b","function":{"name":"read_page","arguments":{"url":"https://a.example/"}}}]}}]}` + "\n\n",
		`data: {"choices":[{"index":1,"delta":{"content":"another choice"}}]}` + "\n\n",
		"data: " + finishChunk("tool_calls") + "\n\n",
		"data: [DONE]\n\n",
	}, "")
	for i := 0; i < len(stream); i += 7 {
		c.Write([]byte(stream[i:min(i+7, len(stream))]))
	}
	g := c.Got(true)
	if !g.served || g.content != "Hello" || g.finish != "tool_calls" || len(g.calls) != 2 {
		t.Fatalf("read %+v", g)
	}
	if a := g.calls[0]; a.id != "call_a" || a.name != "web_search" || string(a.args) != `{"queries":["x"]}` {
		t.Errorf("the first call reads %+v", a)
	}
	if b := g.calls[1]; b.id != "call_b" || b.name != "read_page" || string(b.args) != `{"url":"https://a.example/"}` {
		t.Errorf("the second call reads %+v (args %s)", b, b.args)
	}
	failed := NewCapture(true)
	failed.Header().Set("Content-Type", "text/event-stream")
	failed.Write([]byte("data: " + contentDelta("partial") + "\n\ndata: " + string(apierr.ErrUpstream.Envelope()) + "\n\n"))
	if g := failed.Got(true); g.served || g.code != "upstream_error" || g.content != "" {
		t.Errorf("a stream that failed after it began reads %+v", g)
	}
}

func TestAChatPassTheVendorAnsweredWholeIsReadToo(t *testing.T) {
	c := NewCapture(true)
	c.Header().Set("Content-Type", "application/json")
	c.WriteHeader(200)
	c.Write([]byte(`{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"Whole answer"},"finish_reason":"stop"}]}`))
	if g := c.Got(true); !g.served || g.content != "Whole answer" || g.finish != "stop" {
		t.Errorf("read %+v", g)
	}
	reply := httptest.NewRecorder()
	c.Answer(reply)
	if reply.Code != 200 || reply.Body.String() != "{}" {
		t.Errorf("answered the relay %d %q, want 200 {}", reply.Code, reply.Body.String())
	}
}
