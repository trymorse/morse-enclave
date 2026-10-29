package worker

import (
	"context"
	"testing"
	"time"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/chat"
)

func newWorker(t *testing.T) *InProcess {
	t.Helper()
	w, err := NewInProcess(Config{})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func blockedUntil(release chan struct{}) counter {
	return func(ctx context.Context, _ string) (int, error) {
		select {
		case <-release:
			return 1, nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
}

func pendingCountOf(t *testing.T, count counter) *pendingCount {
	t.Helper()
	return &pendingCount{route: "m", count: count, call: chat.Call{Request: parsed(t, completeBody(""))}, transcript: chat.NewTranscript(1 << 10)}
}

func TestACountThatOutrunsItsBudgetOrMeetsADrainGivesUpAndFreesTheCallerAndItsSlotAtOnce(t *testing.T) {
	for name, stop := range map[string]func(w *InProcess, ctx context.Context) context.Context{
		"budget": func(_ *InProcess, ctx context.Context) context.Context {
			ctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
			t.Cleanup(cancel)
			return ctx
		},
		"drain": func(w *InProcess, ctx context.Context) context.Context {
			go w.Drain()
			return ctx
		},
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorker(t)
			release := make(chan struct{})
			defer close(release)
			p := pendingCountOf(t, blockedUntil(release))
			ctx := stop(w, context.Background())
			start := time.Now()
			if counted, ok := w.count(ctx, p); ok {
				t.Errorf("counted %+v, want the count abandoned", counted)
			}
			if took := time.Since(start); took >= countBudget {
				t.Errorf("the count waited %v, want it ended before the budget", took)
			}
			if held := len(w.counters.slots); held != 0 {
				t.Errorf("%d counting slots still held after the count gave up, want the slot back before the tokenizer finishes", held)
			}
		})
	}
}

func TestADrainIsNotHeldUpByASampleStillCounting(t *testing.T) {
	w := newWorker(t)
	release := make(chan struct{})
	defer close(release)
	p := pendingCountOf(t, blockedUntil(release))
	p.evidence.Outcome = measure.Completed
	w.startSample(Handle{}, p)
	start := time.Now()
	w.Drain()
	if took := time.Since(start); took > time.Second {
		t.Errorf("the drain waited %v on a sample's count, want it to cut the count and finish within its window", took)
	}
	if held := len(w.counters.slots); held != 0 {
		t.Errorf("%d counting slots still held after the drain, want the sample's slot back", held)
	}
}

func TestACountThatWouldStartAfterTheDrainIsRefusedAndItsHandleForgotten(t *testing.T) {
	w := newWorker(t)
	w.Drain()
	handle := w.keep(Opening{}, nil)
	release := make(chan struct{})
	defer close(release)
	if c, ok := <-w.startSample(handle, pendingCountOf(t, blockedUntil(release))); ok {
		t.Errorf("counted %+v, want the count refused with nothing sent", c)
	}
	w.mu.Lock()
	_, kept := w.opened[handle]
	w.mu.Unlock()
	if kept {
		t.Error("the refused count's handle is still open, want it forgotten")
	}
}

func TestACountStartedWhileEverySlotIsBusyAnswersUncountedAtOnce(t *testing.T) {
	w := newWorker(t)
	for range concurrentCounts {
		w.counters.slots <- struct{}{}
	}
	release := make(chan struct{})
	defer close(release)
	handle := w.keep(Opening{}, nil)
	start := time.Now()
	c, ok := <-w.startCount(handle, pendingCountOf(t, blockedUntil(release)), measure.RouteFigures{})
	if !ok || c.Counted {
		t.Errorf("count %+v ok %t, want an uncounted answer", c, ok)
	}
	if took := time.Since(start); took >= countBudget {
		t.Errorf("the count waited %v for a slot, want it to give up at once", took)
	}
}
