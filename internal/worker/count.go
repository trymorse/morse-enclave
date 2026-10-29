package worker

import (
	"context"
	"errors"
	"expvar"
	"sync"
	"time"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/chat"
)

const (
	countBudget      = 2 * time.Second
	maxTranscript    = 4 << 20
	transcriptPerTok = 16
	concurrentCounts = 2
)

var countsSkipped = expvar.NewMap("counts_skipped")

func transcriptLimit(c chat.Call) int {
	return min(maxTranscript, max(c.OutputLimit, 1)*transcriptPerTok)
}

type counter func(ctx context.Context, text string) (int, error)

type pendingCount struct {
	route      string
	count      counter
	evidence   measure.Evidence
	call       chat.Call
	transcript *chat.Transcript
}

type counters struct {
	slots   chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	running sync.WaitGroup
}

func (c *counters) init(slots int) {
	if slots == 0 {
		slots = concurrentCounts
	}
	c.slots = make(chan struct{}, slots)
	c.ctx, c.cancel = context.WithCancel(context.Background())
}

func (w *InProcess) Drain() {
	w.mu.Lock()
	w.counters.cancel()
	w.mu.Unlock()
	w.counters.running.Wait()
}

// The drain cancels under the lock and a new count checks for it under the lock, because a WaitGroup forbids an
// Add once Wait may be running on a zero count.
func (w *InProcess) counts(h Handle, work func(ctx context.Context) Count) <-chan Count {
	out := make(chan Count, 1)
	ctx, stop := context.WithCancel(context.Background())
	w.mu.Lock()
	if w.counters.ctx.Err() != nil {
		delete(w.opened, h)
		w.mu.Unlock()
		stop()
		countsSkipped.Add("draining", 1)
		close(out)
		return out
	}
	w.counters.running.Add(1)
	if e := w.opened[h]; e != nil {
		e.stopCount = stop
	}
	w.mu.Unlock()
	go func() {
		defer w.counters.running.Done()
		defer close(out)
		defer stop()
		out <- work(ctx)
	}()
	return out
}

func (w *InProcess) startCount(h Handle, p *pendingCount, f measure.RouteFigures) <-chan Count {
	return w.counts(h, func(ctx context.Context) Count {
		raw, ok := w.count(ctx, p)
		if !ok {
			return Count{}
		}
		e := p.evidence
		e.Counted = f.Counted(e, raw)
		return Count{Measurement: e.Measure(), Counted: true}
	})
}

func (w *InProcess) startSample(h Handle, p *pendingCount) <-chan Count {
	return w.counts(h, func(ctx context.Context) Count {
		var raw measure.RawCount
		if p.count != nil {
			var ok bool
			if raw, ok = w.count(ctx, p); !ok {
				return Count{}
			}
		}
		return Count{Samples: p.evidence.Samples(p.route, raw)}
	})
}

func (w *InProcess) count(ctx context.Context, p *pendingCount) (measure.RawCount, bool) {
	select {
	case w.counters.slots <- struct{}{}:
	default:
		countsSkipped.Add("busy", 1)
		return measure.RawCount{}, false
	}
	defer func() { <-w.counters.slots }()
	ctx, cancel := context.WithTimeout(ctx, countBudget)
	defer cancel()
	defer context.AfterFunc(w.counters.ctx, cancel)()
	raw, err := p.raw(ctx)
	switch {
	case err == nil:
		return raw, true
	case w.counters.ctx.Err() != nil:
		countsSkipped.Add("draining", 1)
	case errors.Is(err, context.DeadlineExceeded):
		countsSkipped.Add("timeout", 1)
	}
	return measure.RawCount{}, false
}

func (p *pendingCount) raw(ctx context.Context) (measure.RawCount, error) {
	var raw measure.RawCount
	sum := func(texts []string) (int, error) {
		n := 0
		for _, text := range texts {
			tokens, err := p.count(ctx, text)
			if err != nil {
				return 0, err
			}
			n += tokens
		}
		return n, nil
	}
	if texts, ok := p.call.PromptTexts(); ok {
		n, err := sum(texts)
		if err != nil {
			return measure.RawCount{}, err
		}
		raw.Prompt = n
	}
	n, err := sum(p.transcript.Texts())
	if err != nil {
		return measure.RawCount{}, err
	}
	raw.Visible = n
	return raw, nil
}
