package worker

import (
	"context"
	"errors"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
)

// errAtLimit is what a limitCut returns from emit to stop its call: the provider stops reading and closes the upstream
// connection as it returns.
var errAtLimit = errors.New("worker: the reply reached its output limit")

// A limitCut ends a reply at the call's output limit on a host that generates past the limit it is sent
// (IgnoresOutputLimit). It counts what the client is shown, reasoning and tool arguments as well as text, because a
// hold reserves the limit for the whole completion: a host that honors max_completion_tokens counts reasoning against
// it too. A chunk that would take the count past the limit is not sent. The reply ends there with finish_reason
// "length", and the call's context stays live, so the cut is no client's and the reply completed.
//
// The route's tokenizer counts when it has one, and BytesEstimate when it has none, which counts at least as many
// tokens as the host does. Neither sees the tokens a host generates and does not show, such as the marker that ends
// its reasoning, so the host may run a few tokens past the limit. measure.Evidence.AtLimit bills at most the limit.
type limitCut struct {
	ctx         context.Context
	count       func(context.Context, string) (int, error)
	limit, used int
	reached     bool
	finished    bool
}

// newLimitCut is the cut for call c on route r, or nil for a host that honors the limit it is sent.
func newLimitCut(ctx context.Context, r chatRoute, c chat.Call) *limitCut {
	if !r.IgnoresOutputLimit {
		return nil
	}
	l := &limitCut{ctx: ctx, limit: c.OutputLimit}
	if r.Counter != nil {
		l.count = r.Counter.Count
	}
	return l
}

func (l *limitCut) wrap(emit func(chat.Chunk) error) func(chat.Chunk) error {
	if l == nil {
		return emit
	}
	return func(c chat.Chunk) error {
		d := c.Delta()
		n := l.tokens(d)
		if l.finished && n == 0 {
			return emit(c)
		}
		if l.used+n > l.limit {
			return l.end(emit, c)
		}
		if err := emit(c); err != nil {
			return err
		}
		l.used += n
		if d.Finish != chat.FinishNone {
			l.finished = true
			return nil
		}
		if l.used >= l.limit {
			return l.end(emit, c)
		}
		return nil
	}
}

func (l *limitCut) end(emit func(chat.Chunk) error, c chat.Chunk) error {
	l.reached = true
	if l.finished {
		return errAtLimit
	}
	if err := emit(c.Ending(chat.FinishLength)); err != nil {
		return err
	}
	return errAtLimit
}

func (l *limitCut) tokens(d chat.Delta) int {
	n := 0
	for _, text := range []string{d.Content, d.Reasoning, d.ToolArguments} {
		if text != "" {
			n += l.tokensOf(text)
		}
	}
	return n
}

func (l *limitCut) tokensOf(text string) int {
	if l.count != nil {
		if n, err := l.count(l.ctx, text); err == nil {
			return max(n, 1)
		}
	}
	return measure.BytesEstimate(len(text))
}

// atLimit is whether the cut ended the reply.
func (l *limitCut) atLimit() bool { return l != nil && l.reached }

// stopped takes the errAtLimit that stopped a call as the success it is.
func stopped(err error) error {
	if errors.Is(err, errAtLimit) {
		return nil
	}
	return err
}

// whole is call c's reply as one body. On a host that ignores the limit only a stream can be ended at it, so the call
// streams from the host and its chunks are joined into the reply the host would have sent whole.
func whole(ctx context.Context, prov chat.BusyRetry, c chat.Call, cut *limitCut) (chat.Chunk, chat.Usage, chat.Attempts, error) {
	if cut == nil {
		return prov.Complete(ctx, c)
	}
	streamed := *c.Request
	streamed.Stream, streamed.IncludeUsage = true, true
	c.Request = &streamed
	var chunks []chat.Chunk
	usage, attempts, err := prov.Stream(ctx, c, cut.wrap(func(ch chat.Chunk) error {
		chunks = append(chunks, ch)
		return nil
	}))
	if err = stopped(err); err != nil {
		return chat.Chunk{}, usage, attempts, err
	}
	body, err := openaicompat.Whole(chunks)
	return body, usage, attempts, err
}
