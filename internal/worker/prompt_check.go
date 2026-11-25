package worker

import (
	"cmp"
	"context"
	"errors"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/promptcheck"
)

const (
	promptCheckTimeout  = 5 * time.Second
	promptCheckAttempts = 2
)

type PromptCheck struct {
	Scorer  promptcheck.Scorer
	Timeout time.Duration
	totals  promptcheck.Totals
}

type Screened struct{ Uncensored, Adult bool }

func (w *InProcess) screen(ctx context.Context, asked bool, s Screened, kind promptcheck.Kind, prompt string) error {
	if !asked || !s.Uncensored {
		return nil
	}
	check := w.promptCheck
	if check == nil || check.Scorer == nil {
		return apierr.ErrPromptCheckDown
	}
	ask := promptcheck.Ask{Prompt: prompt, Adult: s.Adult}
	refused, err := check.refuses(ctx, ask)
	switch {
	case err != nil && ctx.Err() != nil:
		return ctx.Err()
	case err != nil:
		check.totals.Add(w.now(), kind, promptcheck.Unavailable)
		return apierr.ErrPromptCheckDown
	case refused:
		check.totals.Add(w.now(), kind, promptcheck.Refused)
		return apierr.ErrPromptRefused
	}
	check.totals.Add(w.now(), kind, promptcheck.Allowed)
	return nil
}

func (c *PromptCheck) refuses(ctx context.Context, ask promptcheck.Ask) (bool, error) {
	var err error
	for range promptCheckAttempts {
		var refused bool
		if refused, err = c.once(ctx, ask); err == nil || ctx.Err() != nil || errors.Is(err, promptcheck.ErrBusy) {
			return refused, err
		}
	}
	return false, err
}

func (c *PromptCheck) once(ctx context.Context, ask promptcheck.Ask) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, cmp.Or(c.Timeout, promptCheckTimeout))
	defer cancel()
	scores, err := c.Scorer.Score(ctx, ask.Prompt)
	if err != nil {
		return false, err
	}
	return promptcheck.Refuses(ask, scores)
}

func (w *InProcess) promptChecks() []promptcheck.Total {
	if w.promptCheck == nil {
		return nil
	}
	return w.promptCheck.totals.Ended(w.now())
}
