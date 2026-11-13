package taskrun

import (
	"strings"
	"time"
	"unicode"

	"morse/backend/internal/apierr"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/seal"
	"morse/backend/internal/taskseal"
)

func (r *Run[A]) sealed(outcome phase, now time.Time) (Finished, error) {
	f := Finished{Results: []Sealed{}, Previews: []Sealed{}, Steps: r.steps}
	a, ok := outcome.(answered)
	if !ok {
		f.Outcome = Failed
		if refused, ok := outcome.(failed); ok {
			f.Refusal = refused.refusal
		}
		return f, nil
	}
	b, task, run, runID := r.spec.Bundle, r.spec.Task, r.spec.Run, r.spec.Run.String()
	content, outcomeOf := a.answer, OK
	if asksForChange(b) {
		if rest, unchanged := noChange(a.answer); unchanged {
			content, outcomeOf = rest, Unchanged
		}
	}
	result := Result{
		Task: b.ID, Run: runID, Chat: b.Chat, RanAt: now.Unix(), Outcome: outcomeOf, Route: b.Route, Mode: b.Mode,
		Prompt: b.Prompt, Content: content, Recalled: b.Recalled, Sources: r.sources.list(),
	}
	resultJSON := fitResult(&result)
	for _, k := range b.Keys {
		sealed, err := taskseal.SealResult(k[:], task, run, resultJSON)
		if err != nil {
			return Finished{}, apierr.ErrUnavailable
		}
		f.Results = append(f.Results, Sealed{Key: seal.KeyIDOf(k[:]), Sealed: sealed})
	}
	f.Outcome = outcomeOf
	if outcomeOf != OK {
		return f, nil
	}
	previewJSON := previewOf(b, runID, result.Content)
	for _, k := range b.Keys {
		sealed, err := taskseal.SealPreview(k[:], task, run, previewJSON)
		if err != nil {
			return Finished{}, apierr.ErrUnavailable
		}
		f.Previews = append(f.Previews, Sealed{Key: seal.KeyIDOf(k[:]), Sealed: sealed})
	}
	b.Last = &Last{Run: runID, At: result.RanAt, Text: cutRunes(result.Content, MaxLastRunes)}
	data, err := AtRest(b)
	if err != nil {
		return f, nil
	}
	rev, reserved := r.spec.Floors.reserve(task, r.spec.Revision, true)
	if !reserved {
		return f, nil
	}
	f.Revision = rev
	if f.Bundle, err = taskseal.SealBundle(r.spec.Key, task, uint64(f.Revision), data); err != nil {
		return Finished{}, apierr.ErrUnavailable
	}
	return f, nil
}

func noChange(answer string) (string, bool) {
	first, rest, _ := strings.Cut(strings.TrimLeftFunc(answer, unicode.IsSpace), "\n")
	if strings.TrimSpace(first) != NoChange {
		return "", false
	}
	return strings.TrimSpace(rest), true
}

func fitResult(r *Result) []byte {
	for {
		data, content, ok := fitting(r.Content, taskseal.MaxResultJSON, func(text string) []byte {
			fitted := *r
			fitted.Content = text
			return jsonx.Encode(fitted)
		})
		if ok || len(r.Sources) == 0 {
			r.Content = content
			return data
		}
		r.Sources = r.Sources[:len(r.Sources)-1]
	}
}

func previewOf(b Bundle, runID, content string) []byte {
	p := Preview{Task: b.ID, Run: runID, Chat: b.Chat, Title: b.Name}
	encode := func(body string) []byte {
		p.Body = body
		return jsonx.Encode(p)
	}
	body := strings.Join(strings.Fields(content), " ")
	if data := encode(body); runes(body) <= MaxPreviewRunes && len(data) <= taskseal.MaxPreviewJSON {
		return data
	}
	data, _, _ := fitting(cutRunes(body, MaxPreviewRunes-1), taskseal.MaxPreviewJSON, func(kept string) []byte {
		return encode(strings.TrimRightFunc(kept, unicode.IsSpace) + "…")
	})
	return data
}
