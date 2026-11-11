package worker

import (
	"strings"
	"time"
	"unicode"

	"morse/backend/internal/apierr"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/seal"
	"morse/backend/internal/taskseal"
)

// What a finished run leaves (contracts.md D.4 and C.4 to C.6): its result sealed to each of the task's device keys,
// for ok a preview for each key's push and the bundle sealed again with the run as its last result, and for a run
// with no answer only its outcome. The relay stores them as they are; it can open none of them.

func (r *taskRun) sealed(now time.Time) (TaskFinished, error) {
	f := TaskFinished{Results: []TaskSealed{}, Previews: []TaskSealed{}, Steps: r.steps}
	if !r.answered {
		f.Outcome, f.Refusal = TaskFailed, r.refusal
		return f, nil
	}
	key := r.w.sealing.tasks
	if key == nil {
		return TaskFinished{}, errSealedUnavailable
	}
	content, outcome := r.answer, TaskOK
	if asksForChange(r.bundle) {
		if rest, unchanged := noChange(r.answer); unchanged {
			content, outcome = rest, TaskUnchanged
		}
	}
	b := r.bundle
	result := TaskResult{
		Task: b.ID, Run: r.runID, Chat: b.Chat, RanAt: now.Unix(), Outcome: outcome, Route: b.Route, Mode: b.Mode,
		Prompt: b.Prompt, Content: content, Recalled: b.Recalled, Sources: r.sources.list(),
	}
	resultJSON := fitResult(&result)
	for _, k := range b.Keys {
		sealed, err := taskseal.SealResult(k[:], r.task, r.run, resultJSON)
		if err != nil {
			return TaskFinished{}, apierr.ErrUnavailable
		}
		f.Results = append(f.Results, TaskSealed{Key: seal.KeyIDOf(k[:]), Sealed: sealed})
	}
	f.Outcome = outcome
	if outcome != TaskOK {
		return f, nil
	}
	previewJSON := previewOf(b, r.runID, result.Content)
	for _, k := range b.Keys {
		sealed, err := taskseal.SealPreview(k[:], r.task, r.run, previewJSON)
		if err != nil {
			return TaskFinished{}, apierr.ErrUnavailable
		}
		f.Previews = append(f.Previews, TaskSealed{Key: seal.KeyIDOf(k[:]), Sealed: sealed})
	}
	b.Last = &TaskLast{Run: r.runID, At: result.RanAt, Text: cutRunes(result.Content, MaxTaskLastRunes)}
	data, err := atRest(b)
	if err != nil {
		return f, nil
	}
	rev, reserved := r.w.sealing.floors.reserve(r.task, r.rev, true)
	if !reserved {
		return f, nil
	}
	f.Revision = rev
	if f.Bundle, err = taskseal.SealBundle(key, r.task, uint64(f.Revision), data); err != nil {
		return TaskFinished{}, apierr.ErrUnavailable
	}
	return f, nil
}

// noChange reads an answer that says nothing important changed: NO_CHANGE alone on its first line, and the rest, if
// any, a note.
func noChange(answer string) (string, bool) {
	first, rest, _ := strings.Cut(strings.TrimLeftFunc(answer, unicode.IsSpace), "\n")
	if strings.TrimSpace(first) != TaskNoChange {
		return "", false
	}
	return strings.TrimSpace(rest), true
}

// fitResult is the result's JSON, its content cut at a rune boundary until the JSON fits a result envelope. Sources
// never come near it, but would go before the content does.
func fitResult(r *TaskResult) []byte {
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

// previewOf is the preview's JSON: the content on one line, cut to MaxTaskPreviewRunes and so the JSON fits a
// preview envelope, ending with "…" when cut.
func previewOf(b TaskBundle, runID, content string) []byte {
	p := TaskPreview{Task: b.ID, Run: runID, Chat: b.Chat, Title: b.Name}
	encode := func(body string) []byte {
		p.Body = body
		return jsonx.Encode(p)
	}
	body := strings.Join(strings.Fields(content), " ")
	if data := encode(body); runes(body) <= MaxTaskPreviewRunes && len(data) <= taskseal.MaxPreviewJSON {
		return data
	}
	data, _, _ := fitting(cutRunes(body, MaxTaskPreviewRunes-1), taskseal.MaxPreviewJSON, func(kept string) []byte {
		return encode(strings.TrimRightFunc(kept, unicode.IsSpace) + "…")
	})
	return data
}
