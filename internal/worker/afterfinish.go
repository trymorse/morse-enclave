package worker

import "morse/backend/internal/chat"

// why: Llama 3.1 8B on DeepInfra sends the tail of a tool call as text after finish_reason. It sits inside limitCut,
// which still counts it and stops the call at the limit; only n=1 is served, so a chunk's finish is the reply's.
func dropAfterFinish(emit func(chat.Chunk) error) func(chat.Chunk) error {
	finished := false
	return func(c chat.Chunk) error {
		d := c.Delta()
		if finished && (d.Delivered() || d.Finish != chat.FinishNone) {
			return nil
		}
		finished = finished || d.Finish != chat.FinishNone
		return emit(c)
	}
}
