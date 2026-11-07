package anthropic

// Every shipped Claude model caches nothing under 512 tokens, about 2,048 bytes of English text.
const minCacheBytes = 2048

var ephemeral = &cacheControl{Type: "ephemeral"}

// A cache write costs 1.25 times the prompt rate, so a breakpoint goes only where the next request is likely to send
// the same prefix.
func (r *request) cacheRepeatedPrefix(bodyBytes int) {
	if r.instructionBytes() >= minCacheBytes {
		switch {
		case len(r.System) > 0:
			r.System[len(r.System)-1].CacheControl = ephemeral
		case len(r.Tools) > 0:
			r.Tools[len(r.Tools)-1].CacheControl = ephemeral
		}
	}
	if bodyBytes >= minCacheBytes && r.hasEarlierReply() {
		content := r.Messages[len(r.Messages)-1].Content
		content[len(content)-1] = withCacheControl(content[len(content)-1])
	}
}

func (r *request) instructionBytes() int {
	n := 0
	for _, b := range r.System {
		n += len(b.Text)
	}
	for _, t := range r.Tools {
		n += len(t.Name) + len(t.Description) + len(t.InputSchema)
	}
	return n
}

func (r *request) hasEarlierReply() bool {
	for _, m := range r.Messages[:len(r.Messages)-1] {
		if m.Role == roleAssistant {
			return true
		}
	}
	return false
}

func withCacheControl(b block) block {
	switch b := b.(type) {
	case textBlock:
		b.CacheControl = ephemeral
		return b
	case imageBlock:
		b.CacheControl = ephemeral
		return b
	case toolUseBlock:
		b.CacheControl = ephemeral
		return b
	case toolResultBlock:
		b.CacheControl = ephemeral
		return b
	}
	return b
}
