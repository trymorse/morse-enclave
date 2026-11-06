package anthropic

// Every shipped Claude model caches nothing under 512 tokens, about 2,048 bytes of English text. The caller's body size gates it, which overestimates the prompt a little.
const minCacheBytes = 2048

var ephemeral = &cacheControl{Type: "ephemeral"}

func (r *request) cacheRepeatedPrefix(bodyBytes int) {
	if bodyBytes < minCacheBytes {
		return
	}
	switch {
	case len(r.System) > 0:
		r.System[len(r.System)-1].CacheControl = ephemeral
	case len(r.Tools) > 0:
		r.Tools[len(r.Tools)-1].CacheControl = ephemeral
	}
	content := r.Messages[len(r.Messages)-1].Content
	content[len(content)-1] = withCacheControl(content[len(content)-1])
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
