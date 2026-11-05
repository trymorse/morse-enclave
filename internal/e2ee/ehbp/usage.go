package ehbp

import (
	"errors"
	"strconv"
	"strings"

	"morse/backend/internal/chat"
)

// HeaderUsageMetrics carries the usage the router counted, as a response header for a reply in one piece
// and as a trailer for a stream, when the request asks for it with HeaderRequestUsage. The router writes it
// outside the seal, so the proxy bills what the vendor counted without reading the reply.
const (
	HeaderRequestUsage = "X-Tinfoil-Request-Usage-Metrics"
	HeaderUsageMetrics = "X-Tinfoil-Usage-Metrics"
)

var ErrUsage = errors.New("ehbp: usage metrics are not prompt and completion token counts")

// ParseUsageMetrics reads the router's "prompt=N,completion=N,total=N,cached_prompt_tokens=N,…,model=ID"
// as named fields in any order, and answers the usage and the model it names.
func ParseUsageMetrics(metrics string) (chat.Usage, string, error) {
	fields := map[string]string{}
	for part := range strings.SplitSeq(metrics, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return chat.Usage{}, "", ErrUsage
		}
		fields[name] = value
	}
	count := func(name string, required bool) (int, error) {
		v, ok := fields[name]
		if !ok && !required {
			return 0, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return 0, ErrUsage
		}
		return n, nil
	}
	prompt, err := count("prompt", true)
	if err != nil {
		return chat.Usage{}, "", err
	}
	completion, err := count("completion", true)
	if err != nil {
		return chat.Usage{}, "", err
	}
	cached, err := count("cached_prompt_tokens", false)
	if err != nil {
		return chat.Usage{}, "", err
	}
	return chat.Usage{PromptTokens: prompt, CompletionTokens: completion, CachedPromptTokens: cached}.Normalized(), fields["model"], nil
}
