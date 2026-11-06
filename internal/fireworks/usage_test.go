package fireworks

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"morse/backend/internal/chat"
)

const sameUsage = `{"prompt_tokens":10,"completion_tokens":7,"total_tokens":17,"prompt_tokens_details":{"cached_tokens":2},"completion_tokens_details":{"reasoning_tokens":3}}`

func usageOfReply(t *testing.T, raw []byte) string {
	t.Helper()
	var v struct {
		Usage json.RawMessage `json:"usage"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return string(v.Usage)
}

func TestUsageIsByteIdenticalFromEveryHostForTheSameNumbers(t *testing.T) {
	const head = `{"id":"x","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":`
	replies := map[string]string{
		"together":         `{"prompt_tokens":10,"completion_tokens":7,"total_tokens":17,"prompt_tokens_details":{"cached_tokens":2,"audio_tokens":0},"completion_tokens_details":{"reasoning_tokens":3,"audio_tokens":0,"accepted_prediction_tokens":0,"rejected_prediction_tokens":0}}`,
		"fireworks":        `{"prompt_tokens":10,"total_tokens":17,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":2},"output_tokens_details":{"reasoning_tokens":3}}`,
		"openrouter-style": `{"prompt_tokens":10,"completion_tokens":7,"total_tokens":17,"cost":0.1,"prompt_tokens_details":{"cached_tokens":2,"cache_write_tokens":1},"completion_tokens_details":{"reasoning_tokens":3}}`,
	}
	for name, usage := range replies {
		c, billed, err := serveTogether(t, head+usage+`}`).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		c.WriteTo(&b)
		if got := usageOfReply(t, b.Bytes()); got != sameUsage {
			t.Errorf("%s: whole usage %s, want %s", name, got, sameUsage)
		}
		if billed.ReasoningTokens != 3 || billed.CompletionTokens != 7 || billed.CachedPromptTokens != 2 {
			t.Errorf("%s: billed %+v, want 3 reasoning inside 7 completion and 2 cached", name, billed)
		}

		var seen string
		stream := `{"id":"x","object":"chat.completion.chunk","created":1,"model":"m","choices":[],"usage":` + usage + `}`
		_, err = serveTogether(t, stream).Stream(context.Background(), call(t, `{"model":"m","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`), func(c chat.Chunk) error {
			var b bytes.Buffer
			c.WriteTo(&b)
			seen = usageOfReply(t, b.Bytes())
			return nil
		})
		if err != nil || seen != sameUsage {
			t.Errorf("%s: stream usage %s err %v, want %s", name, seen, err, sameUsage)
		}
	}
}

func TestAReplyWithNoUsageCarriesNone(t *testing.T) {
	c, _, err := serveTogether(t, `{"id":"x","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":null}`).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	c.WriteTo(&b)
	if bytes.Contains(b.Bytes(), []byte(`"usage"`)) {
		t.Errorf("reply %s carries usage", b.Bytes())
	}
}
