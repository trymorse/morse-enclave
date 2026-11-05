package fireworks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

// Replies Together and Fireworks sent for moonshotai/kimi-k3.1-pro and minimax/minimax-m3.1-flash on 2026-11-04. A
// stream keeps its first two and last two events, with one event of the same host's shape between them.
const (
	togetherKimiTools = `{"id":"chatcmpl-01a1aa26dd8c74a49a7ee933","object":"chat.completion.chunk","created":1793856036,"model":"moonshotai/Kimi-K3.1-Pro","system_fingerprint":"default","choices":[{"index":0,"delta":{"role":"assistant","content":""},"logprobs":null,"finish_reason":null}]}
{"id":"chatcmpl-01a1aa26dd8c74a49a7ee933","object":"chat.completion.chunk","created":1793856036,"model":"moonshotai/Kimi-K3.1-Pro","system_fingerprint":"default","choices":[{"index":0,"delta":{"reasoning_content":"K"},"logprobs":null,"finish_reason":null}]}
{"id":"chatcmpl-01a1aa26dd8c74a49a7ee933","object":"chat.completion.chunk","created":1793856036,"model":"moonshotai/Kimi-K3.1-Pro","system_fingerprint":"default","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"get_time_0","type":"function","function":{"name":"get_time","arguments":"{\"city\":\"Paris\"}"}}]},"logprobs":null,"finish_reason":null}]}
{"id":"chatcmpl-01a1aa26dd8c74a49a7ee933","object":"chat.completion.chunk","created":1793856036,"model":"moonshotai/Kimi-K3.1-Pro","system_fingerprint":"default","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"tool_calls","usage":{"prompt_tokens":173,"completion_tokens":86,"total_tokens":259,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":37}}}]}
{"id":"chatcmpl-01a1aa26dd8c74a49a7ee933","object":"chat.completion.chunk","created":1793856036,"model":"moonshotai/Kimi-K3.1-Pro","system_fingerprint":"default","choices":[],"usage":{"prompt_tokens":173,"completion_tokens":86,"total_tokens":259,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":37}}}`
	fireworksKimiTools = `{"id":"chatcmpl-70b5722e1ccd4f49bfb932c33e5968af","object":"chat.completion.chunk","created":1793856036,"model":"accounts/fireworks/models/kimi-k3p1-pro","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null,"raw_output":null}],"usage":{"prompt_tokens":109,"total_tokens":110,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":0}}}
{"id":"chatcmpl-70b5722e1ccd4f49bfb932c33e5968af","object":"chat.completion.chunk","created":1793856036,"model":"accounts/fireworks/models/kimi-k3p1-pro","choices":[{"index":0,"delta":{"reasoning_content":"K"},"finish_reason":null,"raw_output":null}],"usage":{"prompt_tokens":109,"total_tokens":110,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":0}}}
{"id":"chatcmpl-70b5722e1ccd4f49bfb932c33e5968af","object":"chat.completion.chunk","created":1793856036,"model":"accounts/fireworks/models/kimi-k3p1-pro","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_bbc96fff5a2046e285bc8a6e","type":"function","function":{"name":"get_time","arguments":"{\"city\": \"Paris\"}"}}]},"finish_reason":null,"raw_output":null}],"usage":{"prompt_tokens":109,"total_tokens":150,"completion_tokens":41,"prompt_tokens_details":{"cached_tokens":0}}}
{"id":"chatcmpl-70b5722e1ccd4f49bfb932c33e5968af","object":"chat.completion.chunk","created":1793856036,"model":"accounts/fireworks/models/kimi-k3p1-pro","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls","raw_output":null}],"usage":{"prompt_tokens":109,"total_tokens":192,"completion_tokens":83,"prompt_tokens_details":{"cached_tokens":0}}}
{"id":"chatcmpl-70b5722e1ccd4f49bfb932c33e5968af","object":"chat.completion.chunk","created":1793856036,"model":"accounts/fireworks/models/kimi-k3p1-pro","choices":[],"usage":{"prompt_tokens":109,"total_tokens":192,"completion_tokens":83,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":34},"output_tokens_details":{"reasoning_tokens":34}}}`
	togetherMinimax = `{"id":"dc88b2ca-aws_uw1","object":"chat.completion.chunk","created":1793856036,"model":"MiniMaxAI/MiniMax-M3.1-Flash","system_fingerprint":"default","choices":[{"index":0,"delta":{"role":"assistant"},"logprobs":null,"finish_reason":null}]}
{"id":"dc88b2ca-aws_uw1","object":"chat.completion.chunk","created":1793856036,"model":"MiniMaxAI/MiniMax-M3.1-Flash","system_fingerprint":"default","choices":[{"index":0,"delta":{"reasoning_content":"We need respond"},"finish_reason":null}]}
{"id":"dc88b2ca-aws_uw1","object":"chat.completion.chunk","created":1793856036,"model":"MiniMaxAI/MiniMax-M3.1-Flash","system_fingerprint":"default","choices":[{"index":0,"delta":{"content":"pong"},"logprobs":null,"finish_reason":null}]}
{"id":"dc88b2ca-aws_uw1","object":"chat.completion.chunk","created":1793856036,"model":"MiniMaxAI/MiniMax-M3.1-Flash","system_fingerprint":"default","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"stop","matched_stop":200020}]}
{"id":"dc88b2ca-aws_uw1","object":"chat.completion.chunk","created":1793856036,"model":"MiniMaxAI/MiniMax-M3.1-Flash","system_fingerprint":"default","choices":[],"usage":{"prompt_tokens":185,"completion_tokens":26,"total_tokens":211,"prompt_tokens_details":{"cached_tokens":0,"audio_tokens":0},"completion_tokens_details":{"reasoning_tokens":21,"audio_tokens":0,"accepted_prediction_tokens":0,"rejected_prediction_tokens":0}}}`
	fireworksMinimax = `{"id":"chatcmpl-210a4e543ed444eb99de0d73349cab16","object":"chat.completion.chunk","created":1793856037,"model":"accounts/fireworks/models/minimax-m3p1-flash","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}],"usage":{"prompt_tokens":207,"total_tokens":208,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":206}}}
{"id":"chatcmpl-210a4e543ed444eb99de0d73349cab16","object":"chat.completion.chunk","created":1793856037,"model":"accounts/fireworks/models/minimax-m3p1-flash","choices":[{"index":0,"delta":{"reasoning_content":"We need respond"},"finish_reason":null}],"usage":{"prompt_tokens":207,"total_tokens":209,"completion_tokens":2,"prompt_tokens_details":{"cached_tokens":206}}}
{"id":"chatcmpl-210a4e543ed444eb99de0d73349cab16","object":"chat.completion.chunk","created":1793856037,"model":"accounts/fireworks/models/minimax-m3p1-flash","choices":[{"index":0,"delta":{"content":"pong"},"finish_reason":null}],"usage":{"prompt_tokens":207,"total_tokens":224,"completion_tokens":17,"prompt_tokens_details":{"cached_tokens":206}}}
{"id":"chatcmpl-210a4e543ed444eb99de0d73349cab16","object":"chat.completion.chunk","created":1793856037,"model":"accounts/fireworks/models/minimax-m3p1-flash","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":207,"total_tokens":225,"completion_tokens":18,"prompt_tokens_details":{"cached_tokens":206}}}
{"id":"chatcmpl-210a4e543ed444eb99de0d73349cab16","object":"chat.completion.chunk","created":1793856037,"model":"accounts/fireworks/models/minimax-m3p1-flash","choices":[],"usage":{"prompt_tokens":207,"total_tokens":225,"completion_tokens":18,"prompt_tokens_details":{"cached_tokens":206},"completion_tokens_details":{"reasoning_tokens":14},"output_tokens_details":{"reasoning_tokens":14}}}`

	togetherKimiComplete     = `{"id":"chatcmpl-01a1aa26dd687686ae194f78","object":"chat.completion","created":1793856036,"model":"moonshotai/Kimi-K3.1-Pro","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"get_time_0","type":"function","function":{"name":"get_time","arguments":"{\"city\":\"Paris\"}"}}],"reasoning_content":"I need the tool."},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":173,"completion_tokens":88,"total_tokens":261,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":39}},"system_fingerprint":"default"}`
	fireworksKimiComplete    = `{"id":"chatcmpl-73a82297d68a4c50b7f49c43424b2712","object":"chat.completion","created":1793856036,"model":"accounts/fireworks/models/kimi-k3p1-pro","choices":[{"index":0,"message":{"role":"assistant","content":"","reasoning_content":"I need the tool.","tool_calls":[{"index":0,"id":"call_bbc96fff5a2046e285bc8a6e","type":"function","function":{"name":"get_time","arguments":"{\"city\": \"Paris\"}"},"name":null}],"tools":null},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":109,"total_tokens":192,"completion_tokens":83,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":34},"output_tokens_details":{"reasoning_tokens":34}}}`
	togetherMinimaxComplete  = `{"id":"f920777d-aws_uw1","object":"chat.completion","created":1793856036,"model":"MiniMaxAI/MiniMax-M3.1-Flash","choices":[{"index":0,"message":{"role":"assistant","content":"pong","refusal":null,"annotations":[],"reasoning_content":"Say pong."},"logprobs":null,"finish_reason":"stop","matched_stop":200020}],"usage":{"prompt_tokens":185,"completion_tokens":16,"total_tokens":201,"prompt_tokens_details":{"cached_tokens":0,"audio_tokens":0},"completion_tokens_details":{"reasoning_tokens":12,"audio_tokens":0,"accepted_prediction_tokens":0,"rejected_prediction_tokens":0}},"system_fingerprint":"default","service_tier":"default"}`
	fireworksMinimaxComplete = `{"id":"chatcmpl-676a5eba9f244828babc1473b2f4e844","object":"chat.completion","created":1793856037,"model":"accounts/fireworks/models/minimax-m3p1-flash","choices":[{"index":0,"message":{"role":"assistant","content":"pong","reasoning_content":"Say pong."},"finish_reason":"stop"}],"usage":{"prompt_tokens":207,"total_tokens":227,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":16},"output_tokens_details":{"reasoning_tokens":16}}}`
)

type host struct {
	name   string
	serve  func(t *testing.T, reply string) *openaicompat.Provider
	stream map[string]string
	whole  map[string]string
}

func hosts() []host {
	return []host{
		{"together", serveTogether, map[string]string{"kimi": togetherKimiTools, "minimax": togetherMinimax}, map[string]string{"kimi": togetherKimiComplete, "minimax": togetherMinimaxComplete}},
		{"fireworks", serveFireworks, map[string]string{"kimi": fireworksKimiTools, "minimax": fireworksMinimax}, map[string]string{"kimi": fireworksKimiComplete, "minimax": fireworksMinimaxComplete}},
	}
}

// serveTogether builds the provider cmd/internal/vendors builds for a generic private endpoint.
func serveTogether(t *testing.T, reply string) *openaicompat.Provider {
	srv := replying(t, reply)
	return &openaicompat.Provider{Sender: openaicompat.HTTPSender{Endpoint: upstream.Endpoint{BaseURL: srv.URL, HTTP: srv.Client()}}, Model: "up", LimitField: openaicompat.MaxTokens}
}

func serveFireworks(t *testing.T, reply string) *openaicompat.Provider {
	srv := replying(t, reply)
	return NewChat(srv.URL, "fk", "up", srv.Client())
}

func replying(t *testing.T, reply string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(raw), `"stream":true`) {
			io.WriteString(w, reply)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for line := range strings.Lines(reply) {
			io.WriteString(w, "data: "+strings.TrimSpace(line)+"\n\n")
		}
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	t.Cleanup(srv.Close)
	return srv
}

type clientReply struct {
	Choices []map[string]json.RawMessage `json:"choices"`
	Usage   json.RawMessage              `json:"usage"`
}

var (
	choiceKeys = []string{"index", "delta", "message", "finish_reason"}
	answerKeys = []string{"role", "content", "reasoning", "reasoning_content", "refusal", "tool_calls", "function_call", "audio"}
)

// shapeOf is what a client could tell hosts apart by beyond the text: every key in each choice and its delta or
// message, and whether the field is null.
func shapeOf(t *testing.T, raw []byte) (keys []string) {
	t.Helper()
	var r clientReply
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Choices {
		for k, v := range c {
			if !slices.Contains(choiceKeys, k) {
				keys = append(keys, "choice."+k)
			}
			if k != "delta" && k != "message" {
				continue
			}
			var answer map[string]json.RawMessage
			json.Unmarshal(v, &answer)
			for ak, av := range answer {
				switch {
				case !slices.Contains(answerKeys, ak):
					keys = append(keys, k+"."+ak)
				case string(av) == "null" && !(k == "message" && ak == "content"):
					keys = append(keys, k+"."+ak+"=null")
				}
			}
		}
	}
	return keys
}

func TestAReplyFromFireworksOrTogetherCarriesOnlyFieldsBothSend(t *testing.T) {
	asked := `{"model":"m","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`
	for _, h := range hosts() {
		for model, reply := range h.stream {
			var text, reasoning, tools, finish strings.Builder
			var usages int
			_, err := h.serve(t, reply).Stream(context.Background(), call(t, asked), func(c chat.Chunk) error {
				var b bytes.Buffer
				c.WriteTo(&b)
				if extra := shapeOf(t, b.Bytes()); len(extra) > 0 {
					t.Errorf("%s %s: a chunk carries %v: %s", h.name, model, extra, b.Bytes())
				}
				d := chat.NewChunk(b.Bytes()).Delta()
				text.WriteString(d.Content)
				reasoning.WriteString(d.Reasoning)
				if d.Finish != chat.FinishNone {
					finish.WriteString(d.Finish.String())
				}
				if strings.Contains(b.String(), `"get_time"`) {
					tools.WriteString("get_time")
				}
				if strings.Contains(b.String(), `"usage"`) {
					usages++
				}
				return nil
			})
			if err != nil {
				t.Fatalf("%s %s: %v", h.name, model, err)
			}
			want := map[string][4]string{"kimi": {"", "K", "get_time", "tool_calls"}, "minimax": {"pong", "We need respond", "", "stop"}}[model]
			if got := [4]string{text.String(), reasoning.String(), tools.String(), finish.String()}; got != want || usages != 1 {
				t.Errorf("%s %s: the client read %q with %d usage chunks, want %q and one", h.name, model, got, usages, want)
			}
		}
		for model, reply := range h.whole {
			c, _, err := h.serve(t, reply).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
			if err != nil {
				t.Fatalf("%s %s: %v", h.name, model, err)
			}
			var b bytes.Buffer
			c.WriteTo(&b)
			if extra := shapeOf(t, b.Bytes()); len(extra) > 0 {
				t.Errorf("%s %s: the reply carries %v: %s", h.name, model, extra, b.Bytes())
			}
			var r clientReply
			json.Unmarshal(b.Bytes(), &r)
			var message map[string]json.RawMessage
			json.Unmarshal(r.Choices[0]["message"], &message)
			if _, ok := message["content"]; !ok || message["reasoning_content"] == nil || (model == "kimi") != (message["tool_calls"] != nil) {
				t.Errorf("%s %s: the message is %s, want content, reasoning_content, and the tool call it made", h.name, model, r.Choices[0]["message"])
			}
		}
	}
}
