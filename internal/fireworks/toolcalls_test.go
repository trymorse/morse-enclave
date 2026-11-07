package fireworks

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

var morseCallID = regexp.MustCompile(`^call_[A-Za-z0-9]{24}$`)

type seenCall struct {
	Index    *int            `json:"index"`
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Function map[string]any  `json:"function"`
	Name     json.RawMessage `json:"name"`
}

func toolCallsOf(t *testing.T, raw []byte, field string) []seenCall {
	t.Helper()
	var r struct {
		Choices []map[string]json.RawMessage `json:"choices"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	var inner struct {
		ToolCalls []seenCall `json:"tool_calls"`
	}
	if err := json.Unmarshal(r.Choices[0][field], &inner); err != nil {
		t.Fatal(err)
	}
	return inner.ToolCalls
}

func TestAToolCallLooksTheSameFromEveryHost(t *testing.T) {
	var ids []string
	for _, h := range hosts() {
		var opened int
		var arguments string
		_, err := h.serve(t, h.stream["kimi"]).Stream(context.Background(), call(t, `{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`), func(c chat.Chunk) error {
			var b bytes.Buffer
			c.WriteTo(&b)
			if len(b.Bytes()) == 0 || !bytes.Contains(b.Bytes(), []byte(`"choices":[{`)) {
				return nil
			}
			for _, tc := range toolCallsOf(t, b.Bytes(), "delta") {
				if tc.ID == "" {
					if tc.Index == nil || *tc.Index != 0 || tc.Type != "" || len(tc.Function) != 1 || tc.Function["arguments"] == nil {
						t.Errorf("%s: streamed continuation %+v, want index 0 and arguments only", h.name, tc)
					}
					arguments += tc.Function["arguments"].(string)
					continue
				}
				opened++
				if tc.Index == nil || *tc.Index != 0 || !morseCallID.MatchString(tc.ID) || tc.Type != "function" || tc.Function["name"] != "get_time" || tc.Function["arguments"] != "" {
					t.Errorf("%s: streamed call %+v, want index 0, a Morse id, type, name, and arguments \"\"", h.name, tc)
				}
				ids = append(ids, tc.ID)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if opened != 1 || !strings.Contains(arguments, "Paris") {
			t.Errorf("%s: %d streamed calls with arguments %q, want 1 with the host's arguments", h.name, opened, arguments)
		}
		c, _, err := h.serve(t, h.whole["kimi"]).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		c.WriteTo(&b)
		for _, tc := range toolCallsOf(t, b.Bytes(), "message") {
			if tc.Index != nil || tc.Name != nil || !morseCallID.MatchString(tc.ID) || tc.Type != "function" || tc.Function["name"] != "get_time" || tc.Function["arguments"] == nil {
				t.Errorf("%s: whole call %+v, want no index, a Morse id, type, name and arguments", h.name, tc)
			}
			ids = append(ids, tc.ID)
		}
	}
	if len(ids) != 4 {
		t.Fatalf("read %d calls, want 4", len(ids))
	}
	for _, id := range ids {
		if id == "get_time_0" || id == "call_bbc96fff5a2046e285bc8a6e" {
			t.Errorf("a host's id %s reached the client", id)
		}
	}
}

func TestAWholeCallWithNoNameOrTypeIsFilled(t *testing.T) {
	reply := `{"id":"x","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"index":0,"id":"a","function":{"name":null,"arguments":"{}"}}]},"finish_reason":"tool_calls"}]}`
	c, _, err := serveTogether(t, reply).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	c.WriteTo(&b)
	if got := toolCallsOf(t, b.Bytes(), "message"); len(got) != 1 || got[0].Type != "function" || got[0].Function["name"] != "" {
		t.Errorf("got %+v", got)
	}
}

func TestAHistoryWithMorseIDsReachesEveryHostAsSent(t *testing.T) {
	const id = "call_AbCdEfGhIjKlMnOpQrStUvWx"
	history := `{"model":"m","messages":[{"role":"user","content":"time?"},{"role":"assistant","content":null,"tool_calls":[{"id":"` + id + `","type":"function","function":{"name":"get_time","arguments":"{}"}}]},{"role":"tool","tool_call_id":"` + id + `","content":"noon"}]}`
	for name, build := range map[string]func(*httptest.Server) *openaicompat.Provider{
		"together": func(srv *httptest.Server) *openaicompat.Provider {
			return &openaicompat.Provider{Sender: openaicompat.HTTPSender{Endpoint: upstream.Endpoint{BaseURL: srv.URL, HTTP: srv.Client()}}, Model: "up", LimitField: openaicompat.MaxTokens}
		},
		"fireworks": func(srv *httptest.Server) *openaicompat.Provider { return NewChat(srv.URL, "fk", "up", srv.Client()) },
	} {
		var forwarded string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			forwarded = string(raw)
			io.WriteString(w, togetherMinimaxComplete)
		}))
		t.Cleanup(srv.Close)
		if _, _, err := build(srv).Complete(context.Background(), call(t, history)); err != nil {
			t.Fatal(err)
		}
		if strings.Count(forwarded, id) != 2 {
			t.Errorf("%s: forwarded %s, want the id twice, unchanged", name, forwarded)
		}
	}
}
