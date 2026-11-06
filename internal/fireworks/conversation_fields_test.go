package fireworks_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"morse/backend/internal/anthropic"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/deepinfra"
	"morse/backend/internal/fireworks"
	"morse/backend/internal/gemini"
	"morse/backend/internal/isoquant"
	"morse/backend/internal/morph"
	"morse/backend/internal/novita"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/openairesponses"
	"morse/backend/internal/upstream"
	"morse/backend/internal/venice"
	"morse/backend/internal/wafer"
	"morse/backend/internal/xai"
)

const (
	cacheKeyCanary = "CACHE-KEY-CANARY-5d1e"
	sessionCanary  = "SESSION-CANARY-9b2f"
)

func TestNoPlaintextChatEncoderForwardsTheCallersConversationHandles(t *testing.T) {
	body := `{"model":"m","prompt_cache_key":"` + cacheKeyCanary + `","session_id":"` + sessionCanary + `","messages":[{"role":"user","content":"hello"}]}`
	encoders := map[string]func(baseURL string, client *http.Client) chat.Provider{
		"openai": func(u string, c *http.Client) chat.Provider {
			return &openaicompat.Provider{Sender: openaicompat.HTTPSender{Endpoint: upstream.Endpoint{BaseURL: u, Auth: upstream.Bearer("k"), HTTP: c}}, Model: "m"}
		},
		"openai responses": func(u string, c *http.Client) chat.Provider { return openairesponses.New(u, "k", "m", c) },
		"anthropic":        func(u string, c *http.Client) chat.Provider { return anthropic.New(u, "k", "m", c) },
		"gemini":           func(u string, c *http.Client) chat.Provider { return gemini.NewChat(u, "k", "m", c) },
		"xai": func(u string, c *http.Client) chat.Provider {
			return xai.NewChat(u, "k", "m", catalog.RetentionVendor, c)
		},
		"venice":    func(u string, c *http.Client) chat.Provider { return venice.NewChat(u, "k", "m", c) },
		"fireworks": func(u string, c *http.Client) chat.Provider { return fireworks.NewChat(u, "k", "m", c) },
		"isoquant":  func(u string, c *http.Client) chat.Provider { return isoquant.NewChat(u, "k", "m", c) },
		"wafer":     func(u string, c *http.Client) chat.Provider { return wafer.NewChat(u, "k", "m", c) },
		"novita":    func(u string, c *http.Client) chat.Provider { return novita.NewChat(u, "k", "m", false, c) },
		"morph":     func(u string, c *http.Client) chat.Provider { return morph.NewChat(u, "k", "m", c) },
		"deepinfra": func(u string, c *http.Client) chat.Provider { return deepinfra.NewChat(u, "k", "m", false, c) },
	}
	for name, encoder := range encoders {
		var mu sync.Mutex
		var sent []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			mu.Lock()
			sent = append(sent, string(raw))
			mu.Unlock()
			http.Error(w, "recorded", http.StatusInternalServerError)
		}))
		req, err := chat.ParseRequest(strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		encoder(srv.URL, srv.Client()).Complete(context.Background(), chat.Call{Request: req, OutputLimit: 64})
		srv.Close()
		if len(sent) == 0 {
			t.Errorf("%s sent the vendor nothing to inspect", name)
		}
		for _, s := range sent {
			for _, banned := range []string{"prompt_cache_key", "session_id", cacheKeyCanary, sessionCanary} {
				if strings.Contains(s, banned) {
					t.Errorf("%s forwards %s: %s", name, banned, s)
				}
			}
		}
	}
}
