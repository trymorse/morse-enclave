package fireworks

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAConversationThatStartsOnTogetherContinuesOnFireworksWithTheIDItWasGiven(t *testing.T) {
	first, _, err := serveTogether(t, togetherKimiComplete).Complete(context.Background(), call(t, `{"model":"m","messages":[{"role":"user","content":"time?"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	first.WriteTo(&b)
	id := toolCallsOf(t, b.Bytes(), "message")[0].ID
	var forwarded string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		forwarded = string(raw)
		io.WriteString(w, fireworksMinimaxComplete)
	}))
	t.Cleanup(srv.Close)
	second := `{"model":"m","messages":[{"role":"user","content":"time?"},{"role":"assistant","content":null,"tool_calls":[{"id":"` + id + `","type":"function","function":{"name":"get_time","arguments":"{}"}}]},{"role":"tool","tool_call_id":"` + id + `","content":"noon"}]}`
	if _, _, err := NewChat(srv.URL, "fk", "up", srv.Client()).Complete(context.Background(), call(t, second)); err != nil {
		t.Fatal(err)
	}
	if strings.Count(forwarded, id) != 2 || strings.Contains(forwarded, "get_time_0") {
		t.Errorf("Fireworks was sent %s, want the id Morse gave the client, twice", forwarded)
	}
}
