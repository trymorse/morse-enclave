package affinity_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"morse/backend/internal/affinity"
	"morse/backend/internal/chat"
)

func digestOf(t *testing.T, body string) string {
	t.Helper()
	req, err := chat.ParseRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse %s: %v", body, err)
	}
	d := affinity.DigestOf(req)
	if d.IsZero() {
		return ""
	}
	text, err := d.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	return string(text)
}

func body(t *testing.T, extra string, msgs ...any) string {
	t.Helper()
	raw, err := json.Marshal(msgs)
	if err != nil {
		t.Fatal(err)
	}
	if extra != "" {
		extra = "," + extra
	}
	return `{"model":"m","messages":` + string(raw) + extra + `}`
}

func msg(role string, content any) map[string]any {
	return map[string]any{"role": role, "content": content}
}

func lenPrefixed(parts ...string) []byte {
	var out []byte
	for _, p := range parts {
		out = binary.BigEndian.AppendUint32(out, uint32(len(p)))
		out = append(out, p...)
	}
	return out
}

func sumHex(preimage []byte) string {
	text, _ := affinity.DigestOfSum(sha256.Sum256(preimage)).MarshalText()
	return string(text)
}

var (
	system = msg("system", "You are terse.")
	hello  = msg("user", "hello")
)

func TestAPromptCacheKeyNamesTheConversation(t *testing.T) {
	abc := digestOf(t, body(t, `"prompt_cache_key":"abc"`, system, hello))
	if want := sumHex(append([]byte("key"), lenPrefixed("abc")...)); abc != want {
		t.Fatalf("prompt_cache_key abc digests to %s, want %s", abc, want)
	}
	if other := digestOf(t, body(t, `"prompt_cache_key":"abc"`, msg("user", "something else"))); other != abc {
		t.Error("the same key with other messages names another conversation")
	}
	if other := digestOf(t, body(t, `"prompt_cache_key":"abd"`, system, hello)); other == abc {
		t.Error("a different key names the same conversation")
	}
	if got := digestOf(t, body(t, `"prompt_cache_key":""`, system, hello)); got != "" {
		t.Error("an empty prompt_cache_key does not opt out")
	}
	opening := digestOf(t, body(t, "", system, hello))
	if got := digestOf(t, body(t, `"prompt_cache_key":7`, system, hello)); got != opening {
		t.Error("a numeric prompt_cache_key does not fall through to the opening")
	}
}

func TestASessionIDNamesTheConversationWithoutAKey(t *testing.T) {
	s1 := digestOf(t, body(t, `"session_id":"s1"`, system, hello))
	if want := sumHex(append([]byte("session"), lenPrefixed("s1")...)); s1 != want {
		t.Fatalf("session_id s1 digests to %s, want %s", s1, want)
	}
	if got := digestOf(t, body(t, `"session_id":"s1","prompt_cache_key":"s1"`, system, hello)); got == s1 {
		t.Error("a prompt_cache_key does not take precedence over a session_id")
	}
	opening := digestOf(t, body(t, "", system, hello))
	if got := digestOf(t, body(t, `"session_id":""`, system, hello)); got != opening {
		t.Error("an empty session_id does not fall through to the opening")
	}
}

func TestTheOpeningNamesTheConversation(t *testing.T) {
	opening := digestOf(t, body(t, "", system, hello))
	want := sumHex(append([]byte("opening"), lenPrefixed("system", "You are terse.", "user", "hello")...))
	if opening != want {
		t.Fatalf("the opening digests to %s, want %s", opening, want)
	}
	image := map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64,AAAA"}}
	big := strings.Repeat("x", 70<<10)
	cut := big[:64<<10]
	cases := []struct {
		name string
		body string
		same bool
	}{
		{"a later turn", body(t, "", system, hello, msg("assistant", "hi"), msg("user", "and then?")), true},
		{"a system message after the first user message", body(t, "", system, hello, msg("system", "Be verbose.")), true},
		{"an image beside the first user message's text", body(t, "", system, msg("user", []any{map[string]any{"type": "text", "text": "hello"}, image})), true},
		{"cache_control and name on a message", body(t, "", map[string]any{"role": "system", "name": "n", "content": []any{map[string]any{"type": "text", "text": "You are terse.", "cache_control": map[string]any{"type": "ephemeral"}}}}, hello), true},
		{"content as a one-element text array", body(t, "", msg("system", []any{map[string]any{"type": "text", "text": "You are terse."}}), hello), true},
		{"a bare-string array element", body(t, "", msg("system", []any{"You are terse."}), hello), true},
		{"one changed character in the system message", body(t, "", msg("system", "You are terse!"), hello), false},
		{"a changed first user message", body(t, "", system, msg("user", "hello!")), false},
		{"a developer message before the first user message", body(t, "", system, msg("developer", "Use French."), hello), false},
		{"an assistant message before the first user message", body(t, "", system, msg("assistant", "Welcome."), hello), false},
	}
	for _, tc := range cases {
		if got := digestOf(t, tc.body); (got == opening) != tc.same || got == "" {
			t.Errorf("%s: same conversation %v, want %v (digest %q)", tc.name, got == opening, tc.same, got)
		}
	}
	if long, short := digestOf(t, body(t, "", msg("user", big))), digestOf(t, body(t, "", msg("user", cut))); long != short || long == "" {
		t.Error("a 70 KiB message does not digest as its first 64 KiB")
	}
	if long, other := digestOf(t, body(t, "", msg("user", big))), digestOf(t, body(t, "", msg("user", cut[:len(cut)-1]+"y"))); long == other {
		t.Error("the 64 KiB cut drops the cut's last byte")
	}
}

func TestAnOpeningWithoutUserTextHasNoDigest(t *testing.T) {
	image := map[string]any{"type": "image_url", "image_url": map[string]any{"url": "data:image/png;base64,AAAA"}}
	for name, b := range map[string]string{
		"no user message":         body(t, "", system, msg("assistant", "hi")),
		"a user message of image": body(t, "", msg("user", []any{image})),
	} {
		if got := digestOf(t, b); got != "" {
			t.Errorf("%s: digest %q, want none", name, got)
		}
	}
}

func TestAKeyEqualToAnOpeningsBytesNamesAnotherConversation(t *testing.T) {
	encoding := string(lenPrefixed("user", "hello"))
	opening := digestOf(t, body(t, "", hello))
	keyJSON, _ := json.Marshal("opening" + encoding)
	if got := digestOf(t, body(t, `"prompt_cache_key":`+string(keyJSON), hello)); got == opening || got == "" {
		t.Error("a prompt_cache_key equal to an opening's bytes names that opening's conversation")
	}
	keyJSON, _ = json.Marshal(encoding)
	if got := digestOf(t, body(t, `"session_id":`+string(keyJSON), hello)); got == opening || got == "" {
		t.Error("a session_id equal to an opening's bytes names that opening's conversation")
	}
}
