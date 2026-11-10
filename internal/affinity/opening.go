package affinity

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"hash"

	"morse/backend/internal/chat"
)

const openingTextCap = 64 << 10

// DigestOf is the conversation digest of a request as its caller sent it. A prompt_cache_key names
// the conversation first, and an empty one opts out. A session_id comes next. Otherwise the messages up to and
// including the first user message name it. Each source hashes under its own tag, so a key whose bytes equal some
// opening's encoding still names a different conversation.
func DigestOf(req *chat.Request) Digest {
	if key, ok := stringField(req, "prompt_cache_key"); ok {
		if key == "" {
			return Digest{}
		}
		return tagged("key", key)
	}
	if session, ok := stringField(req, "session_id"); ok && session != "" {
		return tagged("session", session)
	}
	return openingDigest(req)
}

func stringField(req *chat.Request, name string) (string, bool) {
	raw, ok := req.Field(name)
	if !ok {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func tagged(tag, value string) Digest {
	h := sha256.New()
	h.Write([]byte(tag))
	writeLen(h, value)
	return sum(h)
}

func openingDigest(req *chat.Request) Digest {
	msgs, err := req.Messages()
	if err != nil {
		return Digest{}
	}
	h := sha256.New()
	h.Write([]byte("opening"))
	hasText := false
	for _, m := range msgs {
		text := textOf(m)
		hasText = hasText || text != ""
		writeLen(h, m.Role)
		writeLen(h, text)
		if m.Role == "user" {
			if !hasText {
				return Digest{}
			}
			return sum(h)
		}
	}
	return Digest{}
}

func textOf(m chat.Message) string {
	var text []byte
	for _, p := range m.Parts() {
		if p.Text != nil && (p.Type == "text" || p.Type == "") {
			text = append(text, *p.Text...)
			if len(text) >= openingTextCap {
				return string(text[:openingTextCap])
			}
		}
	}
	return string(text)
}

func writeLen(h hash.Hash, s string) {
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(s))))
	h.Write([]byte(s))
}

func sum(h hash.Hash) Digest {
	var out [32]byte
	h.Sum(out[:0])
	return DigestOfSum(out)
}
