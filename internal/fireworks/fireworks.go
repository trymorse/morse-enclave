package fireworks

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/http"

	"morse/backend/internal/chat"
	"morse/backend/internal/openaicompat"
	"morse/backend/internal/upstream"
)

const (
	AffinityHeader = "X-Session-Affinity"
	maxMaterial    = 64 << 10
)

var secret = func() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}()

func NewChat(baseURL, apiKey, model string, client *http.Client) *openaicompat.Provider {
	vendor := upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: client}
	return &openaicompat.Provider{
		Sender:     openaicompat.HTTPSender{Endpoint: vendor},
		Model:      model,
		LimitField: openaicompat.MaxTokens,
		Admit:      openaicompat.FunctionToolsTextAndImages,
		Headers:    affinityHeader,
	}
}

func affinityHeader(c chat.Call) http.Header {
	value, ok := Affinity(c)
	if !ok {
		return nil
	}
	return http.Header{AffinityHeader: {value}}
}

func Affinity(c chat.Call) (string, bool) {
	msgs, err := c.Messages()
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, secret)
	for _, m := range msgs {
		switch m.Role {
		case "system", "developer", "user":
		default:
			continue
		}
		text, ok := m.Text()
		if !ok || len(text) > maxMaterial {
			return "", false
		}
		mac.Write([]byte(m.Role))
		binary.Write(mac, binary.BigEndian, uint64(len(text)))
		mac.Write([]byte(text))
		if m.Role == "user" {
			return hex.EncodeToString(mac.Sum(nil)), true
		}
	}
	return "", false
}
