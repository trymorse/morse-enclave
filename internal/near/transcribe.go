package near

import (
	"context"
	"net/http"

	"morse/backend/internal/audio"
	"morse/backend/internal/chat"
	"morse/backend/internal/plans/limits"
)

// TranscriptionLimit paces every transcription the proxy sends NEAR, together.
var TranscriptionLimit = limits.SharedLimit{Subject: "near/transcription", RPM: 300}

// Transcriber sends audio to NEAR's gateway in the clear, through the client its gate pins to the TLS key the
// gateway's attested report binds, since NEAR's end-to-end encryption covers no audio endpoint. It attests as the
// chat route of the same model does.
type Transcriber struct {
	*audio.OpenAI
	route *Route
}

var (
	_ audio.Transcriber = (*Transcriber)(nil)
	_ chat.Attester     = (*Transcriber)(nil)
)

func NewTranscriber(baseURL, upstreamModel, apiKey string, client *http.Client, gate Gate, gpu GPUVerdicts) *Transcriber {
	return &Transcriber{OpenAI: audio.NewOpenAI(baseURL, apiKey, upstreamModel, client), route: New(baseURL, upstreamModel, apiKey, client, gate, gpu)}
}

func (t *Transcriber) Attest(ctx context.Context, nonce string) (chat.Attestation, error) {
	return t.route.Attest(ctx, nonce)
}
