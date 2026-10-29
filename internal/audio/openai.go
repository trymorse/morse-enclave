package audio

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"time"

	"morse/backend/internal/apierr"
	"morse/backend/internal/plans/limits"
	"morse/backend/internal/upstream"
)

// OpenAILimit paces every transcription the proxy sends an OpenAI-compatible vendor, together.
var OpenAILimit = limits.SharedLimit{Subject: "openai/transcription", RPM: 500}

const (
	transcriptionsPath = "/v1/audio/transcriptions"
	maxReplyBytes      = 4 << 20
	// A ten-minute recording took NEAR 9 seconds on 2026-10-26.
	transcribeTimeout = 2 * time.Minute
)

// OpenAI sends a request to an OpenAI-compatible POST /v1/audio/transcriptions. It sends the file as audio.wav,
// forwards the language when one was sent, and asks for verbose_json, the format that reports the audio's length.
type OpenAI struct {
	vendor  upstream.Endpoint
	model   string
	Timeout time.Duration
}

var _ Transcriber = (*OpenAI)(nil)

// NewOpenAI leaves a transport failure bare, so a client pinned to an attested host refuses with its own
// upstream_unattested and the health meter counts an unreachable vendor as one.
func NewOpenAI(baseURL, apiKey, model string, client *http.Client) *OpenAI {
	return &OpenAI{vendor: upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: client, Refuse: refusal}, model: model, Timeout: transcribeTimeout}
}

func refusal(r upstream.Reply) error {
	switch {
	case r.Status == http.StatusRequestEntityTooLarge:
		return apierr.ErrRequestTooLarge
	case r.Status == http.StatusTooManyRequests || r.Status == http.StatusServiceUnavailable || r.Status == 529:
		return ErrUpstreamBusy
	case r.Status == http.StatusUnauthorized || r.Status == http.StatusPaymentRequired || r.Status == http.StatusForbidden || r.Status == http.StatusNotFound:
		return ErrUpstreamUnavailable
	case r.Status/100 == 4:
		return ErrUnreadable
	}
	return ErrUpstream
}

type verboseReply struct {
	Text     *string  `json:"text"`
	Duration *float64 `json:"duration"`
}

func (o *OpenAI) Transcribe(ctx context.Context, req *Request) (Transcript, error) {
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	head, tail, contentType, err := o.form(req)
	if err != nil {
		return Transcript{}, err
	}
	var got verboseReply
	call := upstream.Request{Method: http.MethodPost, Path: transcriptionsPath, Header: http.Header{"Content-Type": {contentType}}, Body: head, Parts: [][]byte{req.audio, tail}}
	if _, err := o.vendor.JSON(ctx, call, &got, maxReplyBytes); err != nil {
		return Transcript{}, err
	}
	if got.Text == nil {
		return Transcript{}, ErrUpstream
	}
	var duration float64
	if got.Duration != nil {
		duration = *got.Duration
	}
	return NewTranscript(*got.Text, duration), nil
}

func (o *OpenAI) form(req *Request) (head, tail []byte, contentType string, err error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	fields := [][2]string{{"model", o.model}, {"response_format", "verbose_json"}}
	if req.language != "" {
		fields = append(fields, [2]string{"language", req.language})
	}
	for _, f := range fields {
		if err := w.WriteField(f[0], f[1]); err != nil {
			return nil, nil, "", err
		}
	}
	header := textproto.MIMEHeader{}
	header.Set("Content-Disposition", `form-data; name="file"; filename="audio.wav"`)
	header.Set("Content-Type", "audio/wav")
	if _, err := w.CreatePart(header); err != nil {
		return nil, nil, "", err
	}
	head = bytes.Clone(b.Bytes())
	b.Reset()
	if err := w.Close(); err != nil {
		return nil, nil, "", err
	}
	return head, b.Bytes(), w.FormDataContentType(), nil
}
