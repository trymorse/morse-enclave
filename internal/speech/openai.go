package speech

import (
	"bytes"
	"context"
	"mime"
	"net/http"
	"time"

	"morse/backend/internal/jsonx"
	"morse/backend/internal/plans/limits"
	"morse/backend/internal/upstream"
)

var DeepInfraLimit = limits.SharedLimit{Subject: "deepinfra/speech", RPM: 600}

const (
	speechPath   = "/v1/audio/speech"
	speakTimeout = 30 * time.Second
)

type OpenAI struct {
	vendor  upstream.Endpoint
	model   string
	Timeout time.Duration
}

var _ Speaker = (*OpenAI)(nil)

func NewOpenAI(baseURL, apiKey, model string, client *http.Client) *OpenAI {
	return &OpenAI{vendor: upstream.Endpoint{BaseURL: baseURL, Auth: upstream.Bearer(apiKey), HTTP: client, Refuse: refusal}, model: model, Timeout: speakTimeout}
}

// why: DeepInfra's 400 quotes the input text it refuses (probe of 2026-11-17), so a refusal maps by status alone.
func refusal(r upstream.Reply) error {
	switch {
	case r.Status == http.StatusTooManyRequests || r.Status == http.StatusServiceUnavailable || r.Status == 529:
		return ErrUpstreamBusy
	case r.Status == http.StatusUnauthorized || r.Status == http.StatusPaymentRequired || r.Status == http.StatusForbidden || r.Status == http.StatusNotFound:
		return ErrUpstreamUnavailable
	case r.Status/100 == 4:
		return ErrUnreadable
	}
	return ErrUpstream
}

type wireRequest struct {
	Model          string  `json:"model"`
	Input          string  `json:"input"`
	Voice          string  `json:"voice"`
	ResponseFormat string  `json:"response_format"`
	Speed          float64 `json:"speed"`
}

func (o *OpenAI) Speak(ctx context.Context, req *Request) (Audio, error) {
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	body := jsonx.Encode(wireRequest{Model: o.model, Input: req.input, Voice: req.voice, ResponseFormat: "mp3", Speed: req.speed})
	call := upstream.Request{Method: http.MethodPost, Path: speechPath, Header: http.Header{"Accept": {ContentType}}, Body: body}
	reply, err := o.vendor.JSON(ctx, call, nil, MaxAudioBytes)
	if err != nil {
		return Audio{}, err
	}
	if !audioOf(reply.Header.Get("Content-Type")) || len(reply.Body) == 0 || bytes.HasPrefix(reply.Body, []byte("{")) {
		return Audio{}, ErrUpstream
	}
	return NewAudio(reply.Body), nil
}

func audioOf(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "audio/mpeg" || mediaType == "audio/mp3"
}
