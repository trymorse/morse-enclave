package speech

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"morse/backend/internal/apierr"
	"morse/backend/internal/strictjson"
)

const (
	// why: DeepInfra bills Kokoro by the input character (cents_per_input_chars on its model API), so this cap holds
	// a call to the route's flat price.
	MaxInputChars  = 500
	MaxRequestBody = 16 << 10
	MaxAudioBytes  = 8 << 20

	MinSpeed, MaxSpeed = 0.5, 2.0
)

var (
	ErrUpstreamBusy        = apierr.Error{Status: 503, Type: "upstream_error", Code: "upstream_busy", Message: "The speech provider is busy. Try again shortly."}
	ErrUpstreamUnavailable = apierr.Error{Status: 502, Type: "upstream_error", Code: "upstream_unavailable", Message: "The speech provider is unavailable."}
	ErrUpstream            = apierr.Error{Status: 502, Type: "upstream_error", Code: "upstream_error", Message: "The speech provider failed."}
	ErrUnreadable          = apierr.Invalid(400, "invalid_request", "The speech provider could not read the request.")

	errNoModel = strictjson.Invalid("model is required.")
	errInput   = strictjson.Invalid(fmt.Sprintf("input must be a string of 1 to %d characters.", MaxInputChars))
	errVoice   = strictjson.Invalid("voice is required, and must name one of the model's voices, such as af_sky.")
	errSpeed   = strictjson.Invalid(fmt.Sprintf("speed must be a number from %.1f to %.1f.", MinSpeed, MaxSpeed))
)

var voiceName = regexp.MustCompile(`^[a-z]{2}_[a-z]{1,24}$`)

const ContentType = "audio/mpeg"

type Request struct {
	Model string
	input string
	voice string
	speed float64
}

func (r Request) Input() string  { return r.input }
func (r Request) Voice() string  { return r.voice }
func (r Request) Speed() float64 { return r.speed }
func (r Request) String() string {
	return fmt.Sprintf("speech.Request(%s, %d characters, voice %s)", r.Model, utf8.RuneCountInString(r.input), r.voice)
}
func (r Request) GoString() string { return r.String() }

func ParseRequest(body io.Reader) (*Request, error) {
	fields, err := strictjson.Object(body, "model", "input", "voice", "speed")
	if err != nil {
		return nil, err
	}
	req := &Request{speed: 1}
	if json.Unmarshal(fields["model"], &req.Model) != nil || req.Model == "" {
		return nil, errNoModel
	}
	if json.Unmarshal(fields["input"], &req.input) != nil {
		return nil, errInput
	}
	if req.input = strings.TrimSpace(req.input); req.input == "" || utf8.RuneCountInString(req.input) > MaxInputChars {
		return nil, errInput
	}
	if json.Unmarshal(fields["voice"], &req.voice) != nil || !voiceName.MatchString(req.voice) {
		return nil, errVoice
	}
	if raw, ok := fields["speed"]; ok {
		if json.Unmarshal(raw, &req.speed) != nil || req.speed < MinSpeed || req.speed > MaxSpeed {
			return nil, errSpeed
		}
	}
	return req, nil
}

type Audio struct {
	data []byte
}

func NewAudio(data []byte) Audio { return Audio{data: data} }

func (a Audio) Bytes() []byte { return a.data }
func (a Audio) String() string {
	return fmt.Sprintf("speech.Audio(%d bytes of mp3)", len(a.data))
}

func (a Audio) GoString() string { return a.String() }

func (a Audio) Write(w io.Writer) error {
	_, err := w.Write(a.data)
	return err
}

type Speaker interface {
	Speak(ctx context.Context, req *Request) (Audio, error)
}
