// Package audio reads a transcription request, writes its transcript, and sends audio to an OpenAI-compatible
// transcription endpoint.
package audio

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"mime/multipart"
	"slices"
	"strings"
	"unicode/utf8"

	"morse/backend/internal/apierr"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/strictjson"
)

const (
	// MaxSeconds is the longest recording a request may carry, the five minutes the web app stops a dictation at. NEAR
	// bills by the length of the audio, so this is what holds a call to the route's flat price.
	MaxSeconds = 5 * 60
	// MaxRequestBody is the most a transcription request may carry: MaxSeconds of the web app's 16 kHz mono 16-bit WAV
	// is 9.6 MB, and the form wraps it in a few hundred bytes. A recording at a higher rate, or in stereo, reaches it
	// sooner.
	MaxRequestBody = 10 << 20
	maxFieldBytes  = 256

	pcm                          = 1
	sampleBytes                  = 2
	minSampleRate, maxSampleRate = 8_000, 48_000
)

var (
	ErrUpstreamBusy        = apierr.Error{Status: 503, Type: "upstream_error", Code: "upstream_busy", Message: "The transcription provider is busy. Try again shortly."}
	ErrUpstreamUnavailable = apierr.Error{Status: 502, Type: "upstream_error", Code: "upstream_unavailable", Message: "The transcription provider is unavailable."}
	ErrUpstream            = apierr.Error{Status: 502, Type: "upstream_error", Code: "upstream_error", Message: "The transcription provider failed."}
	ErrUnreadable          = apierr.Invalid(400, "invalid_request", "The transcription provider could not read the audio.")
	ErrTooLong             = apierr.Invalid(413, "request_too_large", fmt.Sprintf("A recording may be at most %d minutes long.", MaxSeconds/60))

	errNotMultipart = strictjson.Invalid("The request body must be multipart/form-data with a model and a file.")
	errMalformed    = strictjson.Invalid("The request body is not well-formed multipart/form-data.")
	errUnnamedPart  = strictjson.Invalid("Each part of the form must be a field with a name.")
	errNoModel      = strictjson.Invalid("model is required.")
	errNoFile       = strictjson.Invalid("file is required.")
	errNoAudio      = strictjson.Invalid("file holds no audio.")
	errFormat       = strictjson.Invalid("file must be a WAV file of 16-bit PCM, mono or stereo, at 8 to 48 kHz.")
	errLanguage     = strictjson.Invalid("language must be an ISO-639-1 code that Whisper transcribes, such as en, or yue or haw.")
	errOutput       = strictjson.Invalid("response_format must be json.")
)

// Languages are the codes Whisper large-v3 transcribes, from openai/whisper's tokenizer.
var Languages = []string{
	"af", "am", "ar", "as", "az", "ba", "be", "bg", "bn", "bo", "br", "bs", "ca", "cs", "cy", "da", "de", "el", "en",
	"es", "et", "eu", "fa", "fi", "fo", "fr", "gl", "gu", "ha", "haw", "he", "hi", "hr", "ht", "hu", "hy", "id", "is",
	"it", "ja", "jw", "ka", "kk", "km", "kn", "ko", "la", "lb", "ln", "lo", "lt", "lv", "mg", "mi", "mk", "ml", "mn",
	"mr", "ms", "mt", "my", "ne", "nl", "nn", "no", "oc", "pa", "pl", "ps", "pt", "ro", "ru", "sa", "sd", "si", "sk",
	"sl", "sn", "so", "sq", "sr", "su", "sv", "sw", "ta", "te", "tg", "th", "tk", "tl", "tr", "tt", "uk", "ur", "uz",
	"vi", "yi", "yo", "yue", "zh",
}

// Request is one transcription request. Its String names the model and the size, never the audio.
type Request struct {
	Model    string
	language string
	audio    []byte
}

func (r Request) Language() string { return r.language }
func (r Request) Audio() []byte    { return r.audio }
func (r Request) String() string {
	return fmt.Sprintf("audio.Request(%s, %d bytes, language %q)", r.Model, len(r.audio), r.language)
}
func (r Request) GoString() string { return r.String() }

// ParseRequest reads a multipart/form-data body with a model and a file, and optionally a language and a
// response_format of json. It refuses any other field and a field sent twice, so it reads at most five parts. A read
// the body itself failed, such as one past the proxy's size limit, comes back as that error.
func ParseRequest(contentType string, body io.Reader) (*Request, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return nil, errNotMultipart
	}
	src := &sourceReader{r: body}
	form := multipart.NewReader(src, params["boundary"])
	req := &Request{}
	seen := map[string]bool{}
	var file []byte
	for {
		part, err := form.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, src.cause(err)
		}
		name := part.FormName()
		switch {
		case name == "":
			return nil, errUnnamedPart
		case seen[name]:
			return nil, strictjson.Invalid(fmt.Sprintf("Send each field once: %q repeats.", name))
		}
		seen[name] = true
		if name == "file" {
			if file, err = io.ReadAll(part); err != nil {
				return nil, src.cause(err)
			}
			continue
		}
		value, err := field(part, src)
		if err != nil {
			return nil, err
		}
		switch name {
		case "model":
			req.Model = value
		case "language":
			if !slices.Contains(Languages, value) {
				return nil, errLanguage
			}
			req.language = value
		case "response_format":
			if value != "json" {
				return nil, errOutput
			}
		default:
			return nil, strictjson.Invalid(fmt.Sprintf("Unknown field %q.", name))
		}
	}
	switch {
	case req.Model == "":
		return nil, errNoModel
	case !seen["file"]:
		return nil, errNoFile
	}
	if err := checkWAV(file); err != nil {
		return nil, err
	}
	req.audio = file
	return req, nil
}

func field(part *multipart.Part, src *sourceReader) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(part, maxFieldBytes+1))
	if err != nil {
		return "", src.cause(err)
	}
	if len(raw) > maxFieldBytes || !utf8.Valid(raw) {
		return "", strictjson.Invalid(fmt.Sprintf("%s must be at most %d bytes of UTF-8.", part.FormName(), maxFieldBytes))
	}
	return string(raw), nil
}

// sourceReader keeps the error the body itself returned, so a form that broke because the body did is refused as
// the body's failure, not as a malformed form.
type sourceReader struct {
	r   io.Reader
	err error
}

func (s *sourceReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if err != nil && err != io.EOF {
		s.err = err
	}
	return n, err
}

func (s *sourceReader) cause(err error) error {
	if s.err != nil {
		return s.err
	}
	var invalid strictjson.Invalid
	if errors.As(err, &invalid) {
		return err
	}
	return errMalformed
}

// checkWAV refuses a file that is not a WAV of 16-bit PCM, or that holds more than MaxSeconds of it. Its length
// follows from its size: a decoder cannot play more samples than the bytes after the data chunk's header hold, and
// they are counted to the end of the file, whatever the chunk's own size says. A compressed format such as FLAC or
// MP3, or a WAV that carries one, can hold hours in a few megabytes, and NEAR bills by the length, so none is taken.
// The data chunk must hold at least one byte, since NEAR fails a file with no samples as its own error.
func checkWAV(file []byte) error {
	if len(file) == 0 {
		return errNoAudio
	}
	if len(file) < 12 || string(file[:4]) != "RIFF" || string(file[8:12]) != "WAVE" {
		return errFormat
	}
	var rate, frame uint64
	chunks := file[12:]
	for len(chunks) >= 8 {
		id, size := string(chunks[:4]), binary.LittleEndian.Uint32(chunks[4:8])
		chunks = chunks[8:]
		switch id {
		case "fmt ":
			if frame != 0 || size < 16 || uint64(size) > uint64(len(chunks)) {
				return errFormat
			}
			tag, channels := binary.LittleEndian.Uint16(chunks[0:2]), binary.LittleEndian.Uint16(chunks[2:4])
			rate = uint64(binary.LittleEndian.Uint32(chunks[4:8]))
			bits := binary.LittleEndian.Uint16(chunks[14:16])
			if tag != pcm || bits != 8*sampleBytes || channels < 1 || channels > 2 || rate < minSampleRate || rate > maxSampleRate {
				return errFormat
			}
			frame = uint64(channels) * sampleBytes
		case "data":
			switch {
			case frame == 0:
				return errFormat
			case len(chunks) == 0:
				return errNoAudio
			case uint64(len(chunks)) > MaxSeconds*rate*frame:
				return ErrTooLong
			}
			return nil
		}
		skip := uint64(size) + uint64(size&1)
		if skip > uint64(len(chunks)) {
			break
		}
		chunks = chunks[skip:]
	}
	return errFormat
}

// Transcript is what a transcription returns: its text, and the length of the audio, in whole seconds rounded up.
type Transcript struct {
	text    string
	seconds int
}

func NewTranscript(text string, duration float64) Transcript {
	seconds := 0
	if duration > 0 && !math.IsInf(duration, 1) {
		seconds = int(math.Ceil(min(duration, math.MaxInt32)))
	}
	return Transcript{text: strings.TrimSpace(text), seconds: seconds}
}

func (t Transcript) Text() string { return t.text }
func (t Transcript) Seconds() int { return t.seconds }
func (t Transcript) String() string {
	return fmt.Sprintf("audio.Transcript(%d bytes, %d seconds)", len(t.text), t.seconds)
}
func (t Transcript) GoString() string { return t.String() }

type wireUsage struct {
	Type    string `json:"type"`
	Seconds int    `json:"seconds"`
}

type wireTranscript struct {
	Text  string    `json:"text"`
	Usage wireUsage `json:"usage"`
}

// WriteTranscript writes OpenAI's json transcription reply: the text, and the audio's length as duration usage.
func WriteTranscript(w io.Writer, t Transcript) error {
	_, err := w.Write(append(jsonx.Encode(wireTranscript{Text: t.text, Usage: wireUsage{Type: "duration", Seconds: t.seconds}}), '\n'))
	return err
}

type Transcriber interface {
	Transcribe(ctx context.Context, req *Request) (Transcript, error)
}
