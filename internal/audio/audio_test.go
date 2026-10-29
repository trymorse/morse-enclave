package audio_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"

	"morse/backend/internal/audio"
	"morse/backend/internal/strictjson"
)

const audioCanary = "AUDIO-CANARY-81fe"

// wav is a 16 kHz mono 16-bit WAV file holding the samples, with a LIST chunk before its data as many encoders write.
func wav(samples []byte) []byte { return wavOf(1, 1, 16000, 16, samples) }

// wavOf is a WAV file of the format tag, channels, rate, and bits a sample that holds the samples.
func wavOf(tag, channels uint16, rate uint32, bits uint16, samples []byte) []byte {
	var b bytes.Buffer
	list := []byte("INFOISFT\x05\x00\x00\x00morse\x00")
	b.WriteString("RIFF")
	binary.Write(&b, binary.LittleEndian, uint32(4+8+16+8+len(list)+8+len(samples)))
	b.WriteString("WAVEfmt ")
	frame := channels * bits / 8
	for _, v := range []any{uint32(16), tag, channels, rate, rate * uint32(frame), frame, bits} {
		binary.Write(&b, binary.LittleEndian, v)
	}
	b.WriteString("LIST")
	binary.Write(&b, binary.LittleEndian, uint32(len(list)))
	b.Write(list)
	b.WriteString("data")
	binary.Write(&b, binary.LittleEndian, uint32(len(samples)))
	b.Write(samples)
	return b.Bytes()
}

type part struct {
	name, filename, contentType string
	body                        []byte
}

func form(t testing.TB, parts ...part) (string, []byte) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	for _, p := range parts {
		h := textproto.MIMEHeader{}
		disposition := fmt.Sprintf(`form-data; name=%q`, p.name)
		if p.filename != "" {
			disposition += fmt.Sprintf(`; filename=%q`, p.filename)
		}
		h.Set("Content-Disposition", disposition)
		if p.contentType != "" {
			h.Set("Content-Type", p.contentType)
		}
		pw, err := w.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		pw.Write(p.body)
	}
	w.Close()
	return w.FormDataContentType(), b.Bytes()
}

func text(name, value string) part { return part{name: name, body: []byte(value)} }

func file(body []byte) part {
	return part{name: "file", filename: "clip.webm", contentType: "audio/webm", body: body}
}

func parse(t *testing.T, parts ...part) (*audio.Request, error) {
	t.Helper()
	contentType, body := form(t, parts...)
	return audio.ParseRequest(contentType, bytes.NewReader(body))
}

func TestARequestReadsItsModelLanguageAndAPCMWAVWhateverTheClientCalledIt(t *testing.T) {
	samples := []byte(audioCanary)
	fmt16k := wav(nil)[12:36]
	for name, body := range map[string][]byte{
		"16 kHz mono":           wav(samples),
		"48 kHz stereo":         wavOf(1, 2, 48000, 16, samples),
		"8 kHz mono":            wavOf(1, 1, 8000, 16, samples),
		"a chunk of odd size":   append(append(append([]byte("RIFF\x00\x00\x00\x00WAVEjunk\x03\x00\x00\x00abc\x00"), fmt16k...), "data\x02\x00\x00\x00"...), 1, 2),
		"a data size that lies": append(append(append([]byte("RIFF\x00\x00\x00\x00WAVE"), fmt16k...), "data\xff\xff\xff\xff"...), samples...),
	} {
		req, err := parse(t, text("model", "whisper-large-v3-tee"), text("language", "yue"), text("response_format", "json"), file(body))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if req.Model != "whisper-large-v3-tee" || req.Language() != "yue" || !bytes.Equal(req.Audio(), body) {
			t.Errorf("%s: %v reads %d bytes", name, req, len(req.Audio()))
		}
	}
	req, err := parse(t, file(wav(samples)), text("model", "m"))
	if err != nil || req.Language() != "" {
		t.Errorf("a request with no language and the file first: %v, %v", req, err)
	}
}

func TestARequestTakesFiveMinutesOfAudioAndRefusesAnyMoreHoweverItsHeaderPutsIt(t *testing.T) {
	fiveMinutes := func(rate uint32, channels uint16) int { return audio.MaxSeconds * int(rate) * int(channels) * 2 }
	for name, c := range map[string]struct {
		body []byte
		long bool
	}{
		"five minutes at 16 kHz":             {wav(make([]byte, fiveMinutes(16000, 1))), false},
		"a sample more":                      {wav(make([]byte, fiveMinutes(16000, 1)+2)), true},
		"five minutes in stereo at 8 kHz":    {wavOf(1, 2, 8000, 16, make([]byte, fiveMinutes(8000, 2))), false},
		"those bytes heard as mono at 8 kHz": {wavOf(1, 1, 8000, 16, make([]byte, fiveMinutes(8000, 2))), true},
		"a data size that says two bytes":    {append(append(append([]byte("RIFF\x00\x00\x00\x00WAVE"), wav(nil)[12:36]...), "data\x02\x00\x00\x00"...), make([]byte, fiveMinutes(16000, 1)+2)...), true},
		"more audio after a chunk past data": {append(wav(make([]byte, fiveMinutes(16000, 1))), "LIST\x02\x00\x00\x00ab"...), true},
	} {
		_, err := parse(t, text("model", "m"), file(c.body))
		switch {
		case c.long && !errors.Is(err, audio.ErrTooLong):
			t.Errorf("%s: err %v, want %v", name, err, audio.ErrTooLong)
		case !c.long && err != nil:
			t.Errorf("%s: err %v, want none", name, err)
		}
	}
	if got := audio.ErrTooLong; got.Status != http.StatusRequestEntityTooLarge || got.Code != "request_too_large" || got.Message != "A recording may be at most 5 minutes long." {
		t.Errorf("ErrTooLong is %+v", got)
	}
}

func TestARequestKeepsItsAudioOutOfFmtAndJSON(t *testing.T) {
	req, err := parse(t, text("model", "m"), file(wav([]byte(audioCanary))))
	if err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, req) + fmt.Sprintf(verb, *req); strings.Contains(out, audioCanary) {
			t.Errorf("%s leaks the audio: %s", verb, out)
		}
	}
	if b, _ := json.Marshal(req); bytes.Contains(b, []byte(audioCanary)) {
		t.Errorf("json.Marshal leaks the audio: %s", b)
	}
}

func TestARequestRefusesAFormThatIsNotExactlyAModelAFileAndTheOptionalFields(t *testing.T) {
	good := wav([]byte{1, 2})
	const notWAV = "file must be a WAV file of 16-bit PCM, mono or stereo, at 8 to 48 kHz."
	for name, c := range map[string]struct {
		parts []part
		want  string
	}{
		"no model":               {[]part{file(good)}, "model is required."},
		"empty model":            {[]part{text("model", ""), file(good)}, "model is required."},
		"no file":                {[]part{text("model", "m")}, "file is required."},
		"empty file":             {[]part{text("model", "m"), file(nil)}, "file holds no audio."},
		"wav with no samples":    {[]part{text("model", "m"), file(wav(nil))}, "file holds no audio."},
		"wav with no data chunk": {[]part{text("model", "m"), file([]byte("RIFF\x04\x00\x00\x00WAVE"))}, notWAV},
		"wav cut in a chunk":     {[]part{text("model", "m"), file([]byte("RIFF\x00\x00\x00\x00WAVELIST\xff\x00\x00\x00ab"))}, notWAV},
		"webm":                   {[]part{text("model", "m"), file([]byte("\x1a\x45\xdf\xa3webm"))}, notWAV},
		"mp4":                    {[]part{text("model", "m"), file([]byte("\x00\x00\x00\x18ftypmp42"))}, notWAV},
		"adts aac":               {[]part{text("model", "m"), file([]byte{0xff, 0xf1, 0x50, 0x80})}, notWAV},
		"flac":                   {[]part{text("model", "m"), file([]byte("fLaC\x00\x00\x00\x22abc"))}, notWAV},
		"mp3 with ID3":           {[]part{text("model", "m"), file([]byte("ID3\x04\x00\x00\x00\x00\x00\x00abc"))}, notWAV},
		"mp3 frame":              {[]part{text("model", "m"), file([]byte{0xff, 0xfb, 0x90, 0x64, 1, 2})}, notWAV},
		"8-bit wav":              {[]part{text("model", "m"), file(wavOf(1, 1, 16000, 8, []byte{1, 2}))}, notWAV},
		"float wav":              {[]part{text("model", "m"), file(wavOf(3, 1, 16000, 32, []byte{1, 2, 3, 4}))}, notWAV},
		"extensible wav":         {[]part{text("model", "m"), file(wavOf(0xfffe, 1, 16000, 16, []byte{1, 2}))}, notWAV},
		"mp3 in a wav":           {[]part{text("model", "m"), file(wavOf(0x55, 1, 16000, 16, []byte{1, 2}))}, notWAV},
		"three channels":         {[]part{text("model", "m"), file(wavOf(1, 3, 16000, 16, []byte{1, 2, 3, 4, 5, 6}))}, notWAV},
		"4 kHz":                  {[]part{text("model", "m"), file(wavOf(1, 1, 4000, 16, []byte{1, 2}))}, notWAV},
		"96 kHz":                 {[]part{text("model", "m"), file(wavOf(1, 1, 96000, 16, []byte{1, 2}))}, notWAV},
		"data before fmt":        {[]part{text("model", "m"), file([]byte("RIFF\x00\x00\x00\x00WAVEdata\x02\x00\x00\x00\x01\x02"))}, notWAV},
		"a second fmt":           {[]part{text("model", "m"), file(append(append(append([]byte("RIFF\x00\x00\x00\x00WAVE"), good[12:36]...), good[12:36]...), "data\x02\x00\x00\x00\x01\x02"...))}, notWAV},
		"a short fmt":            {[]part{text("model", "m"), file([]byte("RIFF\x00\x00\x00\x00WAVEfmt \x0e\x00\x00\x00\x01\x00\x01\x00\x80\x3e\x00\x00\x00\x7d\x00\x00\x02\x00data\x02\x00\x00\x00\x01\x02"))}, notWAV},
		"unknown language":       {[]part{text("model", "m"), text("language", "xx"), file(good)}, "language must be"},
		"language by name":       {[]part{text("model", "m"), text("language", "english"), file(good)}, "language must be"},
		"upper-case language":    {[]part{text("model", "m"), text("language", "EN"), file(good)}, "language must be"},
		"text output":            {[]part{text("model", "m"), text("response_format", "text"), file(good)}, "response_format must be json."},
		"verbose output":         {[]part{text("model", "m"), text("response_format", "verbose_json"), file(good)}, "response_format must be json."},
		"unknown field":          {[]part{text("model", "m"), text("prompt", "hi"), file(good)}, `Unknown field "prompt".`},
		"repeated model":         {[]part{text("model", "m"), text("model", "n"), file(good)}, `Send each field once: "model" repeats.`},
		"repeated file":          {[]part{text("model", "m"), file(good), file(good)}, `Send each field once: "file" repeats.`},
		"long model":             {[]part{text("model", strings.Repeat("m", 257)), file(good)}, "model must be at most 256 bytes of UTF-8."},
		"model not utf-8":        {[]part{text("model", "\xff"), file(good)}, "model must be at most 256 bytes of UTF-8."},
		"unnamed part":           {[]part{{body: []byte("x")}, text("model", "m"), file(good)}, "Each part of the form must be a field with a name."},
	} {
		_, err := parse(t, c.parts...)
		var invalid strictjson.Invalid
		if !errors.As(err, &invalid) || !strings.Contains(string(invalid), c.want) {
			t.Errorf("%s: err %v, want an invalid %q", name, err, c.want)
		}
	}
}

func TestARequestThatIsNotMultipartIsRefusedAsSuch(t *testing.T) {
	_, body := form(t, text("model", "m"), file(wav([]byte{1})))
	for name, contentType := range map[string]string{
		"json":        "application/json",
		"none":        "",
		"no boundary": "multipart/form-data",
		"mixed":       "multipart/mixed; boundary=x",
		"garbled":     "multipart/form-data; boundary",
	} {
		_, err := audio.ParseRequest(contentType, bytes.NewReader(body))
		if err == nil || err.Error() != "The request body must be multipart/form-data with a model and a file." {
			t.Errorf("%s: err %v", name, err)
		}
	}
	for name, raw := range map[string]string{
		"wrong boundary": "--other\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nm\r\n--other--\r\n",
		"cut short":      "--b\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nm",
	} {
		_, err := audio.ParseRequest("multipart/form-data; boundary=b", strings.NewReader(raw))
		if err == nil || err.Error() != "The request body is not well-formed multipart/form-data." {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestARequestWhoseBodyFailsIsRefusedWithTheBodysOwnError(t *testing.T) {
	contentType, body := form(t, text("model", "m"), file(wav(bytes.Repeat([]byte{1}, 4096))))
	rec := httptest.NewRecorder()
	limited := http.MaxBytesReader(rec, io.NopCloser(bytes.NewReader(body)), 1024)
	_, err := audio.ParseRequest(contentType, limited)
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		t.Errorf("a body past its limit: err %v, want the *http.MaxBytesError", err)
	}
	failing := io.MultiReader(bytes.NewReader(body[:100]), errReader{})
	if _, err := audio.ParseRequest(contentType, failing); !errors.Is(err, errBroken) {
		t.Errorf("a body that broke: err %v, want its error", err)
	}
}

var errBroken = errors.New("connection reset")

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBroken }

func TestATranscriptTrimsItsTextRoundsItsSecondsUpAndWritesOpenAIsJSONReply(t *testing.T) {
	for name, c := range map[string]struct {
		text     string
		duration float64
		want     string
	}{
		"whisper's leading space": {" And so, my fellow Americans.", 11.0, `{"text":"And so, my fellow Americans.","usage":{"type":"duration","seconds":11}}`},
		"part of a second":        {"Hi <there> & you", 0.2, `{"text":"Hi <there> & you","usage":{"type":"duration","seconds":1}}`},
		"no duration":             {"", 0, `{"text":"","usage":{"type":"duration","seconds":0}}`},
		"negative duration":       {"x", -3, `{"text":"x","usage":{"type":"duration","seconds":0}}`},
	} {
		var b bytes.Buffer
		if err := audio.WriteTranscript(&b, audio.NewTranscript(c.text, c.duration)); err != nil || b.String() != c.want+"\n" {
			t.Errorf("%s: wrote %q, %v, want %s", name, b.String(), err, c.want)
		}
	}
	tr := audio.NewTranscript(audioCanary, 3.5)
	if tr.Text() != audioCanary || tr.Seconds() != 4 {
		t.Errorf("transcript reads %q, %d seconds", tr.Text(), tr.Seconds())
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, tr); strings.Contains(out, audioCanary) {
			t.Errorf("%s leaks the transcript: %s", verb, out)
		}
	}
}

func TestTheLanguagesAreWhispersHundredCodesSortedOnce(t *testing.T) {
	if len(audio.Languages) != 100 {
		t.Errorf("%d languages, want Whisper large-v3's 100", len(audio.Languages))
	}
	for i := 1; i < len(audio.Languages); i++ {
		if audio.Languages[i-1] >= audio.Languages[i] {
			t.Errorf("%q comes before %q", audio.Languages[i-1], audio.Languages[i])
		}
	}
}
