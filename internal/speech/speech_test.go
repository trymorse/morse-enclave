package speech_test

import (
	"fmt"
	"strings"
	"testing"

	"morse/backend/internal/speech"
	"morse/backend/internal/strictjson"
)

func TestARequestTakesAModelUpToFiveHundredCharactersAVoiceAndASpeed(t *testing.T) {
	req, err := speech.ParseRequest(strings.NewReader(`{"model":"kokoro-82m","input":"  Hello there.  ","voice":"af_sky","speed":1.25}`))
	if err != nil {
		t.Fatal(err)
	}
	if req.Model != "kokoro-82m" || req.Input() != "Hello there." || req.Voice() != "af_sky" || req.Speed() != 1.25 {
		t.Errorf("parsed %+v, want kokoro-82m, the trimmed input, af_sky and 1.25", req)
	}
	req, err = speech.ParseRequest(strings.NewReader(fmt.Sprintf(`{"model":"m","input":%q,"voice":"bm_george"}`, strings.Repeat("é", speech.MaxInputChars))))
	if err != nil {
		t.Fatalf("an input of %d two-byte characters: %v", speech.MaxInputChars, err)
	}
	if req.Speed() != 1 {
		t.Errorf("the default speed is %v, want 1", req.Speed())
	}
}

func TestARequestIsRefusedForEachFieldItGetsWrong(t *testing.T) {
	for name, body := range map[string]string{
		"no model":         `{"input":"Hi.","voice":"af_sky"}`,
		"an empty model":   `{"model":"","input":"Hi.","voice":"af_sky"}`,
		"no input":         `{"model":"m","voice":"af_sky"}`,
		"a blank input":    `{"model":"m","input":"   ","voice":"af_sky"}`,
		"a long input":     fmt.Sprintf(`{"model":"m","input":%q,"voice":"af_sky"}`, strings.Repeat("a", speech.MaxInputChars+1)),
		"a numeric input":  `{"model":"m","input":5,"voice":"af_sky"}`,
		"no voice":         `{"model":"m","input":"Hi."}`,
		"a path voice":     `{"model":"m","input":"Hi.","voice":"../af_sky"}`,
		"an upper voice":   `{"model":"m","input":"Hi.","voice":"AF_SKY"}`,
		"a format":         `{"model":"m","input":"Hi.","voice":"af_sky","response_format":"mp3"}`,
		"a slow speed":     `{"model":"m","input":"Hi.","voice":"af_sky","speed":0.25}`,
		"a fast speed":     `{"model":"m","input":"Hi.","voice":"af_sky","speed":4}`,
		"a string speed":   `{"model":"m","input":"Hi.","voice":"af_sky","speed":"1"}`,
		"an unknown field": `{"model":"m","input":"Hi.","voice":"af_sky","stream":true}`,
	} {
		_, err := speech.ParseRequest(strings.NewReader(body))
		if _, invalid := err.(strictjson.Invalid); !invalid {
			t.Errorf("%s: err %v, want a strictjson.Invalid the worker refuses as 400", name, err)
		}
	}
}

func TestARequestAndItsAudioPrintNoText(t *testing.T) {
	req, err := speech.ParseRequest(strings.NewReader(`{"model":"m","input":"my secret plan","voice":"af_sky"}`))
	if err != nil {
		t.Fatal(err)
	}
	audio := speech.NewAudio([]byte("ID3 my secret plan"))
	for _, printed := range []string{fmt.Sprint(req), fmt.Sprintf("%v %+v %#v", *req, *req, *req), fmt.Sprint(audio), fmt.Sprintf("%#v", audio)} {
		if strings.Contains(printed, "secret") {
			t.Errorf("printed %q, which holds the text", printed)
		}
	}
}
