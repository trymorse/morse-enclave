package openaicompat

import (
	"encoding/json"
	"math"
	"net/http"
	"slices"
	"strconv"

	"morse/backend/internal/apierr"
	"morse/backend/internal/catalog"
	"morse/backend/internal/chat"
	"morse/backend/internal/consoles"
)

var Settings = slices.Concat([]string{"n", "response_format", "seed", "stop", "temperature", "top_p"}, catalog.SamplingSettings())

// SettingsField is the key setting that lets Settings reach the host.
const SettingsField = "forward_settings"

// unhonoured are the fields that change the reply and that no host is sent, so an API key's chat that sets one is
// refused. Each maps to whether a value leaves the reply as it would be without the field.
var unhonoured = map[string]func(json.RawMessage) bool{
	"audio":              isNull,
	"logprobs":           isFalse,
	"modalities":         isTextOnly,
	"prediction":         isNull,
	"top_logprobs":       isZero,
	"verbosity":          isNull,
	"web_search_options": isNull,
}

var changesNothing = map[string]func(json.RawMessage) bool{
	"response_format":   isTextFormat,
	"frequency_penalty": isZero,
	"presence_penalty":  isZero,
	"logit_bias":        isEmptyObject,
}

// why: models is OpenRouter's list of models to fall back to when the first fails
// (https://openrouter.ai/docs/guides/routing/model-fallbacks). Morse fails over between one model's hosts, never to
// another model, whose price and terms the request did not ask for.
var errModelsList = apierr.Invalid(http.StatusBadRequest, "unsupported_parameter",
	"models is refused: Morse serves a request on the one model it names and fails over between that model's hosts, not to another model. "+
		"Send model alone, and try another model yourself when a request fails.").Naming("models")

func isOneModel(raw json.RawMessage) bool {
	var models []json.RawMessage
	return isNull(raw) || json.Unmarshal(raw, &models) == nil && len(models) <= 1
}

// maxStops is the most stop strings the OpenAI API takes.
const maxStops = 4

// SettingsForwarder is a provider that sends a call's Settings to its host.
type SettingsForwarder interface{ ForwardsSettings() }

func (*Provider) ForwardsSettings() {}

// SettingsOf reads the Settings an API key's plaintext chat sets, which forward lets reach the host, and refuses the
// chat when it sets one that forward does not let through or a field that no host is sent and that changes the reply.
// Every other field, such as user, metadata, store, or service_tier, is dropped as it is for every chat.
func SettingsOf(req *chat.Request, forward bool, console string) ([]string, error) {
	if raw, named := req.Field("models"); named && !isOneModel(raw) {
		return nil, errModelsList
	}
	for _, name := range req.FieldNames() {
		if noOp, ok := unhonoured[name]; ok {
			if raw, _ := req.Field(name); !noOp(raw) {
				return nil, unhonouredRefusal(name)
			}
		}
	}
	var set []string
	for _, name := range Settings {
		raw, ok := req.Field(name)
		if noOp := changesNothing[name]; !ok || isNull(raw) || noOp != nil && noOp(raw) {
			continue
		}
		if err := checkSetting(name, raw); err != nil {
			return nil, err
		}
		if !forward {
			return nil, settingOffRefusal(name, console)
		}
		set = append(set, name)
	}
	return set, nil
}

// SettingsRefusal answers a chat whose Settings no host of its model takes.
func SettingsRefusal(name string) error {
	return apierr.Invalid(http.StatusBadRequest, "unsupported_parameter",
		name+" is refused: no host that serves this model takes it through Morse. Send the request without "+name+".").Naming(name)
}

func ResponseFormatOf(req *chat.Request) (catalog.ResponseFormat, bool) {
	var format struct{ Type string }
	if req.Decode("response_format", &format) != nil {
		return 0, false
	}
	return catalog.ParseResponseFormat(format.Type)
}

func ResponseFormatRefusal(f catalog.ResponseFormat) error {
	return apierr.Invalid(http.StatusBadRequest, "unsupported_parameter",
		"response_format "+f.String()+" is refused: no host that serves this model through Morse honours it, so the reply would not follow it. "+
			"Send the request without response_format, with {\"type\":\"text\"}, or to a model whose hosts honour it.").Naming("response_format")
}

// why: a key cannot change its own settings, since PATCH /v1/keys/{id} takes a login, so the refusal sends the caller
// to the keys page of the console it signs in to.
func settingOffRefusal(name, console string) error {
	return apierr.Invalid(http.StatusBadRequest, "setting_not_forwarded",
		name+" is refused: this API key has \"Let my settings reach the model host\" ("+SettingsField+") turned off, so Morse would drop it. "+
			"Turn it back on for the key in the Morse developer console, at "+console+consoles.KeysPath+", or send the request without "+name+".").Naming(name)
}

func unhonouredRefusal(name string) error {
	return apierr.Invalid(http.StatusBadRequest, "unsupported_parameter",
		name+" is refused: Morse sends it to no host, so the reply would not follow it. Send the request without "+name+".").Naming(name)
}

// why: OpenAI takes at most 300 logit_bias entries; a host takes whatever its own body limit allows, so Morse holds the bound itself.
const maxLogitBias = 300

func checkSetting(name string, raw json.RawMessage) error {
	var ok bool
	switch name {
	case "n":
		var n json.Number
		ok = json.Unmarshal(raw, &n) == nil && n.String() == "1"
		if !ok {
			return apierr.InvalidParameter("n must be 1: Morse returns one choice per request.").Naming("n")
		}
	case "temperature":
		ok = numberWithin(raw, 0, 2)
	case "top_p":
		ok = numberWithin(raw, 0, 1)
	case "seed":
		var seed int64
		ok = json.Unmarshal(raw, &seed) == nil
	case "stop":
		ok = validStop(raw)
	case "top_k":
		var k int64
		ok = json.Unmarshal(raw, &k) == nil && k >= 0
	case "min_p":
		ok = numberWithin(raw, 0, 1)
	case "frequency_penalty", "presence_penalty":
		ok = numberWithin(raw, -2, 2)
	case "repetition_penalty":
		ok = numberWithin(raw, 0, 2)
	case "logit_bias":
		var bias map[string]float64
		ok = json.Unmarshal(raw, &bias) == nil && bias != nil && len(bias) <= maxLogitBias
		for token, value := range bias {
			if _, err := strconv.ParseUint(token, 10, 32); err != nil || value < -100 || value > 100 {
				ok = false
			}
		}
	case "response_format":
		var format struct{ Type string }
		if ok = json.Unmarshal(raw, &format) == nil; ok {
			_, ok = catalog.ParseResponseFormat(format.Type)
		}
	}
	if !ok {
		return apierr.InvalidParameter(name + " " + settingShapes[name]).Naming(name)
	}
	return nil
}

var settingShapes = map[string]string{
	"temperature":     "must be a number from 0 to 2.",
	"top_p":           "must be a number from 0 to 1.",
	"seed":            "must be an integer.",
	"stop":            "must be a string or an array of at most 4 strings.",
	"response_format": "must be an object whose type is text, json_object, or json_schema.",

	"top_k":              "must be a whole number from 0 up.",
	"min_p":              "must be a number from 0 to 1.",
	"frequency_penalty":  "must be a number from -2 to 2.",
	"presence_penalty":   "must be a number from -2 to 2.",
	"repetition_penalty": "must be a number from 0 to 2.",
	"logit_bias":         "must be an object of at most 300 token ids, each a whole number, to numbers from -100 to 100.",
}

func numberWithin(raw json.RawMessage, lo, hi float64) bool {
	var f float64
	return json.Unmarshal(raw, &f) == nil && !math.IsNaN(f) && f >= lo && f <= hi
}

func validStop(raw json.RawMessage) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return true
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && len(many) <= maxStops
}

func isFalse(raw json.RawMessage) bool {
	return isNull(raw) || string(raw) == "false"
}

func isZero(raw json.RawMessage) bool {
	var f float64
	return isNull(raw) || json.Unmarshal(raw, &f) == nil && f == 0
}

func isEmptyObject(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	return isNull(raw) || json.Unmarshal(raw, &m) == nil && len(m) == 0
}

func isTextOnly(raw json.RawMessage) bool {
	var m []string
	return isNull(raw) || json.Unmarshal(raw, &m) == nil && slices.Equal(m, []string{"text"})
}

func isTextFormat(raw json.RawMessage) bool {
	var format map[string]json.RawMessage
	if json.Unmarshal(raw, &format) != nil || len(format) != 1 {
		return false
	}
	return string(format["type"]) == `"text"`
}
