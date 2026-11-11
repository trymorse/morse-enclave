package openaicompat

import (
	"encoding/json"
	"math"
	"net/http"
	"slices"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
)

// Settings are the fields of an API key's chat that change the reply and reach the host only when the key lets its
// settings reach the model host. response_format is one, but no endpoint records that it honours it, so it is refused
// on every key, whatever the key setting.
var Settings = []string{"n", "response_format", "seed", "stop", "temperature", "top_p"}

// SettingsField is the key setting that lets Settings reach the host.
const SettingsField = "forward_settings"

// unhonoured are the fields that change the reply and that no host is sent, so an API key's chat that sets one is
// refused. Each maps to whether a value leaves the reply as it would be without the field.
var unhonoured = map[string]func(json.RawMessage) bool{
	"audio":              isNull,
	"frequency_penalty":  isZero,
	"logit_bias":         isEmptyObject,
	"logprobs":           isFalse,
	"min_p":              isNull,
	"modalities":         isTextOnly,
	"prediction":         isNull,
	"presence_penalty":   isZero,
	"repetition_penalty": isNull,
	"top_k":              isNull,
	"top_logprobs":       isZero,
	"verbosity":          isNull,
	"web_search_options": isNull,
}

// maxStops is the most stop strings the OpenAI API takes.
const maxStops = 4

// SettingsForwarder is a provider that sends a call's Settings to its host.
type SettingsForwarder interface{ ForwardsSettings() }

func (*Provider) ForwardsSettings() {}

// SettingsOf reads the Settings an API key's plaintext chat sets, which forward lets reach the host, and refuses the
// chat when it sets one that forward does not let through or a field that no host is sent and that changes the reply.
// Every other field, such as user, metadata, store, or service_tier, is dropped as it is for every chat.
func SettingsOf(req *chat.Request, forward bool) ([]string, error) {
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
		if !ok || isNull(raw) || name == "response_format" && isTextFormat(raw) {
			continue
		}
		if err := checkSetting(name, raw); err != nil {
			return nil, err
		}
		if name == "response_format" {
			return nil, errResponseFormat
		}
		if !forward {
			return nil, settingOffRefusal(name)
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

var errResponseFormat = apierr.Invalid(http.StatusBadRequest, "unsupported_parameter",
	"response_format is refused: no Morse endpoint records that it honours response_format, so it is never sent to a host. Send the request without response_format, or with {\"type\":\"text\"}.").Naming("response_format")

func settingOffRefusal(name string) error {
	return apierr.Invalid(http.StatusBadRequest, "setting_not_forwarded",
		name+" is refused: this API key does not let request settings reach the model host, so Morse would drop it. "+
			"Turn on \"Let my settings reach the model host\" ("+SettingsField+") on the key's page in the Morse web app, or send the request without "+name+".").Naming(name)
}

func unhonouredRefusal(name string) error {
	return apierr.Invalid(http.StatusBadRequest, "unsupported_parameter",
		name+" is refused: Morse sends it to no host, so the reply would not follow it. Send the request without "+name+".").Naming(name)
}

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
	case "response_format":
		var format struct{ Type string }
		ok = json.Unmarshal(raw, &format) == nil && format.Type != ""
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
	"response_format": "must be an object with a type.",
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
