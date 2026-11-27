package consoles

import "strings"

const (
	TryMorse       = "https://console.trymorse.ai"
	MorseInference = "https://console.morseinference.com"
	AddCreditsPath = "/credits?sheet=add-credits"
	KeysPath       = "/keys"
)

// why: a caller of a morseinference.com API name keeps its account on that site's console, a second build of
// TryMorse's. Every name the inference door serves under that domain is one of its API names, dev's included.
func Of(doorHost string) string {
	if strings.HasSuffix(doorHost, ".morseinference.com") {
		return MorseInference
	}
	return TryMorse
}
