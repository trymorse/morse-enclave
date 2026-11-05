package seal

type Route struct {
	Pattern string
	Sealed  bool
}

var Routes = []Route{
	{Pattern: "POST /v1/chat/completions", Sealed: true},
	{Pattern: "POST /v1/chat/compact", Sealed: true},
	{Pattern: "POST /v1/images/generations", Sealed: true},
	{Pattern: "POST /v1/videos", Sealed: true},
	{Pattern: "GET /v1/videos/{id}/content", Sealed: true},
	{Pattern: "POST /v1/search", Sealed: true},
	{Pattern: "POST /v1/fetch", Sealed: true},
	{Pattern: "POST /v1/research", Sealed: true},
	{Pattern: "GET /v1/research/{id}", Sealed: true},
	{Pattern: "GET /v1/research/{id}/events", Sealed: true},
	{Pattern: "GET /v1/lookup/{service}/{path...}", Sealed: true},
	{Pattern: "POST /v1/audio/transcriptions", Sealed: true},
	{Pattern: "GET /v1/models"},
	{Pattern: "GET /v1/attestation"},
	{Pattern: "GET /v1/receipts/{id}"},
	{Pattern: "GET /v1/videos/{id}"},
}

func SealedPatterns() []string {
	var patterns []string
	for _, rt := range Routes {
		if rt.Sealed {
			patterns = append(patterns, rt.Pattern)
		}
	}
	return patterns
}
