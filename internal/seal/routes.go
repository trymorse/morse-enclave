package seal

const (
	MaxBody           = 32 << 20
	Endpoint          = "POST /v1/sealed"
	ContentType       = "application/morse-sealed"
	DoorClientAddress = "Door-Client-Address"
)

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
	{Pattern: "POST /v1/plugins/call", Sealed: true},
	{Pattern: "POST /v1/plugins/token", Sealed: true},
	{Pattern: "POST /v1/plugins/revoke", Sealed: true},
	{Pattern: "POST /v1/tasks", Sealed: true},
	{Pattern: "POST /v1/tasks/{id}/bundle", Sealed: true},
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
