package worker

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestAProviderOnAContentRouteOtherThanChatIsAnUnknownFieldNotDropped(t *testing.T) {
	w, err := NewInProcess(Config{})
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{ImagesPattern, VideosPattern, SearchPattern, FetchPattern, ResearchPattern} {
		method, path, _ := strings.Cut(pattern, " ")
		_, err := w.Open(context.Background(), Opening{Method: method, Path: path, Header: http.Header{}, Body: strings.NewReader(`{"provider":{"min_privacy":"tee"},"model":"m"}`)})
		if refusal := refusalOf(t, err); refusal.Code != "invalid_parameter" || refusal.Message != `Unknown field "provider".` {
			t.Errorf("%s: refused with %+v, want invalid_parameter naming provider", pattern, refusal)
		}
	}
}
