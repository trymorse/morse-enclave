package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"morse/backend/internal/catalog"
)

func TestTheSealVectorsListExactlyTheRoutesTheWorkerOpensSealed(t *testing.T) {
	raw, err := os.ReadFile("../seal/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Patterns []string `json:"sealable_patterns"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(v.Patterns, SealablePatterns) {
		t.Errorf("internal/seal/testdata/vectors.json lists %q as sealable_patterns and the worker opens %q sealed; edit the file's list", v.Patterns, SealablePatterns)
	}
}

func TestOpenTakesARouteOnlyUnderItsOwnMethodAndReadsTheJobIDFromThePath(t *testing.T) {
	w, err := NewInProcess(Config{Models: map[string]Model{"vid": {Tier: catalog.Private, Serves: Videos{queuedVideos{}}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		method, path string
		want         string
	}{
		{http.MethodPost, "/v1/videos", "worker.MediaAdmission"},
		{http.MethodGet, "/v1/videos", "not_found"},
		{"", "/v1/videos", "not_found"},
		{http.MethodGet, "/v1/videos/video_7/content", "video_7"},
		{http.MethodGet, "/v1/research/research_9/events", "research_9"},
		{http.MethodGet, "/v1/research/research_9", "research_9"},
		{http.MethodGet, "/v1/research/research_9/", "not_found"},
		{http.MethodGet, "/v1/research//events", "not_found"},
		{http.MethodPost, "/v1/videos/video_7/content", "not_found"},
	} {
		admitted, err := w.Open(context.Background(), Opening{Method: c.method, Path: c.path, Body: strings.NewReader(`{"model":"vid","prompt":"p","seconds":5}`)})
		got := "not_found"
		switch a := admitted.(type) {
		case ReadAdmission:
			got = a.JobID
			w.Cut(a.Handle(), 0)
		case nil:
			if err != errNoSuchRoute {
				got = err.Error()
			}
		default:
			got = "worker.MediaAdmission"
			w.Cut(a.Handle(), 0)
		}
		if got != c.want {
			t.Errorf("%s %s opened %q, want %q", c.method, c.path, got, c.want)
		}
	}
}
