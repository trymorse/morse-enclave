package nras

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeNRAS struct {
	mu           sync.Mutex
	response     []byte
	jwks         [][]byte
	jwksHits     int
	attested     [][]byte
	attestedType []string
}

func (f *fakeNRAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == attestPath:
		body, _ := io.ReadAll(r.Body)
		f.attested = append(f.attested, body)
		f.attestedType = append(f.attestedType, r.Header.Get("Content-Type"))
		w.Write(f.response)
	case r.Method == http.MethodGet && r.URL.Path == jwksPath:
		served := f.jwks[min(f.jwksHits, len(f.jwks)-1)]
		f.jwksHits++
		w.Write(served)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeNRAS) hits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jwksHits
}

func (f *fakeNRAS) serve(response []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.response = response
}

func jwksWithout(t *testing.T, raw []byte, kid string) []byte {
	t.Helper()
	set, err := parseJWKS(raw)
	if err != nil {
		t.Fatal(err)
	}
	kept := set.Keys[:0]
	for _, k := range set.Keys {
		if k.Kid != kid {
			kept = append(kept, k)
		}
	}
	if len(kept) == len(set.Keys) {
		t.Fatalf("the jwks never listed %s", kid)
	}
	out, err := json.Marshal(jwks{Keys: kept})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func overallKid(t *testing.T, token string) string {
	t.Helper()
	headerSegment, _, _ := strings.Cut(token, ".")
	var header jwsHeader
	if err := decodeSegment(headerSegment, &header); err != nil {
		t.Fatal(err)
	}
	return header.Kid
}

func TestCacheRefetchesTheJWKSOnceForAnUnknownKid(t *testing.T) {
	overall, gpus := recordedTokens(t)
	full := readFile(t, recordedJWKSPath)
	payload := readFile(t, recordedRequestPath)
	nras := &fakeNRAS{
		response: readFile(t, recordedResponsePath),
		jwks:     [][]byte{jwksWithout(t, full, overallKid(t, overall)), full},
	}
	server := httptest.NewServer(nras)
	defer server.Close()
	cache := NewCache(Service{Base: server.URL, Client: server.Client()})
	ctx := context.Background()

	_, err := cache.VerifyGPU(ctx, payload, recordedNonce(t), recordedNow)
	if !errors.Is(err, ErrUnknownKID) || !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want %v as %v: the jwks fetched a moment ago cannot be refetched yet", err, ErrUnknownKID, ErrUnreachable)
	}
	if nras.hits() != 1 {
		t.Fatalf("jwks fetched %d times inside a minute, want 1", nras.hits())
	}

	refetchedAt := recordedNow.Add(jwksRefetchInterval)
	v, err := cache.VerifyGPU(ctx, payload, recordedNonce(t), refetchedAt)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Expires.Equal(time.Unix(recordedExp, 0)) {
		t.Errorf("expires %v, want %v", v.Expires, time.Unix(recordedExp, 0))
	}
	if nras.hits() != 2 {
		t.Fatalf("jwks fetched %d times, want 2", nras.hits())
	}
	if !bytes.Equal(nras.attested[0], payload) || nras.attestedType[0] != "application/json" {
		t.Errorf("attest got %d bytes as %q, want the payload unchanged as application/json", len(nras.attested[0]), nras.attestedType[0])
	}

	nras.serve(assemble(t, withKid(t, overall, unlistedKid), gpus))
	_, err = cache.VerifyGPU(ctx, payload, recordedNonce(t), refetchedAt.Add(jwksRefetchInterval-time.Second))
	if !errors.Is(err, ErrUnknownKID) || !errors.Is(err, ErrUnreachable) || errors.Is(err, ErrEvidence) {
		t.Fatalf("got %v, want %v as %v: no fresh jwks could judge the kid", err, ErrUnknownKID, ErrUnreachable)
	}
	if nras.hits() != 2 {
		t.Fatalf("an unknown kid within a minute refetched; jwks fetched %d times", nras.hits())
	}

	_, err = cache.VerifyGPU(ctx, payload, recordedNonce(t), refetchedAt.Add(jwksRefetchInterval))
	if !errors.Is(err, ErrUnknownKID) || errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want only %v: a fresh jwks that lacks the kid is a verdict", err, ErrUnknownKID)
	}
	if nras.hits() != 3 {
		t.Fatalf("an unknown kid a minute later did not refetch; jwks fetched %d times", nras.hits())
	}
}

func TestCacheRefetchesTheJWKSOnceItIsAnHourOldAndDetachesTheFetchFromTheCallersContext(t *testing.T) {
	payload := readFile(t, recordedRequestPath)
	entered, released := make(chan struct{}, 1), make(chan struct{})
	var jwksHits atomic.Int32
	nvidia := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == jwksPath {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-released
			jwksHits.Add(1)
			w.Write(readFile(t, recordedJWKSPath))
			return
		}
		w.Write(readFile(t, recordedResponsePath))
	}))
	defer nvidia.Close()
	cache := NewCache(Service{Base: nvidia.URL, Client: nvidia.Client()})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := cache.VerifyGPU(ctx, payload, recordedNonce(t), recordedNow)
		done <- err
	}()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("the canceled caller got %v, want its cancellation", err)
	}
	close(released)
	if _, err := cache.keyset(context.Background(), recordedNow.Add(jwksMaxAge-time.Second)); err != nil || jwksHits.Load() != 1 {
		t.Fatalf("within the max age: %v after %d jwks fetches, want the cached keys", err, jwksHits.Load())
	}
	if _, err := cache.keyset(context.Background(), recordedNow.Add(jwksMaxAge)); err != nil || jwksHits.Load() != 2 {
		t.Errorf("at the max age: %v after %d jwks fetches, want a refetch", err, jwksHits.Load())
	}
}

func TestAHungJWKSFetchDoesNotHoldACanceledWaiter(t *testing.T) {
	entered, released := make(chan struct{}, 1), make(chan struct{})
	nvidia := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-released
		w.Write(readFile(t, recordedJWKSPath))
	}))
	defer nvidia.Close()
	defer close(released)
	cache := NewCache(Service{Base: nvidia.URL, Client: nvidia.Client()})

	go cache.keyset(context.Background(), recordedNow)
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	waited := make(chan error, 1)
	go func() {
		_, err := cache.keyset(ctx, recordedNow)
		waited <- err
	}()
	cancel()
	select {
	case err := <-waited:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnreachable) {
			t.Errorf("the canceled waiter got %v, want its cancellation as %v", err, ErrUnreachable)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a canceled waiter is still blocked behind the hung jwks fetch")
	}
}

func TestServiceReportsTransportFailuresAsUnreachable(t *testing.T) {
	ctx := context.Background()
	payload := readFile(t, recordedRequestPath)

	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if _, err := (Service{Base: closed.URL, Client: closed.Client()}).Attest(ctx, payload); !errors.Is(err, ErrUnreachable) {
		t.Errorf("closed server attest: %v", err)
	}
	if _, err := (Service{Base: closed.URL, Client: closed.Client()}).JWKS(ctx); !errors.Is(err, ErrUnreachable) {
		t.Errorf("closed server jwks: %v", err)
	}

	unavailable := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer unavailable.Close()
	if _, err := (Service{Base: unavailable.URL, Client: unavailable.Client()}).Attest(ctx, payload); !errors.Is(err, ErrUnreachable) {
		t.Errorf("503 attest: %v", err)
	}
	if _, err := NewCache(Service{Base: unavailable.URL, Client: unavailable.Client()}).VerifyGPU(ctx, payload, recordedNonce(t), recordedNow); !errors.Is(err, ErrUnreachable) {
		t.Errorf("503 through the cache: %v", err)
	}

	garbage := httptest.NewServer(&fakeNRAS{response: []byte("<html>busy</html>"), jwks: [][]byte{readFile(t, recordedJWKSPath)}})
	defer garbage.Close()
	_, err := NewCache(Service{Base: garbage.URL, Client: garbage.Client()}).VerifyGPU(ctx, payload, recordedNonce(t), recordedNow)
	if !errors.Is(err, ErrEvidence) || errors.Is(err, ErrUnreachable) {
		t.Errorf("a 200 garbage body is a verdict, got %v", err)
	}

	garbageKeys := httptest.NewServer(&fakeNRAS{response: readFile(t, recordedResponsePath), jwks: [][]byte{[]byte("<html>busy</html>")}})
	defer garbageKeys.Close()
	if _, err := NewCache(Service{Base: garbageKeys.URL, Client: garbageKeys.Client()}).VerifyGPU(ctx, payload, recordedNonce(t), recordedNow); !errors.Is(err, ErrUnreachable) {
		t.Errorf("a jwks that does not parse is an outage, got %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = (Service{Base: unavailable.URL, Client: unavailable.Client()}).Attest(canceled, payload)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnreachable) {
		t.Errorf("a canceled context: %v", err)
	}
}

func TestServiceTakesOnlyA200AsAnAnswer(t *testing.T) {
	accepted := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Write(readFile(t, recordedJWKSPath))
	}))
	defer accepted.Close()
	if _, err := (Service{Base: accepted.URL, Client: accepted.Client()}).JWKS(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Errorf("a 202: %v, want %v", err, ErrUnreachable)
	}
}

func TestServiceRefusesAnOversizedBody(t *testing.T) {
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, maxBodyLen+1))
	}))
	defer huge.Close()
	if _, err := (Service{Base: huge.URL, Client: huge.Client()}).JWKS(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Errorf("an oversized body: %v", err)
	}
}

func TestNRASRefusingTheEvidenceIsAVerdictAndRefusingTheRequestOrFailingIsAnOutage(t *testing.T) {
	const (
		badChain    = `{"status":"BAD_REQUEST","errorCode":4007,"message":"INVALID_CERTIFICATE_CHAIN","debugMessage":"Invalid Certificate, please provide valid certificate","fieldName":"certificate","timestamp":"2026-10-03 10:45:31"}`
		badFormat   = `{"status":"BAD_REQUEST","errorCode":4006,"message":"INVALID_EVIDENCE_FORMAT","debugMessage":"Invalid Evidence format, please provide valid evidence","fieldName":"evidences","timestamp":"2026-10-03 10:45:31"}`
		badArch     = `{"status":"BAD_REQUEST","errorCode":4012,"message":"GPU_ARCHITECTURE_NOT_SUPPORTED","debugMessage":"GPU Architecture Not Supported","timestamp":"2026-10-03 10:45:31"}`
		ourNonce    = `{"status":"BAD_REQUEST","errorCode":4003,"message":"INVALID_NONCE","debugMessage":"Invalid Nonce, please provide valid nonce","fieldName":"nonce","timestamp":"2026-10-03 10:44:48"}`
		ourJSON     = `{"status":"BAD_REQUEST","errorCode":4400,"message":"JSON parse error: Unrecognized token 'xx'","debugMessage":"Invalid Request Body","timestamp":"2026-10-03 10:44:48"}`
		unreadable  = `<html>bad request</html>`
		evidenceish = `{"errorCode":4007}`
	)
	for _, c := range []struct {
		name    string
		status  int
		body    string
		verdict bool
	}{
		{"a 400 naming an invalid certificate chain", http.StatusBadRequest, badChain, true},
		{"a 400 naming an invalid evidence format", http.StatusBadRequest, badFormat, true},
		{"a 400 naming an unsupported GPU architecture", http.StatusBadRequest, badArch, true},
		{"a 400 naming our nonce field", http.StatusBadRequest, ourNonce, false},
		{"a 400 naming our request body", http.StatusBadRequest, ourJSON, false},
		{"a 400 with no error code", http.StatusBadRequest, unreadable, false},
		{"a 403 with an evidence error code", http.StatusForbidden, evidenceish, false},
		{"a 404", http.StatusNotFound, "", false},
		{"a 408", http.StatusRequestTimeout, "", false},
		{"a 429 with an evidence error code", http.StatusTooManyRequests, evidenceish, false},
		{"a 500 with an evidence error code", http.StatusInternalServerError, evidenceish, false},
		{"a 503", http.StatusServiceUnavailable, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				io.WriteString(w, c.body)
			}))
			defer srv.Close()
			_, err := NewCache(Service{Base: srv.URL, Client: srv.Client()}).VerifyGPU(context.Background(), readFile(t, recordedRequestPath), recordedNonce(t), recordedNow)
			if verdict := errors.Is(err, ErrEvidence) && !errors.Is(err, ErrUnreachable); verdict != c.verdict {
				t.Errorf("err %v, verdict %t, want %t", err, verdict, c.verdict)
			}
			if !c.verdict && !errors.Is(err, ErrUnreachable) {
				t.Errorf("err %v, want %v", err, ErrUnreachable)
			}
		})
	}
}
