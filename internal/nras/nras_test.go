package nras

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	recordedNonceHex          = "de3f3ee94495798ea125bd1e4c6e20e8162c259dd38bf0c6a0c64e5b66a27390"
	recordedExp               = 1790834204
	nvidiaIntermediateSHA256  = "2df8907cf4d6c277b855d407ec178a649930a8e73f7294e8fce66e6ee27c5175"
	recordedResponsePath      = "testdata/nras-response.json"
	recordedJWKSPath          = "testdata/nras-jwks.json"
	recordedRequestPath       = "testdata/nras-request.json"
	recordedArch              = "GH100"
	recordedGPUCount          = 8
	recordedDriver            = "595.58.03"
	recordedVBIOS             = "96.00.CF.00.02"
	unlistedKid               = "nv-eat-kid-not-in-the-jwks"
	syntheticKid              = "synthetic-kid"
	overallResultClaim        = "x-nvidia-overall-att-result"
	submodsClaim              = "submods"
	eatNonceClaim             = "eat_nonce"
	measresClaim              = "measres"
	dbgstatClaim              = "dbgstat"
	secbootClaim              = "secboot"
	nonceMatchClaim           = "x-nvidia-gpu-attestation-report-nonce-match"
	syntheticGPUCount         = 2
	syntheticTokenLifetime    = time.Hour
	syntheticCertLifetimeDays = 2
)

func verifyRaw(raw, rawJWKS []byte, nonce [32]byte, now time.Time, roots *x509.CertPool) (Verdict, error) {
	keys, err := parseJWKS(rawJWKS)
	if err != nil {
		return Verdict{}, fmt.Errorf("%w: %w", ErrEvidence, err)
	}
	return verify(raw, keys, nonce, now, roots)
}

var recordedNow = time.Unix(1790830700, 0)

func recordedNonce(t *testing.T) [32]byte {
	t.Helper()
	raw, err := hex.DecodeString(recordedNonceHex)
	if err != nil || len(raw) != 32 {
		t.Fatalf("recorded nonce: %v", err)
	}
	return [32]byte(raw)
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func recordedTokens(t *testing.T) (string, map[string]string) {
	t.Helper()
	return tokensOf(t, readFile(t, recordedResponsePath))
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assemble(t *testing.T, overall string, gpus map[string]string) []byte {
	t.Helper()
	return marshal(t, []any{[]string{overallTokenKind, overall}, gpus})
}

func segment(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func withKid(t *testing.T, token, kid string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	parts[0] = segment(t, jwsHeader{Kid: kid, Alg: algES384})
	return strings.Join(parts, ".")
}

func withFlippedSignature(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(sig)
	return strings.Join(parts, ".")
}

func selfSignedRoot(t *testing.T) *x509.CertPool {
	t.Helper()
	ca := newAuthority(t, recordedNow)
	return ca.roots
}

func withGPUsInReverseOrder(t *testing.T, overall string, gpus map[string]string) []byte {
	t.Helper()
	names := slices.Sorted(maps.Keys(gpus))
	slices.Reverse(names)
	members := make([]string, len(names))
	for i, name := range names {
		members[i] = string(marshal(t, name)) + ":" + string(marshal(t, gpus[name]))
	}
	return []byte("[" + string(marshal(t, []string{overallTokenKind, overall})) + ",{" + strings.Join(members, ",") + "}]")
}

func TestRecordedNRASResponseVerifiesUnderThePinnedIntermediate(t *testing.T) {
	overall, gpus := recordedTokens(t)
	for _, response := range [][]byte{readFile(t, recordedResponsePath), withGPUsInReverseOrder(t, overall, gpus)} {
		assertRecordedVerdict(t, response)
	}
}

func assertRecordedVerdict(t *testing.T, response []byte) {
	t.Helper()
	v, err := verifyRaw(response, readFile(t, recordedJWKSPath), recordedNonce(t), recordedNow, Roots())
	if err != nil {
		t.Fatal(err)
	}
	if !v.Expires.Equal(time.Unix(recordedExp, 0)) {
		t.Errorf("Expires %v, want %v", v.Expires, time.Unix(recordedExp, 0))
	}
	if len(v.GPUs) != recordedGPUCount {
		t.Fatalf("got %d GPUs, want %d", len(v.GPUs), recordedGPUCount)
	}
	ueids := map[string]bool{}
	for i, gpu := range v.GPUs {
		want := GPU{Name: "GPU-" + string(rune('0'+i)), Arch: recordedArch, UEID: gpu.UEID}
		if gpu != want || len(gpu.UEID) < 16 || ueids[gpu.UEID] {
			t.Errorf("GPUs[%d] = %+v, want %+v with a ueid no other GPU carries", i, gpu, want)
		}
		ueids[gpu.UEID] = true
	}
}

func TestTheRelayedResponseAndItsKidChainsReverifyToTheSameVerdict(t *testing.T) {
	response := readFile(t, recordedResponsePath)
	full, err := parseJWKS(readFile(t, recordedJWKSPath))
	if err != nil {
		t.Fatal(err)
	}
	v, err := verifyRaw(response, readFile(t, recordedJWKSPath), recordedNonce(t), recordedNow, Roots())
	if err != nil {
		t.Fatal(err)
	}
	if string(v.Response) != string(response) {
		t.Fatal("Response is not the verbatim NRAS reply")
	}
	if len(v.X5C) == 0 || len(v.X5C) >= len(full.Keys) {
		t.Fatalf("X5C names %d kids of the %d the jwks lists, want only the ones the tokens use", len(v.X5C), len(full.Keys))
	}
	relayed := jwks{}
	for _, kid := range slices.Sorted(maps.Keys(v.X5C)) {
		relayed.Keys = append(relayed.Keys, jwk{Kid: kid, X5c: v.X5C[kid]})
	}
	again, err := verifyRaw(v.Response, marshal(t, relayed), recordedNonce(t), recordedNow, Roots())
	if err != nil {
		t.Fatalf("the relayed response does not reverify under its own kid chains: %v", err)
	}
	if !slices.Equal(again.GPUs, v.GPUs) || !again.Expires.Equal(v.Expires) {
		t.Errorf("reverified to %+v, want %+v", again, v)
	}
}

func TestRecordedTampersAreRefused(t *testing.T) {
	overall, gpus := recordedTokens(t)
	response := readFile(t, recordedResponsePath)
	jwksRaw := readFile(t, recordedJWKSPath)
	otherNonce := recordedNonce(t)
	otherNonce[0] ^= 1
	swapped := map[string]string{}
	for name, token := range gpus {
		swapped[name] = token
	}
	swapped["GPU-0"] = gpus["GPU-1"]

	cases := []struct {
		name     string
		response []byte
		nonce    [32]byte
		now      time.Time
		roots    *x509.CertPool
		want     error
	}{
		{name: "a nonce one byte off", nonce: otherNonce, want: ErrEvidence},
		{name: "a check after exp", now: time.Unix(recordedExp, 0), want: ErrEvidence},
		{name: "a flipped overall signature byte", response: assemble(t, withFlippedSignature(t, overall), gpus), want: ErrEvidence},
		{name: "a GPU token swapped for another GPU's", response: assemble(t, overall, swapped), want: ErrEvidence},
		{name: "an overall kid the jwks does not list", response: assemble(t, withKid(t, overall, unlistedKid), gpus), want: ErrUnknownKID},
		{name: "an empty root pool", roots: x509.NewCertPool(), want: ErrEvidence},
		{name: "a root pool that is not NVIDIA's", roots: selfSignedRoot(t), want: ErrEvidence},
		{name: "a body that is not an array", response: []byte(`{"JWT":"x"}`), want: ErrEvidence},
		{name: "a three-element array", response: []byte(`[["JWT","x"],{"GPU-0":"y"},{}]`), want: ErrEvidence},
		{name: "a first element labelled other than JWT", response: marshal(t, []any{[]string{"JWE", overall}, gpus}), want: ErrEvidence},
		{name: "a first element longer than a pair", response: marshal(t, []any{[]string{overallTokenKind, overall, overall}, gpus}), want: ErrEvidence},
		{name: "no GPU tokens", response: assemble(t, overall, map[string]string{}), want: ErrEvidence},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.response == nil {
				c.response = response
			}
			if c.nonce == ([32]byte{}) {
				c.nonce = recordedNonce(t)
			}
			if c.now.IsZero() {
				c.now = recordedNow
			}
			if c.roots == nil {
				c.roots = Roots()
			}
			_, err := verifyRaw(c.response, jwksRaw, c.nonce, c.now, c.roots)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if errors.Is(c.want, ErrUnknownKID) && errors.Is(err, ErrEvidence) {
				t.Errorf("an unknown kid is its own class, got %v", err)
			}
		})
	}
}

func TestNVIDIAIntermediateIsThePinnedGPUIntermediate004(t *testing.T) {
	block, _ := pem.Decode(nvidiaIntermediatePEM)
	if block == nil {
		t.Fatal("embedded intermediate is not PEM")
	}
	if sum := sha256.Sum256(block.Bytes); hex.EncodeToString(sum[:]) != nvidiaIntermediateSHA256 {
		t.Errorf("embedded intermediate fingerprint %x, want %s", sum, nvidiaIntermediateSHA256)
	}
}

type authority struct {
	roots *x509.CertPool
	jwks  []byte
	key   *ecdsa.PrivateKey
}

func newAuthority(t *testing.T, leafNotAfter time.Time) authority {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "synthetic NRAS CA"},
		NotBefore:             recordedNow.AddDate(-1, 0, 0),
		NotAfter:              recordedNow.AddDate(1, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "synthetic NRAS signer"},
		NotBefore:    leafNotAfter.AddDate(0, 0, -syntheticCertLifetimeDays),
		NotAfter:     leafNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	set, err := json.Marshal(jwks{Keys: []jwk{{Kid: syntheticKid, X5c: []string{
		base64.StdEncoding.EncodeToString(leafDER),
		base64.StdEncoding.EncodeToString(caDER),
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return authority{roots: pool, jwks: set, key: leafKey}
}

func (a authority) sign(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	signing := segment(t, jwsHeader{Kid: syntheticKid, Alg: alg}) + "." + segment(t, claims)
	digest := sha512.Sum384([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, es384SignatureLen)
	r.FillBytes(sig[:es384SignatureLen/2])
	s.FillBytes(sig[es384SignatureLen/2:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type evidenceEdit struct {
	gpu        func(claims map[string]any)
	overall    func(claims map[string]any, tokens map[string]string)
	overallAlg string
}

func (a authority) response(t *testing.T, nonce [32]byte, edit evidenceEdit) []byte {
	t.Helper()
	exp := recordedNow.Add(syntheticTokenLifetime).Unix()
	tokens := map[string]string{}
	submods := map[string]any{}
	for i := range syntheticGPUCount {
		name := "GPU-" + string(rune('0'+i))
		claims := map[string]any{
			"exp":                         exp,
			"nbf":                         recordedNow.Unix(),
			eatNonceClaim:                 hex.EncodeToString(nonce[:]),
			measresClaim:                  measresSuccess,
			dbgstatClaim:                  dbgstatDisabled,
			secbootClaim:                  true,
			nonceMatchClaim:               true,
			"hwmodel":                     recordedArch,
			"x-nvidia-gpu-driver-version": recordedDriver,
			"x-nvidia-gpu-vbios-version":  recordedVBIOS,
		}
		if edit.gpu != nil {
			edit.gpu(claims)
		}
		tokens[name] = a.sign(t, algES384, claims)
		sum := sha256.Sum256([]byte(tokens[name]))
		submods[name] = []any{submodDigestKind, []string{submodDigestAlg, hex.EncodeToString(sum[:])}}
	}
	overall := map[string]any{
		"exp":              exp,
		"nbf":              recordedNow.Unix(),
		eatNonceClaim:      hex.EncodeToString(nonce[:]),
		overallResultClaim: true,
		submodsClaim:       submods,
	}
	if edit.overall != nil {
		edit.overall(overall, tokens)
	}
	alg := edit.overallAlg
	if alg == "" {
		alg = algES384
	}
	return assemble(t, a.sign(t, alg, overall), tokens)
}

func unsigned(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	return segment(t, jwsHeader{Kid: syntheticKid, Alg: alg}) + "." + segment(t, claims) + "."
}

func TestSyntheticEvidenceVerifiesUnderItsOwnCA(t *testing.T) {
	ca := newAuthority(t, recordedNow.Add(syntheticTokenLifetime))
	nonce := recordedNonce(t)
	v, err := verifyRaw(ca.response(t, nonce, evidenceEdit{}), ca.jwks, nonce, recordedNow, ca.roots)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Expires.Equal(recordedNow.Add(syntheticTokenLifetime)) {
		t.Errorf("expires %v, want the synthetic token's exp %v", v.Expires, recordedNow.Add(syntheticTokenLifetime))
	}
	minted := evidenceEdit{
		gpu:     func(c map[string]any) { c["nbf"] = recordedNow.Add(nbfLeeway).Unix() },
		overall: func(c map[string]any, _ map[string]string) { c["nbf"] = recordedNow.Add(nbfLeeway).Unix() },
	}
	if _, err := verifyRaw(ca.response(t, nonce, minted), ca.jwks, nonce, recordedNow, ca.roots); err != nil {
		t.Errorf("a verdict NVIDIA minted just after our clock read: %v", err)
	}
}

func TestSyntheticRefusals(t *testing.T) {
	ca := newAuthority(t, recordedNow.Add(syntheticTokenLifetime))
	expiredLeaf := newAuthority(t, recordedNow.Add(-time.Minute))
	stranger := newAuthority(t, recordedNow.Add(syntheticTokenLifetime))
	nonce := recordedNonce(t)
	otherNonce := hex.EncodeToString(append([]byte{1}, nonce[1:]...))
	set := func(key string, value any) func(map[string]any) {
		return func(claims map[string]any) { claims[key] = value }
	}

	cases := []struct {
		name     string
		signer   authority
		edit     evidenceEdit
		response func() []byte
		roots    *x509.CertPool
	}{
		{name: "an overall result of false", edit: evidenceEdit{overall: func(c map[string]any, _ map[string]string) { c[overallResultClaim] = false }}},
		{name: "an overall eat_nonce for another nonce", edit: evidenceEdit{overall: func(c map[string]any, _ map[string]string) { c[eatNonceClaim] = otherNonce }}},
		{name: "a GPU eat_nonce for another nonce", edit: evidenceEdit{gpu: set(eatNonceClaim, otherNonce)}},
		{name: "a failed measurement", edit: evidenceEdit{gpu: set(measresClaim, "fail")}},
		{name: "debug enabled", edit: evidenceEdit{gpu: set(dbgstatClaim, "enabled")}},
		{name: "secure boot off", edit: evidenceEdit{gpu: set(secbootClaim, false)}},
		{name: "a GPU report nonce mismatch", edit: evidenceEdit{gpu: set(nonceMatchClaim, false)}},
		{name: "a GPU expired before now", edit: evidenceEdit{gpu: set("exp", recordedNow.Unix())}},
		{name: "a GPU not yet valid", edit: evidenceEdit{gpu: set("nbf", recordedNow.Add(nbfLeeway+time.Second).Unix())}},
		{name: "a submod GPU with no token", edit: evidenceEdit{overall: func(_ map[string]any, tokens map[string]string) { delete(tokens, "GPU-1") }}},
		{name: "a GPU token with no submod", edit: evidenceEdit{overall: func(c map[string]any, _ map[string]string) { delete(c[submodsClaim].(map[string]any), "GPU-1") }}},
		{name: "submods naming a GPU other than the tokens", edit: evidenceEdit{overall: func(c map[string]any, _ map[string]string) {
			submods := c[submodsClaim].(map[string]any)
			submods["GPU-9"] = submods["GPU-1"]
			delete(submods, "GPU-1")
		}}},
		{name: "a submod that is not a SHA-256 digest", edit: evidenceEdit{overall: func(c map[string]any, _ map[string]string) {
			submods := c[submodsClaim].(map[string]any)
			digest := submods["GPU-1"].([]any)[1].([]string)[1]
			submods["GPU-1"] = []any{submodDigestKind, []string{"SHA-384", digest}}
		}}},
		{name: "an overall alg of ES256", edit: evidenceEdit{overallAlg: "ES256"}},
		{name: "a leaf chained to a CA other than the roots", signer: stranger, roots: ca.roots},
		{name: "a leaf certificate past its NotAfter", signer: expiredLeaf},
		{name: "an overall alg of none", response: func() []byte {
			_, gpus := tokensOf(t, ca.response(t, nonce, evidenceEdit{}))
			return assemble(t, unsigned(t, "none", map[string]any{"exp": recordedNow.Add(time.Hour).Unix(), eatNonceClaim: hex.EncodeToString(nonce[:]), overallResultClaim: true}), gpus)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			signer := ca
			if c.signer.key != nil {
				signer = c.signer
			}
			var response []byte
			if c.response != nil {
				response = c.response()
			} else {
				response = signer.response(t, nonce, c.edit)
			}
			roots := signer.roots
			if c.roots != nil {
				roots = c.roots
			}
			_, err := verifyRaw(response, signer.jwks, nonce, recordedNow, roots)
			if !errors.Is(err, ErrEvidence) {
				t.Fatalf("got %v, want %v", err, ErrEvidence)
			}
		})
	}
}

func tokensOf(t *testing.T, raw []byte) (string, map[string]string) {
	t.Helper()
	resp, err := parseResponse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return resp.overall, resp.gpus
}
