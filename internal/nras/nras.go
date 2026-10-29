package nras

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	DefaultBase = "https://nras.attestation.nvidia.com"

	algES384          = "ES384"
	es384SignatureLen = 96
	jwsPartCount      = 3
	overallTokenKind  = "JWT"
	submodDigestKind  = "DIGEST"
	submodDigestAlg   = "SHA-256"
	measresSuccess    = "success"
	dbgstatDisabled   = "disabled"
	nbfLeeway         = time.Minute
)

var (
	ErrUnreachable = errors.New("nras: the attestation service could not be reached")
	ErrUnknownKID  = errors.New("nras: the token names a kid the jwks does not list")
	ErrEvidence    = errors.New("nras: the GPU evidence does not verify")
)

type GPU struct {
	Name string
	Arch string
	UEID string
}

type Verdict struct {
	GPUs     []GPU
	Expires  time.Time
	Response json.RawMessage
	X5C      map[string][]string
}

//go:embed nvidia_gpu_intermediate_004.pem
var nvidiaIntermediatePEM []byte

var roots = sync.OnceValue(func() *x509.CertPool {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(nvidiaIntermediatePEM) {
		panic("nras: embedded NVIDIA GPU intermediate does not parse")
	}
	return pool
})

func Roots() *x509.CertPool { return roots() }

type jwk struct {
	Kid string   `json:"kid"`
	X5c []string `json:"x5c"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func parseJWKS(raw []byte) (jwks, error) {
	var set jwks
	if err := json.Unmarshal(raw, &set); err != nil {
		return jwks{}, fmt.Errorf("jwks is not JSON: %w", err)
	}
	if len(set.Keys) == 0 {
		return jwks{}, errors.New("jwks lists no keys")
	}
	return set, nil
}

func (s jwks) chain(kid string) ([]string, bool) {
	for _, k := range s.Keys {
		if k.Kid == kid {
			return k.X5c, true
		}
	}
	return nil, false
}

type jwsHeader struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

type eatClaims struct {
	Exp      int64  `json:"exp"`
	Nbf      *int64 `json:"nbf"`
	EatNonce string `json:"eat_nonce"`
}

func (c eatClaims) check(nonce string, now time.Time) error {
	if !time.Unix(c.Exp, 0).After(now) {
		return fmt.Errorf("%w: the token expired at %d", ErrEvidence, c.Exp)
	}
	if c.Nbf != nil && time.Unix(*c.Nbf, 0).After(now.Add(nbfLeeway)) {
		return fmt.Errorf("%w: the token is not valid before %d", ErrEvidence, *c.Nbf)
	}
	if c.EatNonce != nonce {
		return fmt.Errorf("%w: eat_nonce %q is not our nonce", ErrEvidence, c.EatNonce)
	}
	return nil
}

type submodDigest [sha256.Size]byte

func (d *submodDigest) UnmarshalJSON(raw []byte) error {
	var outer []json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil {
		return err
	}
	if len(outer) != 2 {
		return fmt.Errorf("submod has %d elements, want 2", len(outer))
	}
	var kind string
	if err := json.Unmarshal(outer[0], &kind); err != nil || kind != submodDigestKind {
		return fmt.Errorf("submod kind is not %s", submodDigestKind)
	}
	var digest []string
	if err := json.Unmarshal(outer[1], &digest); err != nil || len(digest) != 2 || digest[0] != submodDigestAlg {
		return fmt.Errorf("submod digest is not a %s pair", submodDigestAlg)
	}
	sum, err := hex.DecodeString(digest[1])
	if err != nil || len(sum) != sha256.Size {
		return fmt.Errorf("submod digest %q is not a %s hex digest", digest[1], submodDigestAlg)
	}
	copy(d[:], sum)
	return nil
}

type overallClaims struct {
	eatClaims
	Result  bool                    `json:"x-nvidia-overall-att-result"`
	Submods map[string]submodDigest `json:"submods"`
}

type gpuClaims struct {
	eatClaims
	Measres    string `json:"measres"`
	Dbgstat    string `json:"dbgstat"`
	Secboot    bool   `json:"secboot"`
	NonceMatch bool   `json:"x-nvidia-gpu-attestation-report-nonce-match"`
	Hwmodel    string `json:"hwmodel"`
	UEID       string `json:"ueid"`
}

func (c gpuClaims) measured() error {
	switch {
	case c.Measres != measresSuccess:
		return fmt.Errorf("%w: measres is %q", ErrEvidence, c.Measres)
	case c.Dbgstat != dbgstatDisabled:
		return fmt.Errorf("%w: dbgstat is %q", ErrEvidence, c.Dbgstat)
	case !c.Secboot:
		return fmt.Errorf("%w: secure boot is off", ErrEvidence)
	case !c.NonceMatch:
		return fmt.Errorf("%w: the GPU report nonce did not match", ErrEvidence)
	}
	return nil
}

type response struct {
	overall string
	gpus    map[string]string
}

func parseResponse(raw []byte) (response, error) {
	var parts []json.RawMessage
	if err := json.Unmarshal(raw, &parts); err != nil || len(parts) != 2 {
		return response{}, fmt.Errorf("%w: the response is not a two-element array", ErrEvidence)
	}
	var overall []string
	if err := json.Unmarshal(parts[0], &overall); err != nil || len(overall) != 2 || overall[0] != overallTokenKind {
		return response{}, fmt.Errorf("%w: the first element is not a [%q, token] pair", ErrEvidence, overallTokenKind)
	}
	var gpus map[string]string
	if err := json.Unmarshal(parts[1], &gpus); err != nil || len(gpus) == 0 {
		return response{}, fmt.Errorf("%w: the second element is not a non-empty map of GPU tokens", ErrEvidence)
	}
	return response{overall: overall[1], gpus: gpus}, nil
}

func verify(raw []byte, keys jwks, nonce [32]byte, now time.Time, roots *x509.CertPool) (Verdict, error) {
	resp, err := parseResponse(raw)
	if err != nil {
		return Verdict{}, err
	}
	want := hex.EncodeToString(nonce[:])
	used := map[string][]string{}
	var overall overallClaims
	if err := verifyToken(resp.overall, keys, now, roots, used, &overall); err != nil {
		return Verdict{}, fmt.Errorf("overall token: %w", err)
	}
	if err := overall.check(want, now); err != nil {
		return Verdict{}, fmt.Errorf("overall token: %w", err)
	}
	if !overall.Result {
		return Verdict{}, fmt.Errorf("%w: the overall attestation result is not true", ErrEvidence)
	}
	if len(overall.Submods) != len(resp.gpus) {
		return Verdict{}, fmt.Errorf("%w: submods name %d GPUs but %d tokens came back", ErrEvidence, len(overall.Submods), len(resp.gpus))
	}
	gpus := make([]GPU, 0, len(resp.gpus))
	for _, name := range slices.Sorted(maps.Keys(resp.gpus)) {
		token := resp.gpus[name]
		digest := overall.Submods[name]
		if sha256.Sum256([]byte(token)) != digest {
			return Verdict{}, fmt.Errorf("%w: %s token is not the one the submods digest", ErrEvidence, name)
		}
		var claims gpuClaims
		if err := verifyToken(token, keys, now, roots, used, &claims); err != nil {
			return Verdict{}, fmt.Errorf("%s: %w", name, err)
		}
		if err := claims.check(want, now); err != nil {
			return Verdict{}, fmt.Errorf("%s: %w", name, err)
		}
		if err := claims.measured(); err != nil {
			return Verdict{}, fmt.Errorf("%s: %w", name, err)
		}
		gpus = append(gpus, GPU{Name: name, Arch: claims.Hwmodel, UEID: claims.UEID})
	}
	return Verdict{GPUs: gpus, Expires: time.Unix(overall.Exp, 0), Response: json.RawMessage(raw), X5C: used}, nil
}

func verifyToken(compact string, keys jwks, now time.Time, roots *x509.CertPool, used map[string][]string, claims any) error {
	parts := strings.Split(compact, ".")
	if len(parts) != jwsPartCount {
		return fmt.Errorf("%w: the token is not a compact JWS", ErrEvidence)
	}
	var header jwsHeader
	if err := decodeSegment(parts[0], &header); err != nil {
		return fmt.Errorf("%w: header: %w", ErrEvidence, err)
	}
	if header.Alg != algES384 {
		return fmt.Errorf("%w: alg %q is not %s", ErrEvidence, header.Alg, algES384)
	}
	if header.Kid == "" {
		return fmt.Errorf("%w: the header names no kid", ErrEvidence)
	}
	x5c, ok := keys.chain(header.Kid)
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownKID, header.Kid)
	}
	key, err := chainedKey(x5c, now, roots)
	if err != nil {
		return fmt.Errorf("%w: kid %s: %w", ErrEvidence, header.Kid, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != es384SignatureLen {
		return fmt.Errorf("%w: the signature is not a raw %d-byte %s signature", ErrEvidence, es384SignatureLen, algES384)
	}
	digest := sha512.Sum384([]byte(parts[0] + "." + parts[1]))
	r := new(big.Int).SetBytes(sig[:es384SignatureLen/2])
	s := new(big.Int).SetBytes(sig[es384SignatureLen/2:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return fmt.Errorf("%w: the %s signature does not verify under kid %s", ErrEvidence, algES384, header.Kid)
	}
	if err := decodeSegment(parts[1], claims); err != nil {
		return fmt.Errorf("%w: claims: %w", ErrEvidence, err)
	}
	used[header.Kid] = x5c
	return nil
}

func decodeSegment(segment string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.NewDecoder(bytes.NewReader(raw)).Decode(into)
}

func chainedKey(x5c []string, now time.Time, roots *x509.CertPool) (*ecdsa.PublicKey, error) {
	if len(x5c) == 0 {
		return nil, errors.New("x5c is empty")
	}
	certs := make([]*x509.Certificate, len(x5c))
	for i, encoded := range x5c {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d] is not base64: %w", i, err)
		}
		if certs[i], err = x509.ParseCertificate(der); err != nil {
			return nil, fmt.Errorf("x5c[%d]: %w", i, err)
		}
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	leaf := certs[0]
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, err
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() {
		return nil, errors.New("the leaf key is not ECDSA P-384")
	}
	return key, nil
}
