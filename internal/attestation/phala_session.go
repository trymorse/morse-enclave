package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"morse/backend/internal/dataurl"
	"morse/backend/internal/jcs"
)

const (
	PhalaDirectVerifier = "private-ai-verifier/phala-direct/v1"
	sessionAPIVersion   = "aci/1"
	spkiBinding         = "tls_spki_sha256"
	signingAddressLen   = 20
)

var (
	ErrSessionID          = errors.New("attestation: the session record does not hash to its id")
	ErrNotPhalaDirect     = errors.New("attestation: the session record is not a phala-direct one")
	ErrSessionShape       = errors.New("attestation: the phala-direct session record is malformed")
	ErrSessionEvidence    = errors.New("attestation: the session evidence does not hash to the digest its record names")
	ErrSessionChannelBind = errors.New("attestation: no channel binding names the TLS key the quote binds at the record's endpoint")
)

type phalaSession struct {
	APIVersion string `json:"api_version"`
	VerifierID string `json:"verifier_id"`
	Endpoint   string `json:"endpoint"`
	Evidence   struct {
		Data   string `json:"data"`
		Digest string `json:"digest"`
	} `json:"evidence"`
	ChannelBinding []channelBinding `json:"channel_binding"`
	Claims         struct {
		Extra struct {
			CanonicalModelID string `json:"canonical_model_id"`
		} `json:"extra"`
	} `json:"claims"`
}

type channelBinding struct {
	Type       string `json:"type"`
	Origin     string `json:"origin"`
	SPKISHA256 string `json:"spki_sha256"`
}

type phalaDirectEvidence struct {
	SigningAddress string          `json:"signing_address"`
	Quote          string          `json:"intel_quote"`
	EventLog       json.RawMessage `json:"event_log"`
	Info           struct {
		TCBInfo json.RawMessage `json:"tcb_info"`
	} `json:"info"`
	TLSFingerprint string `json:"tls_cert_fingerprint"`
	RequestNonce   string `json:"request_nonce"`
	NvidiaPayload  string `json:"nvidia_payload"`
}

// PhalaDirectSession is a phala-direct model server as its session record's evidence measures it.
type PhalaDirectSession struct {
	Workload
	Model    string
	Endpoint string
	Compose  AppCompose
}

// VerifyPhalaDirectSession runs the checks a browser runs on the record a receipt cites: the record hashes
// to id in its RFC 8785 form, its evidence to the digest it names, and the evidence's quote verifies under
// Intel's collateral, binds sha256(signing address || TLS fingerprint) then the gateway's challenge, and
// measures the event log and app_compose. A binding then names that TLS key at the record's endpoint. Any
// TCB status Intel lists short of Revoked is recorded, not refused, as the browser does. The GPUs are not
// judged here.
func (p Policy) VerifyPhalaDirectSession(ctx context.Context, id string, record []byte) (PhalaDirectSession, error) {
	canonical, err := jcs.Canonicalize(record)
	if err != nil {
		return PhalaDirectSession{}, fmt.Errorf("%w: %w", ErrSessionShape, err)
	}
	if sum := sha256.Sum256(canonical); hex.EncodeToString(sum[:]) != id {
		return PhalaDirectSession{}, fmt.Errorf("%w: sha256 %x, id %s", ErrSessionID, sum, id)
	}
	var s phalaSession
	if err := json.Unmarshal(record, &s); err != nil {
		return PhalaDirectSession{}, fmt.Errorf("%w: %w", ErrSessionShape, err)
	}
	if s.APIVersion != sessionAPIVersion || s.VerifierID != PhalaDirectVerifier {
		return PhalaDirectSession{}, fmt.Errorf("%w: %s %s", ErrNotPhalaDirect, s.APIVersion, s.VerifierID)
	}
	raw, err := evidenceBytes(s.Evidence.Data)
	if err != nil {
		return PhalaDirectSession{}, fmt.Errorf("%w: %w", ErrSessionShape, err)
	}
	if sum := sha256.Sum256(raw); "sha256:"+hex.EncodeToString(sum[:]) != s.Evidence.Digest {
		return PhalaDirectSession{}, fmt.Errorf("%w: sha256:%x, the record names %s", ErrSessionEvidence, sum, s.Evidence.Digest)
	}
	var e phalaDirectEvidence
	if err := json.Unmarshal(raw, &e); err != nil {
		return PhalaDirectSession{}, fmt.Errorf("%w: the evidence: %w", ErrSessionShape, err)
	}
	address, err := sized(e.SigningAddress, signingAddressLen, "signing_address")
	if err != nil {
		return PhalaDirectSession{}, err
	}
	fingerprint, err := sized(e.TLSFingerprint, sha256.Size, "tls_cert_fingerprint")
	if err != nil {
		return PhalaDirectSession{}, err
	}
	nonce, err := sized(e.RequestNonce, len(Nonce{}), "request_nonce")
	if err != nil {
		return PhalaDirectSession{}, err
	}
	var tcb struct {
		AppCompose string `json:"app_compose"`
	}
	if err := json.Unmarshal(unquoted(e.Info.TCBInfo), &tcb); err != nil || tcb.AppCompose == "" {
		return PhalaDirectSession{}, fmt.Errorf("%w: info.tcb_info carries no app_compose", ErrSessionShape)
	}
	bound := nearReportData(sha256.Sum256(slices.Concat(address, fingerprint)), Nonce(nonce))
	w, err := p.measure(ctx, dstackEvidence{Quote: e.Quote, EventLog: e.EventLog, AppCompose: tcb.AppCompose}, bound, p.now(), reportTCBStatus)
	if err != nil {
		return PhalaDirectSession{}, err
	}
	spki := hex.EncodeToString(fingerprint)
	if !slices.ContainsFunc(s.ChannelBinding, func(b channelBinding) bool {
		return b.Type == spkiBinding && strings.ToLower(b.SPKISHA256) == spki && b.Origin == s.Endpoint
	}) {
		return PhalaDirectSession{}, fmt.Errorf("%w: %s at %s", ErrSessionChannelBind, spki, s.Endpoint)
	}
	compose, err := ParseAppCompose(tcb.AppCompose)
	if err != nil {
		return PhalaDirectSession{}, fmt.Errorf("%w: %w", ErrSessionShape, err)
	}
	return PhalaDirectSession{Workload: w, Model: s.Claims.Extra.CanonicalModelID, Endpoint: s.Endpoint, Compose: compose}, nil
}

func sized(text string, n int, what string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(text, "0x"))
	if err != nil || len(b) != n {
		return nil, fmt.Errorf("%w: %s %q is not %d bytes of hex", ErrSessionShape, what, text, n)
	}
	return b, nil
}

// PhalaDirectGPUVerdict relays NRAS's verdict on a phala-direct session record's nvidia_payload, under the
// payload's own nonce, so a browser can judge the tokens itself. It judges nothing else in the record: whether
// that nonce is the session's is the browser's check. It is nil with no error for a record from another
// verifier or evidence with no nvidia_payload.
func (p Policy) PhalaDirectGPUVerdict(ctx context.Context, record []byte) (*GPUVerdict, error) {
	var s phalaSession
	if err := json.Unmarshal(record, &s); err != nil {
		return nil, fmt.Errorf("%w: the session record: %w", ErrGPU, err)
	}
	if s.VerifierID != PhalaDirectVerifier {
		return nil, nil
	}
	payload, err := phalaDirectPayload(s.Evidence.Data)
	if err != nil || payload == "" {
		return nil, err
	}
	var bound struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(payload), &bound); err != nil {
		return nil, fmt.Errorf("%w: nvidia_payload: %w", ErrGPU, err)
	}
	nonce, err := hex.DecodeString(bound.Nonce)
	if err != nil || len(nonce) != len(Nonce{}) {
		return nil, fmt.Errorf("%w: nvidia_payload nonce %q is not 32 bytes of hex", ErrGPU, bound.Nonce)
	}
	verdict, err := p.relayGPU(ctx, payload, Nonce(nonce), p.now())
	if err != nil {
		return nil, err
	}
	return &verdict, nil
}

func evidenceBytes(data string) ([]byte, error) {
	u, err := dataurl.Parse(data)
	if err != nil || u.MediaType != "application/json" {
		return nil, errors.New("the session evidence is not a base64 application/json data URL")
	}
	raw, err := base64.StdEncoding.DecodeString(u.Base64)
	if err != nil {
		return nil, fmt.Errorf("the session evidence: %w", err)
	}
	return raw, nil
}

func phalaDirectPayload(data string) (string, error) {
	raw, err := evidenceBytes(data)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrGPU, err)
	}
	var evidence phalaDirectEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return "", fmt.Errorf("%w: the session evidence: %w", ErrGPU, err)
	}
	return evidence.NvidiaPayload, nil
}
