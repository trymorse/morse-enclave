package attestation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"morse/backend/internal/aci"
	"morse/backend/internal/jcs"
	"morse/backend/internal/nras"
)

const nearSigningAlgo = "ed25519"

var (
	ErrNearReport         = errors.New("attestation: the NEAR report is not a gateway attestation with model attestations")
	ErrNearSigningKey     = errors.New("attestation: the NEAR signing key is not the 32-byte ed25519 key its signing_address names")
	ErrNearTLS            = errors.New("attestation: tls_cert_fingerprint is not a 32-byte SPKI digest")
	ErrNearModel          = errors.New("attestation: the model attestation is not for the route's upstream model")
	ErrNearComposeManager = errors.New("attestation: compose_manager_attestation is not the model TD's quote over its action log")
)

type nearReport struct {
	Gateway nearAttestation        `json:"gateway_attestation"`
	Models  []nearModelAttestation `json:"model_attestations"`
}

type nearAttestation struct {
	SigningAddress string          `json:"signing_address"`
	SigningAlgo    string          `json:"signing_algo"`
	Quote          string          `json:"intel_quote"`
	EventLog       json.RawMessage `json:"event_log"`
	Info           nearInfo        `json:"info"`
	TLSFingerprint string          `json:"tls_cert_fingerprint"`
}

type nearInfo struct {
	TCBInfo  json.RawMessage `json:"tcb_info"`
	VMConfig json.RawMessage `json:"vm_config"`
}

type nearModelAttestation struct {
	nearAttestation
	Model            string          `json:"model_name"`
	SigningPublicKey string          `json:"signing_public_key"`
	NvidiaPayload    string          `json:"nvidia_payload"`
	ComposeManager   json.RawMessage `json:"compose_manager_attestation"`
}

type nearComposeManager struct {
	Actions     json.RawMessage `json:"actions"`
	ActionsHash string          `json:"actions_hash"`
	Quote       string          `json:"quote"`
}

type NearGateway struct {
	Workload
	TLS aci.SPKI
}

type NearComposeManager struct {
	ActionsHash string
	ActionCount int
}

type NearModel struct {
	Workload
	Model          string
	GPUs           []string
	ComposeManager NearComposeManager
	Gateway        NearGateway
	Endpoint       Endpoint[aci.SPKI]
}

func (m NearModel) Facts() []any {
	return []any{"endpoint", m.Endpoint.ID, "instance_id", m.InstanceID, "not_after", m.Endpoint.NotAfter.UTC().Format(time.RFC3339), "model", m.Model, "compose_hash", m.ComposeHash, "tcb_status", string(m.TCB.Status), "tcb_advisories", m.TCB.Advisories, "gateway_instance_id", m.Gateway.InstanceID, "gateway_compose_hash", m.Gateway.ComposeHash, "gateway_tcb_status", string(m.Gateway.TCB.Status), "compose_manager_actions_hash", m.ComposeManager.ActionsHash, "compose_manager_action_count", m.ComposeManager.ActionCount}
}

type NearReport struct {
	Gateway NearGateway
	Models  []NearModel
	Refused []Refusal
}

// VerifyNear judges one NEAR report for the route's upstream model. The gateway TD fails the whole
// report; each model attestation is judged on its own and refused into Refused.
func (p Policy) VerifyNear(ctx context.Context, raw []byte, nonce Nonce, model string) (NearReport, error) {
	var r nearReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return NearReport{}, fmt.Errorf("%w: %w", ErrNearReport, err)
	}
	if len(r.Models) == 0 {
		return NearReport{}, fmt.Errorf("%w: no model_attestations", ErrNearReport)
	}
	now := p.now()
	address, err := nearKey(r.Gateway.SigningAlgo, r.Gateway.SigningAddress)
	if err != nil {
		return NearReport{}, err
	}
	gateway, err := p.verifyNearTD(ctx, r.Gateway, address, nonce, now)
	if err != nil {
		return NearReport{}, err
	}
	report := NearReport{Gateway: gateway}
	for _, m := range r.Models {
		verified, err := p.verifyNearModel(ctx, m, gateway, nonce, model, now)
		if err != nil {
			report.Refused = append(report.Refused, Refusal{EndpointID: strings.ToLower(m.SigningPublicKey), Err: err})
			continue
		}
		report.Models = append(report.Models, verified)
	}
	return report, nil
}

func (p Policy) verifyNearModel(ctx context.Context, m nearModelAttestation, gateway NearGateway, nonce Nonce, model string, now time.Time) (NearModel, error) {
	key, err := nearKey(m.SigningAlgo, m.SigningPublicKey)
	if err != nil {
		return NearModel{}, err
	}
	if address, err := hex.DecodeString(m.SigningAddress); err != nil || !bytes.Equal(address, key) {
		return NearModel{}, fmt.Errorf("%w: signing_address %q, signing_public_key %q", ErrNearSigningKey, m.SigningAddress, m.SigningPublicKey)
	}
	if m.Model != model {
		return NearModel{}, fmt.Errorf("%w: model_name %q, route %q", ErrNearModel, m.Model, model)
	}
	td, err := p.verifyNearTD(ctx, m.nearAttestation, key, nonce, now)
	if err != nil {
		return NearModel{}, err
	}
	verdict, err := p.verifyBoundGPU(ctx, m.NvidiaPayload, nonce, now)
	if err != nil {
		return NearModel{}, err
	}
	gpus, err := gpuModels(verdict)
	if err != nil {
		return NearModel{}, err
	}
	composeManager, err := p.verifyNearComposeManager(ctx, m.ComposeManager, td.Workload, nonce, now)
	if err != nil {
		return NearModel{}, err
	}
	return NearModel{
		Workload:       td.Workload,
		Model:          m.Model,
		GPUs:           gpus,
		ComposeManager: composeManager,
		Gateway:        gateway,
		Endpoint:       Endpoint[aci.SPKI]{ID: hex.EncodeToString(key), NotAfter: verdict.Expires, Keys: []aci.SPKI{gateway.TLS}},
	}, nil
}

func nearKey(algo, keyHex string) ([]byte, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil || algo != nearSigningAlgo || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: signing_algo %q, key %q", ErrNearSigningKey, algo, keyHex)
	}
	return key, nil
}

func nearReportData(digest [sha256.Size]byte, nonce Nonce) [quoteReportDataLen]byte {
	var want [quoteReportDataLen]byte
	copy(want[:sha256.Size], digest[:])
	copy(want[sha256.Size:], nonce[:])
	return want
}

func (p Policy) verifyNearTD(ctx context.Context, a nearAttestation, key []byte, nonce Nonce, now time.Time) (NearGateway, error) {
	fingerprint, err := hex.DecodeString(a.TLSFingerprint)
	if err != nil || len(fingerprint) != sha256.Size {
		return NearGateway{}, fmt.Errorf("%w: %q", ErrNearTLS, a.TLSFingerprint)
	}
	var tcb struct {
		AppCompose string `json:"app_compose"`
	}
	if err := json.Unmarshal(unquoted(a.Info.TCBInfo), &tcb); err != nil || tcb.AppCompose == "" {
		return NearGateway{}, fmt.Errorf("%w: info.tcb_info carries no app_compose", ErrNearReport)
	}
	w, err := p.measure(ctx, dstackEvidence{Quote: a.Quote, EventLog: a.EventLog, AppCompose: tcb.AppCompose, VMConfig: a.Info.VMConfig}, nearReportData(sha256.Sum256(slices.Concat(key, fingerprint)), nonce), now, reportTCBStatus)
	if err != nil {
		return NearGateway{}, err
	}
	return NearGateway{Workload: w, TLS: aci.SPKI(fingerprint)}, nil
}

func (p Policy) verifyBoundGPU(ctx context.Context, payload string, nonce Nonce, now time.Time) (nras.Verdict, error) {
	var bound struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(payload), &bound); err != nil {
		return nras.Verdict{}, fmt.Errorf("%w: nvidia_payload: %w", ErrGPU, err)
	}
	if got, err := hex.DecodeString(bound.Nonce); err != nil || !bytes.Equal(got, nonce[:]) {
		return nras.Verdict{}, fmt.Errorf("%w: nvidia_payload is bound to nonce %q, not %s", ErrGPU, bound.Nonce, nonce)
	}
	return p.verifyGPU(ctx, []byte(payload), nonce, now)
}

func (p Policy) verifyNearComposeManager(ctx context.Context, raw json.RawMessage, td Workload, nonce Nonce, now time.Time) (NearComposeManager, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return NearComposeManager{}, nil
	}
	var cm nearComposeManager
	if err := json.Unmarshal(unquoted(raw), &cm); err != nil {
		return NearComposeManager{}, fmt.Errorf("%w: %w", ErrNearComposeManager, err)
	}
	var actions []json.RawMessage
	if err := json.Unmarshal(cm.Actions, &actions); err != nil {
		return NearComposeManager{}, fmt.Errorf("%w: actions: %w", ErrNearComposeManager, err)
	}
	canonical, err := jcs.Canonicalize(cm.Actions)
	if err != nil {
		return NearComposeManager{}, fmt.Errorf("%w: %w", ErrNearComposeManager, err)
	}
	actionsHash := sha256.Sum256(canonical)
	if cm.ActionsHash != hex.EncodeToString(actionsHash[:]) {
		return NearComposeManager{}, fmt.Errorf("%w: actions_hash %s, sha256 of the canonical actions %x", ErrNearComposeManager, cm.ActionsHash, actionsHash)
	}
	quote, err := hex.DecodeString(cm.Quote)
	if err != nil {
		return NearComposeManager{}, fmt.Errorf("%w: quote is not hex: %w", ErrQuote, err)
	}
	body, _, err := p.quoteBoundTo(ctx, quote, nearReportData(actionsHash, nonce), now, reportTCBStatus)
	if err != nil {
		return NearComposeManager{}, err
	}
	if m := measured(body); m.Boot != td.Boot || m.RTMR3 != td.RTMR3 {
		return NearComposeManager{}, fmt.Errorf("%w: its registers are not the model TD's", ErrNearComposeManager)
	}
	return NearComposeManager{ActionsHash: cm.ActionsHash, ActionCount: len(actions)}, nil
}

// GPUVerdict is NRAS's signed reply for one GPU payload, with the certificate chain of each key
// that signed it, so a client can verify the tokens offline.
type GPUVerdict struct {
	Response json.RawMessage     `json:"response"`
	X5C      map[string][]string `json:"x5c"`
	Expires  time.Time           `json:"-"`
}

const maxGPURelays = 8

var relayNRASCalls = make(chan struct{}, maxGPURelays)

// NearGPUVerdicts relays NRAS's tokens so a browser can check them itself. It verifies nothing
// else in the report, which the gate already judged under its own nonce.
func (p Policy) NearGPUVerdicts(ctx context.Context, raw []byte, nonce Nonce) (map[string]GPUVerdict, []Refusal) {
	verdicts := map[string]GPUVerdict{}
	var r nearReport
	if err := json.Unmarshal(raw, &r); err != nil {
		return verdicts, []Refusal{{Err: fmt.Errorf("%w: %w", ErrNearReport, err)}}
	}
	now := p.now()
	var refused []Refusal
	for _, m := range r.Models {
		key, verdict, err := p.nearGPUVerdict(ctx, m, nonce, now)
		if err != nil {
			refused = append(refused, Refusal{EndpointID: strings.ToLower(m.SigningPublicKey), Err: err})
			continue
		}
		verdicts[key] = verdict
	}
	return verdicts, refused
}

func (p Policy) nearGPUVerdict(ctx context.Context, m nearModelAttestation, nonce Nonce, now time.Time) (string, GPUVerdict, error) {
	key, err := nearKey(m.SigningAlgo, m.SigningPublicKey)
	if err != nil {
		return "", GPUVerdict{}, err
	}
	verdict, err := p.relayGPU(ctx, m.NvidiaPayload, nonce, now)
	return hex.EncodeToString(key), verdict, err
}

// relayGPU asks NRAS about a payload bound to nonce, in one of the maxGPURelays calls every relay shares.
func (p Policy) relayGPU(ctx context.Context, payload string, nonce Nonce, now time.Time) (GPUVerdict, error) {
	select {
	case relayNRASCalls <- struct{}{}:
		defer func() { <-relayNRASCalls }()
	case <-ctx.Done():
		return GPUVerdict{}, Outage{Err: fmt.Errorf("%w: waiting for one of %d NRAS calls: %w", ErrGPUService, maxGPURelays, ctx.Err())}
	}
	verdict, err := p.verifyBoundGPU(ctx, payload, nonce, now)
	if err != nil {
		return GPUVerdict{}, err
	}
	return GPUVerdict{Response: verdict.Response, X5C: verdict.X5C, Expires: verdict.Expires}, nil
}
