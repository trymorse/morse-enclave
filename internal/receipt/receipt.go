package receipt

import (
	"cmp"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"morse/backend/internal/aci"
	"morse/backend/internal/jcs"
)

const (
	eventRequest  = "request.received"
	eventResponse = "response.returned"
	eventUpstream = "upstream.verified"
)

type Upstream struct {
	Result    string
	Required  bool
	ModelID   string
	SessionID string
}

type Receipt struct {
	ID               string
	ChatID           string
	Model            string
	KeyID            string
	WorkloadID       string
	Digest           aci.Hash
	RequestReceived  aci.Hash
	ResponseReturned aci.Hash
	Upstream         Upstream
	signed           []byte
	signature        []byte
}

type event struct {
	Type string `json:"type"`
	// Phala's docs name the response hash wire_hash. Live receipts send body_hash (2026-09-29).
	BodyHash  string `json:"body_hash"`
	WireHash  string `json:"wire_hash"`
	Result    string `json:"result"`
	Required  bool   `json:"required"`
	ModelID   string `json:"model_id"`
	SessionID string `json:"session_id"`
}

var (
	ErrMissingEvent   = errors.New("receipt: event_log lacks request.received, response.returned, or upstream.verified")
	ErrDuplicateEvent = errors.New("receipt: event_log carries request.received, response.returned, or upstream.verified twice")
	ErrHashConflict   = errors.New("receipt: response.returned carries a body_hash and a wire_hash that differ")
)

func Parse(raw []byte) (Receipt, error) {
	var fields struct {
		ID     string `json:"receipt_id"`
		ChatID string `json:"chat_id"`
		Model  string `json:"model"`
		KeyID  string `json:"key_id"`
		// Absent from live reports and receipts (2026-09-29).
		WorkloadID string  `json:"workload_id"`
		Digest     string  `json:"workload_keyset_digest"`
		EventLog   []event `json:"event_log"`
		Signature  string  `json:"signature"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Receipt{}, err
	}
	r := Receipt{ID: fields.ID, ChatID: fields.ChatID, Model: fields.Model, KeyID: fields.KeyID, WorkloadID: fields.WorkloadID}
	var err error
	if r.signature, err = hex.DecodeString(fields.Signature); err != nil || len(r.signature) != ed25519.SignatureSize {
		return Receipt{}, fmt.Errorf("receipt: signature is not %d hex-encoded bytes", ed25519.SignatureSize)
	}
	if r.Digest, err = aci.ParseHash(fields.Digest); err != nil {
		return Receipt{}, err
	}
	events := map[string]event{}
	for _, e := range fields.EventLog {
		switch e.Type {
		case eventRequest, eventResponse, eventUpstream:
			if _, twice := events[e.Type]; twice {
				return Receipt{}, fmt.Errorf("%w: %s", ErrDuplicateEvent, e.Type)
			}
			events[e.Type] = e
		}
	}
	if len(events) != 3 {
		return Receipt{}, ErrMissingEvent
	}
	request, response, upstream := events[eventRequest], events[eventResponse], events[eventUpstream]
	if r.RequestReceived, err = aci.ParseHash(request.BodyHash); err != nil {
		return Receipt{}, err
	}
	if response.BodyHash != "" && response.WireHash != "" && response.BodyHash != response.WireHash {
		return Receipt{}, ErrHashConflict
	}
	if r.ResponseReturned, err = aci.ParseHash(cmp.Or(response.BodyHash, response.WireHash)); err != nil {
		return Receipt{}, err
	}
	r.Upstream = Upstream{Result: upstream.Result, Required: upstream.Required, ModelID: upstream.ModelID, SessionID: upstream.SessionID}
	decoded, err := jcs.Decode(raw)
	if err != nil {
		return Receipt{}, err
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return Receipt{}, errors.New("receipt: not a JSON object")
	}
	delete(object, "signature")
	if r.signed, err = jcs.Marshal(object); err != nil {
		return Receipt{}, err
	}
	return r, nil
}

type Exchange struct {
	Model        string
	RequestBody  []byte
	ResponseBody []byte
	ResponseID   string
}

var (
	ErrKeyUnknown         = errors.New("receipt: key_id is not in the attested keyset")
	ErrKeyAlgo            = errors.New("receipt: signing key algorithm is not ed25519")
	ErrSignature          = errors.New("receipt: signature does not verify under the attested key")
	ErrKeysetDigest       = errors.New("receipt: workload_keyset_digest differs from the attestation")
	ErrWorkloadID         = errors.New("receipt: workload_id differs from the attestation")
	ErrKeysetExpired      = errors.New("receipt: the attested keyset's not_after has passed")
	ErrChatID             = errors.New("receipt: chat_id is not the response id")
	ErrModel              = errors.New("receipt: model is not the model requested")
	ErrRequestHash        = errors.New("receipt: request.received.body_hash differs from the restored request")
	ErrResponseHash       = errors.New("receipt: response.returned.body_hash differs from the received bytes")
	ErrUpstreamUnverified = errors.New("receipt: upstream.verified is not verified and required")
)

func (r Receipt) Verify(ks aci.Keyset, x Exchange, now time.Time) error {
	if err := r.VerifyResponse(ks, Response{Model: x.Model, ID: x.ResponseID, Hash: aci.Sum(x.ResponseBody)}, now); err != nil {
		return err
	}
	switch {
	case aci.Sum(x.RequestBody) != r.RequestReceived:
		return ErrRequestHash
	case r.Upstream.Result != "verified" || !r.Upstream.Required:
		return ErrUpstreamUnverified
	}
	return nil
}

type Response struct {
	Model string
	ID    string
	Hash  aci.Hash
}

// VerifyResponse leaves request.received alone, since that hashes the plaintext request only the client can
// restore.
func (r Receipt) VerifyResponse(ks aci.Keyset, resp Response, now time.Time) error {
	var key *aci.Key
	for i := range ks.SigningKeys {
		if ks.SigningKeys[i].ID == r.KeyID {
			key = &ks.SigningKeys[i]
		}
	}
	switch {
	case key == nil:
		return ErrKeyUnknown
	// Phala's docs show secp256k1 ECDSA, but the live receipt key is Ed25519 (measured 2026-09-29).
	case key.Algo != aci.AlgoEd25519 || len(key.Public) != ed25519.PublicKeySize:
		return ErrKeyAlgo
	case !ed25519.Verify(ed25519.PublicKey(key.Public), r.signed, r.signature):
		return ErrSignature
	case r.Digest != ks.Digest:
		return ErrKeysetDigest
	case r.WorkloadID != ks.WorkloadID:
		return ErrWorkloadID
	case !now.Before(ks.NotAfter):
		return ErrKeysetExpired
	case r.ChatID != resp.ID:
		return ErrChatID
	case r.Model != resp.Model:
		return ErrModel
	case resp.Hash != r.ResponseReturned:
		return ErrResponseHash
	}
	return nil
}
