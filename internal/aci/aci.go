package aci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"morse/backend/internal/jcs"
)

const (
	hashPrefix  = "sha256:"
	AlgoEd25519 = "ed25519"
)

type Hash [sha256.Size]byte

func Sum(b []byte) Hash { return sha256.Sum256(b) }

func ParseHash(s string) (Hash, error) {
	var h Hash
	digest, ok := strings.CutPrefix(s, hashPrefix)
	if !ok || !decodeFixed(h[:], digest) {
		return Hash{}, fmt.Errorf("aci: hash %q is not %s<64 hex>", s, hashPrefix)
	}
	return h, nil
}

func decodeFixed(dst []byte, s string) bool {
	if len(s) != hex.EncodedLen(len(dst)) {
		return false
	}
	_, err := hex.Decode(dst, []byte(s))
	return err == nil
}

func (h Hash) String() string { return hashPrefix + hex.EncodeToString(h[:]) }

type Key struct {
	ID     string
	Algo   string
	Public []byte
}

type SPKI [sha256.Size]byte

func (s SPKI) String() string { return hex.EncodeToString(s[:]) }

type TLSKey struct {
	Domain string
	SPKI   SPKI
}

type Keyset struct {
	WorkloadID  string
	Digest      Hash
	NotAfter    time.Time
	SigningKeys []Key
	E2EEKeys    []Key
	TLSKeys     []TLSKey
}

var (
	ErrReportDigest = errors.New("aci: workload_keyset_digest is not the digest of the report's workload_keyset")
	ErrNoNotAfter   = errors.New("aci: workload_keyset has no not_after, so it never verifies")
)

type wireKey struct {
	ID     string `json:"key_id"`
	Algo   string `json:"algo"`
	Public string `json:"public_key"`
}

type wireTLSKey struct {
	Domain string `json:"domain"`
	SPKI   string `json:"spki_sha256"`
}

func (ks Keyset) E2EEKey(algo string) (Key, bool) {
	for _, k := range ks.E2EEKeys {
		if k.Algo == algo {
			return k, true
		}
	}
	return Key{}, false
}

func ParseKeyset(report []byte) (Keyset, error) {
	var top struct {
		WorkloadID  string `json:"workload_id"`
		Digest      string `json:"workload_keyset_digest"`
		Attestation struct {
			WorkloadKeyset json.RawMessage `json:"workload_keyset"`
		} `json:"attestation"`
	}
	if err := json.Unmarshal(report, &top); err != nil {
		return Keyset{}, err
	}
	if top.Digest == "" || top.Attestation.WorkloadKeyset == nil {
		return Keyset{}, errors.New("aci: report lacks workload_keyset_digest or attestation.workload_keyset")
	}
	canonical, err := jcs.Canonicalize(top.Attestation.WorkloadKeyset)
	if err != nil {
		return Keyset{}, err
	}
	digest, err := ParseHash(top.Digest)
	if err != nil || Sum(canonical) != digest {
		return Keyset{}, ErrReportDigest
	}
	var keyset struct {
		NotAfter    int64        `json:"not_after"`
		SigningKeys []wireKey    `json:"receipt_signing_keys"`
		E2EEKeys    []wireKey    `json:"e2ee_public_keys"`
		TLSKeys     []wireTLSKey `json:"tls_public_keys"`
	}
	if err := json.Unmarshal(top.Attestation.WorkloadKeyset, &keyset); err != nil {
		return Keyset{}, err
	}
	if keyset.NotAfter == 0 {
		return Keyset{}, ErrNoNotAfter
	}
	ks := Keyset{WorkloadID: top.WorkloadID, Digest: digest, NotAfter: time.Unix(keyset.NotAfter, 0).UTC()}
	if ks.SigningKeys, err = decodeKeys("signing", keyset.SigningKeys); err != nil {
		return Keyset{}, err
	}
	if ks.E2EEKeys, err = decodeKeys("e2ee", keyset.E2EEKeys); err != nil {
		return Keyset{}, err
	}
	if ks.TLSKeys, err = decodeTLSKeys(keyset.TLSKeys); err != nil {
		return Keyset{}, err
	}
	return ks, nil
}

func decodeTLSKeys(wire []wireTLSKey) ([]TLSKey, error) {
	var keys []TLSKey
	for _, k := range wire {
		key := TLSKey{Domain: k.Domain}
		if !decodeFixed(key.SPKI[:], k.SPKI) {
			return nil, fmt.Errorf("aci: tls key for %q: spki_sha256 %q is not %d hex bytes", k.Domain, k.SPKI, len(key.SPKI))
		}
		if key.Domain == "" {
			return nil, errors.New("aci: tls key has no domain")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func decodeKeys(role string, wire []wireKey) ([]Key, error) {
	var keys []Key
	for _, k := range wire {
		public, err := hex.DecodeString(strings.TrimPrefix(k.Public, "0x"))
		if err != nil {
			return nil, fmt.Errorf("aci: %s key %s: %w", role, k.ID, err)
		}
		keys = append(keys, Key{ID: k.ID, Algo: k.Algo, Public: public})
	}
	return keys, nil
}
