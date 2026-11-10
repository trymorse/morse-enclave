package pinsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"morse/backend/internal/sigstore/rekorv2"
)

//go:embed sigstore_trusted_root.json
var publicGood []byte

// PublicGood parses the Sigstore public-good trusted root this package embeds.
func PublicGood() (TrustRoot, error) { return ParseTrustRoot(publicGood) }

// TrustRoot is the subset of a Sigstore trusted_root.json the verifier
// needs: Fulcio CA chains with their validity windows, Rekor v1 ECDSA P-256
// log keys by log id for VerifyDSSE, and the Rekor v2 Ed25519 shards for
// Verify and VerifyVendor.
type TrustRoot struct {
	authorities []authority
	logs        map[[32]byte]logKey
	shards      rekorv2.Shards
}

type authority struct {
	chain  []*x509.Certificate // intermediates first, the root last
	window window
}

type logKey struct {
	key    *ecdsa.PublicKey
	window window
}

type tlogJSON struct {
	HashAlgorithm string `json:"hashAlgorithm"`
	PublicKey     struct {
		RawBytes   []byte     `json:"rawBytes"`
		KeyDetails string     `json:"keyDetails"`
		ValidFor   windowJSON `json:"validFor"`
	} `json:"publicKey"`
	LogID struct {
		KeyID []byte `json:"keyId"`
	} `json:"logId"`
}

type trustRootJSON struct {
	Logs        []tlogJSON `json:"tlogs"`
	Authorities []struct {
		CertChain struct {
			Certificates []struct {
				RawBytes []byte `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"certChain"`
		ValidFor windowJSON `json:"validFor"`
	} `json:"certificateAuthorities"`
}

type windowJSON struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func (w windowJSON) window() window { return window{start: w.Start, end: w.End} }

func ParseTrustRoot(trustedRootJSON []byte) (TrustRoot, error) {
	var raw trustRootJSON
	if err := json.Unmarshal(trustedRootJSON, &raw); err != nil {
		return TrustRoot{}, fmt.Errorf("%w: %v", ErrTrustRoot, err)
	}
	root := TrustRoot{logs: map[[32]byte]logKey{}}
	for _, l := range raw.Logs {
		if l.HashAlgorithm != "SHA2_256" || l.PublicKey.KeyDetails != "PKIX_ECDSA_P256_SHA_256" {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(l.PublicKey.RawBytes)
		if err != nil {
			return TrustRoot{}, fmt.Errorf("%w: log key: %v", ErrTrustRoot, err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.Curve != elliptic.P256() {
			return TrustRoot{}, fmt.Errorf("%w: a log key named PKIX_ECDSA_P256_SHA_256 is not a P-256 key", ErrTrustRoot)
		}
		id := sha256.Sum256(l.PublicKey.RawBytes)
		if len(l.LogID.KeyID) != 32 || [32]byte(l.LogID.KeyID) != id {
			return TrustRoot{}, fmt.Errorf("%w: a log id is not the SHA-256 of its key", ErrTrustRoot)
		}
		if l.PublicKey.ValidFor.Start.IsZero() {
			return TrustRoot{}, fmt.Errorf("%w: a log key has no validity start", ErrTrustRoot)
		}
		root.logs[id] = logKey{key: ec, window: l.PublicKey.ValidFor.window()}
	}
	for _, a := range raw.Authorities {
		var chain []*x509.Certificate
		for _, c := range a.CertChain.Certificates {
			cert, err := x509.ParseCertificate(c.RawBytes)
			if err != nil {
				return TrustRoot{}, fmt.Errorf("%w: CA certificate: %v", ErrTrustRoot, err)
			}
			chain = append(chain, cert)
		}
		if len(chain) == 0 || a.ValidFor.Start.IsZero() {
			return TrustRoot{}, fmt.Errorf("%w: a certificate authority has no chain or no validity start", ErrTrustRoot)
		}
		root.authorities = append(root.authorities, authority{chain: chain, window: a.ValidFor.window()})
	}
	if len(root.logs) == 0 || len(root.authorities) == 0 {
		return TrustRoot{}, fmt.Errorf("%w: no Rekor v1 log key or no certificate authority", ErrTrustRoot)
	}
	// A root with no Ed25519 log leaves the shards empty, so every Rekor v2
	// entry fails as an unknown log. One that lists a shard must be readable.
	if slices.ContainsFunc(raw.Logs, func(l tlogJSON) bool { return l.PublicKey.KeyDetails == "PKIX_ED25519" }) {
		shards, err := rekorv2.ParseEmbeddedShards(trustedRootJSON)
		if err != nil {
			return TrustRoot{}, fmt.Errorf("%w: %v", ErrTrustRoot, err)
		}
		root.shards = shards
	}
	return root, nil
}
