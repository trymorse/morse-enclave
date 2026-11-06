// Package affinity names a conversation so both relays place it on the same host. The worker derives an unkeyed
// Digest from the plaintext opening it already reads; the relay keys that under PROXY_AFFINITY_KEY with the
// credential, model, and tier into a Conversation, and every draw reads the Conversation and nothing else.
package affinity

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/bits"

	"morse/backend/internal/catalog"
)

// Key is the relay secret. The zero Key is unset.
type Key struct{ secret []byte }

const minKeyBytes = 32

// ParseKey reads the secret as the operator set it. "" is the zero Key.
func ParseKey(raw string) (Key, error) {
	if raw == "" {
		return Key{}, nil
	}
	if len(raw) < minKeyBytes {
		return Key{}, errors.New("an affinity key needs at least 32 bytes, such as the output of openssl rand -hex 32")
	}
	return Key{secret: []byte(raw)}, nil
}

func (k Key) Set() bool { return len(k.secret) > 0 }

func (Key) String() string { return "affinity.Key(redacted)" }

func (Key) GoString() string { return "affinity.Key(redacted)" }

// Owner is the credential half of a Scope: a key's or a guest's credential digest, or an account id for a login or a
// guest with an account.
type Owner struct {
	kind byte
	id   []byte
}

func CredentialOwner(digest [32]byte) Owner { return Owner{kind: 1, id: digest[:]} }

func AccountOwner(id [16]byte) Owner { return Owner{kind: 2, id: id[:]} }

type Scope struct {
	Owner Owner
	Model catalog.ModelID
	Tier  catalog.Tier
}

// Conversation is HMAC-SHA256(key, scope, digest).
type Conversation [32]byte

const messageVersion = "morse/affinity/v1\x00"

func (k Key) Conversation(s Scope, d Digest) Conversation {
	mac := hmac.New(sha256.New, k.secret)
	mac.Write([]byte(messageVersion))
	mac.Write([]byte{s.Owner.kind})
	mac.Write(s.Owner.id)
	mac.Write(binary.BigEndian.AppendUint16(nil, uint16(len(s.Model))))
	mac.Write([]byte(s.Model))
	mac.Write([]byte{byte(s.Tier)})
	if d.IsZero() {
		mac.Write([]byte{0})
	} else {
		mac.Write([]byte{1})
		mac.Write(d.sum[:])
	}
	var c Conversation
	mac.Sum(c[:0])
	return c
}

// Ramped reads bytes 0..8 of c as a fraction and is true when it falls under share. It is monotone in share:
// WholeShare is always true; 0 is never.
func (c Conversation) Ramped(share Share) bool { return under(c[0:8], share) }

// Spread reads bytes 8..16, a slice Ramped never reads.
func (c Conversation) Spread(share Share) bool { return under(c[8:16], share) }

// Canary reads bytes 16..24, a slice neither Ramped nor Spread reads.
func (c Conversation) Canary(share Share) bool { return under(c[16:24], share) }

func under(slice []byte, share Share) bool {
	return basisPointsOf(binary.BigEndian.Uint64(slice)) < uint64(share)
}

// basisPointsOf scales u from 0..2^64 to 0..WholeShare.
func basisPointsOf(u uint64) uint64 {
	hi, _ := bits.Mul64(u, uint64(WholeShare))
	return hi
}

// Rendezvous picks the endpoint with the highest SHA-256(c, id), compared as big-endian bytes. Identical scores keep
// the first. No ids gives "".
func (c Conversation) Rendezvous(ids []catalog.EndpointID) catalog.EndpointID {
	var winner catalog.EndpointID
	var best []byte
	for _, id := range ids {
		score := sha256.Sum256(append(c[:], id...))
		if best == nil || bytes.Compare(score[:], best) > 0 {
			winner, best = id, score[:]
		}
	}
	return winner
}

// Short is bytes 24..32 of c in hex, for logs. No draw reads that slice, so the log names the conversation without
// giving away where it was placed.
func (c Conversation) Short() string { return hex.EncodeToString(c[24:32]) }

func (Conversation) String() string { return "affinity.Conversation(redacted)" }

func (Conversation) GoString() string { return "affinity.Conversation(redacted)" }
