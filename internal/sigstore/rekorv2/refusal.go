// Package rekorv2 verifies one Rekor v2 entry offline: the shard rules,
// the RFC 9162 inclusion proof, the checkpoint's signed note, the
// cosignature/v1 witness count, and the strict hashedrekord v0.0.2 body. It
// also rebuilds an entry's inclusion proof from a shard's tiles, for the
// host, through a fetch function the host supplies.
package rekorv2

// Reason is why Verify refused an entry. Each value is the reason that
// PUT /door/record answers, so the door writes it with no mapping.
type Reason string

const (
	NotV2           Reason = "not_v2"
	UnknownLog      Reason = "unknown_log"
	LogNotValidNow  Reason = "log_not_valid_now"
	Inclusion       Reason = "inclusion"
	BadCheckpoint   Reason = "checkpoint"
	LogSignature    Reason = "log_signature"
	TooFewWitnesses Reason = "witnesses"
	NotThisRecord   Reason = "not_this_record"
)

// Refusal is the only error that Verify and VerifyCheckpoint return.
type Refusal struct {
	Reason Reason
	Detail string
}

func (r *Refusal) Error() string { return "rekorv2: " + string(r.Reason) + ": " + r.Detail }

func refuse(reason Reason, detail string) *Refusal { return &Refusal{Reason: reason, Detail: detail} }
