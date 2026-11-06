package affinity

import (
	"encoding/hex"
	"fmt"
)

// Digest is SHA-256 over a request's conversation material, or none. The zero value is none and marshals as hex.
type Digest struct {
	sum [32]byte
	set bool
}

func DigestOfSum(sum [32]byte) Digest { return Digest{sum: sum, set: true} }

func (d Digest) IsZero() bool { return !d.set }

func (d Digest) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(d.sum[:])), nil }

// UnmarshalText takes exactly 64 hex characters. Anything else is a protocol error, never a zero digest.
func (d *Digest) UnmarshalText(text []byte) error {
	if len(text) != 2*len(d.sum) {
		return fmt.Errorf("an affinity digest is %d hex characters, not %d", 2*len(d.sum), len(text))
	}
	var sum [32]byte
	if _, err := hex.Decode(sum[:], text); err != nil {
		return fmt.Errorf("an affinity digest is hex: %w", err)
	}
	*d = Digest{sum: sum, set: true}
	return nil
}

func (Digest) String() string { return "affinity.Digest(redacted)" }

func (Digest) GoString() string { return "affinity.Digest(redacted)" }
