package rekorv2

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

const cosignatureAlg = 0x04

// Witness is one cosignature/v1 key that may count, and the operator that
// runs it.
type Witness struct {
	Name     string
	Operator string
	key      ed25519.PublicKey
	hash     [4]byte
}

// ParseWitness reads a published verifier key, "name+hash+base64(0x04 ||
// key)", and refuses another algorithm, ML-DSA among them, and a key hash
// that is not the key's.
func ParseWitness(vkey, operator string) (Witness, error) {
	name, rest, ok1 := strings.Cut(vkey, "+")
	hashHex, keyB64, ok2 := strings.Cut(rest, "+")
	if !ok1 || !ok2 || !validName(name) || operator == "" {
		return Witness{}, fmt.Errorf("rekorv2: %q is not a verifier key with an operator", vkey)
	}
	raw, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(raw) != 1+ed25519.PublicKeySize || raw[0] != cosignatureAlg {
		return Witness{}, fmt.Errorf("rekorv2: the key of %s is not a cosignature/v1 Ed25519 key", name)
	}
	w := Witness{Name: name, Operator: operator, key: ed25519.PublicKey(raw[1:])}
	w.hash = keyHash(name, cosignatureAlg, w.key)
	if hashHex != hex.EncodeToString(w.hash[:]) {
		return Witness{}, fmt.Errorf("rekorv2: the key hash of %s is not its key's", name)
	}
	return w, nil
}

func keyHash(name string, alg byte, key []byte) [4]byte {
	h := sha256.Sum256(append([]byte(name+"\n"+string([]byte{alg})), key...))
	return [4]byte(h[:4])
}

func (w Witness) verify(text []byte, sig []byte) (time.Time, bool) {
	if len(sig) != 8+ed25519.SignatureSize {
		return time.Time{}, false
	}
	seconds := binary.BigEndian.Uint64(sig[:8])
	msg := append([]byte("cosignature/v1\ntime "+strconv.FormatUint(seconds, 10)+"\n"), text...)
	if seconds > 1<<62 || !ed25519.Verify(w.key, msg, sig[8:]) {
		return time.Time{}, false
	}
	return time.Unix(int64(seconds), 0).UTC(), true
}

// WitnessPolicy is k and the witnesses whose cosignatures may count. Its
// zero value counts nothing and accepts no checkpoint.
type WitnessPolicy struct {
	k         int
	witnesses []Witness
}

// NewWitnessPolicy refuses k < 1, one name under two operators, a key
// listed twice, and a k above the number of operators, which no checkpoint
// could meet. One name may have several keys, as during a key rotation,
// and it still counts once.
func NewWitnessPolicy(k int, witnesses ...Witness) (WitnessPolicy, error) {
	if k < 1 {
		return WitnessPolicy{}, fmt.Errorf("rekorv2: k is %d", k)
	}
	operatorOf := map[string]string{}
	operators := map[string]bool{}
	for i, w := range witnesses {
		if w.key == nil {
			return WitnessPolicy{}, fmt.Errorf("rekorv2: witness %d was not made by ParseWitness", i)
		}
		if op, ok := operatorOf[w.Name]; ok && op != w.Operator {
			return WitnessPolicy{}, fmt.Errorf("rekorv2: %s is listed under %s and %s", w.Name, op, w.Operator)
		}
		if slices.ContainsFunc(witnesses[:i], func(v Witness) bool { return bytes.Equal(v.key, w.key) }) {
			return WitnessPolicy{}, fmt.Errorf("rekorv2: a key of %s is listed twice", w.Name)
		}
		operatorOf[w.Name] = w.Operator
		operators[w.Operator] = true
	}
	if k > len(operators) {
		return WitnessPolicy{}, fmt.Errorf("rekorv2: k is %d and only %d operators are listed", k, len(operators))
	}
	return WitnessPolicy{k: k, witnesses: slices.Clone(witnesses)}, nil
}

// K is the number of counted cosigners a checkpoint needs.
func (p WitnessPolicy) K() int { return p.k }

// Cosigner is one counted cosignature.
type Cosigner struct {
	Name     string
	Operator string
	// Time is the witness's signed time of cosigning.
	Time time.Time
}

func (p WitnessPolicy) count(text []byte, sigs []noteSig) []Cosigner {
	earliest := map[string]Cosigner{}
	for _, s := range sigs {
		for _, w := range p.witnesses {
			if w.Name != s.name || w.hash != s.hash {
				continue
			}
			t, ok := w.verify(text, s.sig)
			if !ok {
				continue
			}
			if c, seen := earliest[w.Operator]; !seen || t.Before(c.Time) {
				earliest[w.Operator] = Cosigner{Name: w.Name, Operator: w.Operator, Time: t}
			}
		}
	}
	counted := make([]Cosigner, 0, len(earliest))
	for _, c := range earliest {
		counted = append(counted, c)
	}
	slices.SortFunc(counted, func(a, b Cosigner) int {
		if c := a.Time.Compare(b.Time); c != 0 {
			return c
		}
		return strings.Compare(a.Operator, b.Operator)
	})
	return counted
}
