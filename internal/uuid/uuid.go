package uuid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

const textLen = 36

var dashes = [...]int{8, 13, 18, 23}

func New() [16]byte {
	var b [16]byte
	rand.Read(b[:])
	return versioned(b, 4)
}

func NewV7(now time.Time) [16]byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(now.UnixMilli())<<16)
	rand.Read(b[6:])
	return versioned(b, 7)
}

// Derived is the one id a step that follows parent under name has, so a retry finds it without a second random id.
func Derived(parent [16]byte, name string) [16]byte {
	sum := sha256.Sum256(append(parent[:], name...))
	return versioned([16]byte(sum[:16]), 8)
}

// IsRandom reports a version 4 UUID, one New mints. A Derived id is version 8, so a key a client sends that
// IsRandom never collides with the id of a step derived from another key.
func IsRandom(id [16]byte) bool { return id[6]>>4 == 4 && id[8]>>6 == 2 }

func versioned(b [16]byte, version byte) [16]byte {
	b[6] = b[6]&0x0f | version<<4
	b[8] = b[8]&0x3f | 0x80
	return b
}

func Format(id [16]byte) string {
	h := hex.EncodeToString(id[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func Parse(s string) ([16]byte, bool) {
	var id [16]byte
	if len(s) != textLen {
		return id, false
	}
	for _, i := range dashes {
		if s[i] != '-' {
			return id, false
		}
	}
	digits := s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	_, err := hex.Decode(id[:], []byte(digits))
	return id, err == nil
}
