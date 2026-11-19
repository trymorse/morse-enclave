package frameconsent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"time"

	"morse/backend/internal/apierr"
)

const Version = "2026-11-18"

var Statement = []string{
	"I have the right to use this picture.",
	"Everyone shown in it is 18 or older.",
	"Everyone shown in it agreed that I may use their likeness this way, or the only person shown is me.",
	"I will not use it to make sexual content of a real person who has not agreed to it.",
	"Breaking these promises breaks the Terms and can close my account, and a person shown can report it to Morse.",
}

type Digest [sha256.Size]byte

func Of(data []byte) Digest { return sha256.Sum256(data) }

func (d Digest) String() string { return hex.EncodeToString(d[:]) }

func (d Digest) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

func (d *Digest) UnmarshalText(text []byte) error {
	parsed, err := Parse(string(text))
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

var errMalformed = errors.New("frameconsent: a digest is 64 lowercase hexadecimal characters")

func Parse(s string) (Digest, error) {
	var d Digest
	if len(s) != 2*len(d) {
		return Digest{}, errMalformed
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return Digest{}, errMalformed
		}
	}
	if _, err := hex.Decode(d[:], []byte(s)); err != nil {
		return Digest{}, errMalformed
	}
	return d, nil
}

type Record struct {
	Digest  Digest
	Version string
	At      time.Time
}

var ErrRequired = apierr.Invalid(http.StatusForbidden, "frame_consent_required",
	"This model makes a clip from an uploaded frame only once the account's owner has accepted the frame consent statement for that exact file. "+
		"Read it with GET /v1/account/frame-consents, accept it with POST /v1/account/frame-consents, then send the clip again.")

func Required(frame int) error {
	if frame == 0 {
		return ErrRequired.Naming("image")
	}
	return ErrRequired.Naming("last_image")
}

func Missing(frames, consented []Digest) (frame int, missing bool) {
	for i, d := range frames {
		if !slices.Contains(consented, d) {
			return i, true
		}
	}
	return 0, false
}
