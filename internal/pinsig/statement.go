package pinsig

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"morse/backend/internal/jcs"
	"morse/backend/internal/strictjson"
)

const statementType = "morse-enclave-pins-v1"

// Statement is a signed pins statement: the images one environment admits,
// at one commit of the pins repository.
type Statement struct {
	Environment string
	Sequence    uint64
	PinsCommit  string
	Time        time.Time
	Images      []Image
}

type Image struct {
	PCRs    [3][48]byte
	Revoked bool
}

// encoding/json matches a struct field case-insensitively with Unicode
// folding, so decoding into a struct would let "\u017fequence" stand in for
// "sequence".
func exactFields(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	fields, err := strictjson.Object(bytes.NewReader(raw), keys...)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		v, ok := fields[k]
		if !ok {
			return nil, fmt.Errorf("no %s", k)
		}
		if string(v) == "null" {
			return nil, fmt.Errorf("%s is null", k)
		}
	}
	return fields, nil
}

// ParseStatement decodes the JCS bytes of a statement. It refuses bytes that
// are not canonical, a key set other than the statement's own, a null, another
// type, an empty image list, and an image whose PCRs are all zero, which is
// what a debug-mode enclave measures.
func ParseStatement(raw []byte) (Statement, error) {
	canonical, err := jcs.Canonicalize(raw)
	if err != nil {
		return Statement{}, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	if !bytes.Equal(canonical, raw) {
		return Statement{}, fmt.Errorf("%w: not JCS canonical bytes", ErrStatement)
	}
	fields, err := exactFields(raw, "environment", "images", "pins_commit", "sequence", "time", "type")
	if err != nil {
		return Statement{}, fmt.Errorf("%w: %v", ErrStatement, err)
	}
	var (
		typ, at string
		st      Statement
		images  []json.RawMessage
	)
	for key, into := range map[string]any{
		"type": &typ, "environment": &st.Environment, "sequence": &st.Sequence,
		"pins_commit": &st.PinsCommit, "time": &at, "images": &images,
	} {
		if err := json.Unmarshal(fields[key], into); err != nil {
			return Statement{}, fmt.Errorf("%w: %s: %v", ErrStatement, key, err)
		}
	}
	if typ != statementType {
		return Statement{}, fmt.Errorf("%w: type %q is not %s", ErrStatement, typ, statementType)
	}
	if st.Environment == "" {
		return Statement{}, fmt.Errorf("%w: no environment", ErrStatement)
	}
	if _, err := hex.DecodeString(st.PinsCommit); err != nil || len(st.PinsCommit) != 40 {
		return Statement{}, fmt.Errorf("%w: pins_commit is not 40 hex digits", ErrStatement)
	}
	if st.Time, err = time.Parse(time.RFC3339, at); err != nil {
		return Statement{}, fmt.Errorf("%w: time: %v", ErrStatement, err)
	}
	if len(images) == 0 {
		return Statement{}, fmt.Errorf("%w: no images", ErrStatement)
	}
	for _, raw := range images {
		img, err := exactFields(raw, "pcr0", "pcr1", "pcr2", "revoked")
		if err != nil {
			return Statement{}, fmt.Errorf("%w: image: %v", ErrStatement, err)
		}
		var image Image
		for i, key := range []string{"pcr0", "pcr1", "pcr2"} {
			var h string
			if err := json.Unmarshal(img[key], &h); err != nil {
				return Statement{}, fmt.Errorf("%w: %s: %v", ErrStatement, key, err)
			}
			pcr, err := hex.DecodeString(h)
			if err != nil || len(pcr) != 48 {
				return Statement{}, fmt.Errorf("%w: %s is not 96 hex digits", ErrStatement, key)
			}
			image.PCRs[i] = [48]byte(pcr)
		}
		if image.PCRs == [3][48]byte{} {
			return Statement{}, fmt.Errorf("%w: an image's PCRs are all zero", ErrStatement)
		}
		if err := json.Unmarshal(img["revoked"], &image.Revoked); err != nil {
			return Statement{}, fmt.Errorf("%w: revoked: %v", ErrStatement, err)
		}
		st.Images = append(st.Images, image)
	}
	return st, nil
}

// Admit is the policy a verified statement must pass before its images are
// trusted: it is for env, its sequence is at or above the floor the key has
// travelled with, and Rekor logged it at or before now and no more than
// maxAge before. now must come from a source the host cannot move, such as
// the timestamp of a fresh NSM attestation document: a host clock set back
// would admit a statement Rekor logged years ago.
func Admit(st Statement, env string, floor uint64, integrated, now time.Time, maxAge time.Duration) error {
	switch {
	case now.IsZero():
		return fmt.Errorf("%w: no trusted time", ErrAdmit)
	case st.Environment != env:
		return fmt.Errorf("%w: statement is for %s, not %s", ErrAdmit, st.Environment, env)
	case st.Sequence < floor:
		return fmt.Errorf("%w: sequence %d is below the floor %d", ErrAdmit, st.Sequence, floor)
	case integrated.After(now):
		return fmt.Errorf("%w: logged at %s, after now %s", ErrAdmit, integrated.Format(time.RFC3339), now.Format(time.RFC3339))
	case now.Sub(integrated) > maxAge:
		return fmt.Errorf("%w: logged %s ago, more than %s", ErrAdmit, now.Sub(integrated), maxAge)
	}
	return nil
}

// Lists reports whether the statement admits an image with these PCRs: it
// lists them, and no entry that lists them is revoked.
func (s Statement) Lists(pcrs [3][48]byte) bool {
	listed := false
	for _, img := range s.Images {
		if img.PCRs != pcrs {
			continue
		}
		if img.Revoked {
			return false
		}
		listed = true
	}
	return listed
}
