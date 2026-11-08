package pinsig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"morse/backend/internal/jcs"
)

const vendorStatementType = "morse-vendor-pins-v1"

// VendorFiles are the pins repository files a vendor statement digests, by their path there. A statement
// lists exactly these, as morse-core's VENDOR_FILES does.
var VendorFiles = [...]string{
	"v4/phala_pins.json",
	"v4/near_pins.json",
	"v4/tinfoil_pins.json",
	"v4/phala_model_pins.json",
}

// VendorStatement is a signed vendor pins statement: the sha256 of the JCS bytes of each vendor pins file,
// at one commit of the pins repository.
type VendorStatement struct {
	Sequence   uint64
	PinsCommit string
	Time       time.Time
	digests    map[string][sha256.Size]byte
}

// ParseVendorStatement decodes the JCS bytes of a vendor statement. It refuses bytes that are not canonical,
// a key set other than the statement's own, a null, another type, and a files object whose keys are not
// exactly VendorFiles with a lowercase hex sha256 each.
func ParseVendorStatement(raw []byte) (VendorStatement, error) {
	fields, err := canonicalFields(raw, "files", "pins_commit", "sequence", "time", "type")
	if err != nil {
		return VendorStatement{}, err
	}
	var (
		typ, at string
		st      VendorStatement
		files   json.RawMessage
	)
	for key, into := range map[string]any{"type": &typ, "sequence": &st.Sequence, "pins_commit": &st.PinsCommit, "time": &at, "files": &files} {
		if err := json.Unmarshal(fields[key], into); err != nil {
			return VendorStatement{}, fmt.Errorf("%w: %s: %v", ErrStatement, key, err)
		}
	}
	if typ != vendorStatementType {
		return VendorStatement{}, fmt.Errorf("%w: type %q is not %s", ErrStatement, typ, vendorStatementType)
	}
	if err := checkHeader(st.PinsCommit, at, &st.Time); err != nil {
		return VendorStatement{}, err
	}
	listed, err := exactFields(files, VendorFiles[:]...)
	if err != nil {
		return VendorStatement{}, fmt.Errorf("%w: files: %v", ErrStatement, err)
	}
	st.digests = map[string][sha256.Size]byte{}
	for _, path := range VendorFiles {
		var h string
		if err := json.Unmarshal(listed[path], &h); err != nil {
			return VendorStatement{}, fmt.Errorf("%w: %s: %v", ErrStatement, path, err)
		}
		sum, err := hex.DecodeString(h)
		if err != nil || len(sum) != sha256.Size || h != hex.EncodeToString(sum) {
			return VendorStatement{}, fmt.Errorf("%w: %s is not 64 lowercase hex digits", ErrStatement, path)
		}
		st.digests[path] = [sha256.Size]byte(sum)
	}
	return st, nil
}

// Digest is the hex sha256 the statement lists for a path in VendorFiles, or "" for any other.
func (s VendorStatement) Digest(path string) string {
	d, ok := s.digests[path]
	if !ok {
		return ""
	}
	return hex.EncodeToString(d[:])
}

// CheckFile returns the JCS bytes of the file at path when they hash to the digest the statement lists. Those
// are the bytes the signer vouched for, so a caller parses them and never the raw file.
func (s VendorStatement) CheckFile(path string, raw []byte) ([]byte, error) {
	want, ok := s.digests[path]
	if !ok {
		return nil, fmt.Errorf("%w: the statement lists no %s", ErrStatement, path)
	}
	canonical, err := jcs.Canonicalize(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrStatement, path, err)
	}
	if sha256.Sum256(canonical) != want {
		return nil, fmt.Errorf("%w: %s is not the file the statement lists", ErrStatement, path)
	}
	return canonical, nil
}

// VerifyVendor checks the bundle over a vendor statement and parses it. Like Verify, the statement must name
// the commit the signing run built from.
func VerifyVendor(statement, bundle []byte, root TrustRoot, id Identity) (VendorStatement, time.Time, error) {
	rec, err := VerifyBundle(statement, bundle, root, id)
	if err != nil {
		return VendorStatement{}, time.Time{}, err
	}
	st, err := ParseVendorStatement(statement)
	if err != nil {
		return VendorStatement{}, time.Time{}, err
	}
	if st.PinsCommit != rec.SourceDigest {
		return VendorStatement{}, time.Time{}, fmt.Errorf("%w: pins_commit %s is not the commit the signer built from, %s", ErrStatement, st.PinsCommit, rec.SourceDigest)
	}
	return st, rec.IntegratedTime, nil
}

// AdmitVendor is Admit for a vendor statement, which names no environment: its sequence is at or above the
// floor, and Rekor logged it at or before now and no more than maxAge before. now must come from a source the
// host cannot move.
func AdmitVendor(st VendorStatement, floor uint64, integrated, now time.Time, maxAge time.Duration) error {
	return admitWindow(st.Sequence, floor, integrated, now, maxAge)
}
