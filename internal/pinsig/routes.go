package pinsig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"morse/backend/internal/sigstore/rekorv2"
)

const routesStatementType = "morse-routes-v1"

func RoutesFile(environment string) string {
	return "routes/" + environment + "/routes.json"
}

type RoutesStatement struct {
	Environment string
	Sequence    uint64
	PinsCommit  string
	Time        time.Time
	Base        [sha256.Size]byte
	File        [sha256.Size]byte
}

func lowercaseSHA256(raw json.RawMessage) ([sha256.Size]byte, error) {
	var h string
	if err := json.Unmarshal(raw, &h); err != nil {
		return [sha256.Size]byte{}, err
	}
	sum, err := hex.DecodeString(h)
	if err != nil || len(sum) != sha256.Size || h != hex.EncodeToString(sum) {
		return [sha256.Size]byte{}, fmt.Errorf("not 64 lowercase hex digits")
	}
	return [sha256.Size]byte(sum), nil
}

func ParseRoutesStatement(raw []byte) (RoutesStatement, error) {
	fields, err := canonicalFields(raw, "base", "environment", "files", "pins_commit", "sequence", "time", "type")
	if err != nil {
		return RoutesStatement{}, err
	}
	var (
		typ, at string
		st      RoutesStatement
	)
	for key, into := range map[string]any{"type": &typ, "environment": &st.Environment, "sequence": &st.Sequence, "pins_commit": &st.PinsCommit, "time": &at} {
		if err := json.Unmarshal(fields[key], into); err != nil {
			return RoutesStatement{}, fmt.Errorf("%w: %s: %v", ErrStatement, key, err)
		}
	}
	if typ != routesStatementType {
		return RoutesStatement{}, fmt.Errorf("%w: type %q is not %s", ErrStatement, typ, routesStatementType)
	}
	if st.Environment == "" {
		return RoutesStatement{}, fmt.Errorf("%w: no environment", ErrStatement)
	}
	if err := checkHeader(st.PinsCommit, at, &st.Time); err != nil {
		return RoutesStatement{}, err
	}
	if st.Base, err = lowercaseSHA256(fields["base"]); err != nil {
		return RoutesStatement{}, fmt.Errorf("%w: base: %v", ErrStatement, err)
	}
	path := RoutesFile(st.Environment)
	listed, err := exactFields(fields["files"], path)
	if err != nil {
		return RoutesStatement{}, fmt.Errorf("%w: files: %v", ErrStatement, err)
	}
	if st.File, err = lowercaseSHA256(listed[path]); err != nil {
		return RoutesStatement{}, fmt.Errorf("%w: %s: %v", ErrStatement, path, err)
	}
	return st, nil
}

func (s RoutesStatement) CheckFile(raw []byte) error {
	if sha256.Sum256(raw) != s.File {
		return fmt.Errorf("%w: %s is not the file the statement lists", ErrStatement, RoutesFile(s.Environment))
	}
	return nil
}

func VerifyRoutes(statement, bundle []byte, root TrustRoot, id Identity, witnesses rekorv2.WitnessPolicy) (RoutesStatement, time.Time, error) {
	rec, err := VerifyBundleV2(statement, bundle, root, id, witnesses)
	if err != nil {
		return RoutesStatement{}, time.Time{}, err
	}
	st, err := ParseRoutesStatement(statement)
	if err != nil {
		return RoutesStatement{}, time.Time{}, err
	}
	if st.PinsCommit != rec.SourceDigest {
		return RoutesStatement{}, time.Time{}, fmt.Errorf("%w: pins_commit %s is not the commit the signer built from, %s", ErrStatement, st.PinsCommit, rec.SourceDigest)
	}
	return st, rec.NotBefore, nil
}

func AdmitRoutes(st RoutesStatement, env string, boot [sha256.Size]byte, floor uint64, signed, now time.Time, maxAge time.Duration) error {
	if st.Environment != env {
		return fmt.Errorf("%w: statement is for %s, not %s", ErrAdmit, st.Environment, env)
	}
	if st.Base != boot {
		return fmt.Errorf("%w: statement is for the image whose routes.json is %x, not %x", ErrAdmit, st.Base, boot)
	}
	return admitWindow(st.Sequence, floor, signed, now, maxAge)
}
