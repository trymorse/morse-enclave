// Package tuf runs the TUF client workflow over metadata that the caller
// supplies, at a reference time that the caller supplies. It reads no
// network, disk or wall clock, so the enclave, which has none of them,
// and the host run the same code.
package tuf

import (
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

//go:embed sigstore-root-16.json
var sigstoreRoot []byte

// SigstoreRoot returns root.json version 16 of Sigstore's public-good TUF
// repository, which expires on 2027-04-22. It returns a copy, so no caller
// can change the root that every other caller trusts.
func SigstoreRoot() []byte { return append([]byte(nil), sigstoreRoot...) }

// Set is the metadata the host fetched, in the order the workflow reads it.
type Set struct {
	// Roots holds every root after the trusted one, oldest first. It is
	// empty when the trusted root is the newest.
	Roots       [][]byte `json:"roots"`
	Timestamp   []byte   `json:"timestamp"`
	Snapshot    []byte   `json:"snapshot"`
	Targets     []byte   `json:"targets"`
	TrustedRoot []byte   `json:"trusted_root"`
}

// TrustedRoot is a trusted_root.json that Verify accepted. Its field is
// unexported, so Verify is the only way to get one.
type TrustedRoot struct {
	json []byte
}

// JSON returns the verified bytes.
func (r TrustedRoot) JSON() []byte { return r.json }

// ErrUnverified wraps every refusal of Verify.
var ErrUnverified = errors.New("tuf: the metadata did not verify")

const trustedRootTarget = "trusted_root.json"

// Verify checks set against the trusted root at time at: each newer root
// signed by a threshold of the keys of the root before it and of its own,
// then the timestamp, the snapshot version it names, the targets version
// that names, and the length and hashes of trusted_root.json. Only the
// final root, the timestamp, the snapshot and the targets must be unexpired
// at at.
func Verify(trusted []byte, set Set, at time.Time) (_ TrustedRoot, err error) {
	// go-tuf v2.4.2 panics parsing a targets.json that lists a target as
	// null, before it checks a signature, and the host supplies the bytes.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: go-tuf panicked: %v", ErrUnverified, r)
		}
	}()
	if at.IsZero() {
		return TrustedRoot{}, fmt.Errorf("%w: no reference time", ErrUnverified)
	}
	md, err := trustedmetadata.New(trusted)
	if err != nil {
		return TrustedRoot{}, fmt.Errorf("%w: the trusted root: %v", ErrUnverified, err)
	}
	// New sets RefTime to the wall clock, and every expiry check reads it.
	md.RefTime = at
	for i, root := range set.Roots {
		if _, err := md.UpdateRoot(root); err != nil {
			return TrustedRoot{}, fmt.Errorf("%w: root %d of the set: %v", ErrUnverified, i, err)
		}
	}
	if _, err := md.UpdateTimestamp(set.Timestamp); err != nil {
		return TrustedRoot{}, fmt.Errorf("%w: timestamp: %v", ErrUnverified, err)
	}
	if _, err := md.UpdateSnapshot(set.Snapshot, false); err != nil {
		return TrustedRoot{}, fmt.Errorf("%w: snapshot: %v", ErrUnverified, err)
	}
	targets, err := md.UpdateTargets(set.Targets)
	if err != nil {
		return TrustedRoot{}, fmt.Errorf("%w: targets: %v", ErrUnverified, err)
	}
	target, ok := targets.Signed.Targets[trustedRootTarget]
	if !ok {
		return TrustedRoot{}, fmt.Errorf("%w: targets lists no %s", ErrUnverified, trustedRootTarget)
	}
	if err := target.VerifyLengthHashes(set.TrustedRoot); err != nil {
		return TrustedRoot{}, fmt.Errorf("%w: %s: %v", ErrUnverified, trustedRootTarget, err)
	}
	return TrustedRoot{json: append([]byte(nil), set.TrustedRoot...)}, nil
}
