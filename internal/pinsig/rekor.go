package pinsig

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"strconv"
	"strings"

	"morse/backend/internal/jcs"
)

// verifySET checks the signed entry timestamp: Rekor v1 signs the canonical
// JSON of the entry's body, integrated time, log id, and log index.
func verifySET(e logEntry, key *ecdsa.PublicKey) error {
	payload, err := jcs.Marshal(map[string]any{
		"body":           base64.StdEncoding.EncodeToString(e.canonicalBody),
		"integratedTime": json.Number(strconv.FormatInt(e.integratedTime.Unix(), 10)),
		"logID":          hex.EncodeToString(e.logID[:]),
		"logIndex":       json.Number(strconv.FormatUint(e.logIndex, 10)),
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLog, err)
	}
	digest := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(key, digest[:], e.set) {
		return fmt.Errorf("%w: the signed entry timestamp did not verify", ErrLog)
	}
	return nil
}

// verifyInclusion checks the RFC 6962 inclusion proof from the entry's leaf
// hash to the proof's root hash, and that the log signed a checkpoint for
// that root hash and tree size.
func verifyInclusion(e logEntry, key *ecdsa.PublicKey) error {
	leaf := sha256.Sum256(append([]byte{0}, e.canonicalBody...))
	root, err := rootFromProof(e.proof.index, e.proof.treeSize, leaf, e.proof.hashes)
	if err != nil {
		return err
	}
	if root != e.proof.rootHash {
		return fmt.Errorf("%w: the inclusion proof does not reach the root hash", ErrLog)
	}
	return verifyCheckpoint(e.proof.checkpoint, e.proof.treeSize, e.proof.rootHash, e.logID, key)
}

func rootFromProof(index, size uint64, leaf [32]byte, proof [][32]byte) ([32]byte, error) {
	if index >= size {
		return [32]byte{}, fmt.Errorf("%w: leaf index %d is outside a tree of size %d", ErrLog, index, size)
	}
	inner := bits.Len64(index ^ (size - 1))
	border := bits.OnesCount64(index >> inner)
	if len(proof) != inner+border {
		return [32]byte{}, fmt.Errorf("%w: inclusion proof has %d hashes, not %d", ErrLog, len(proof), inner+border)
	}
	h := leaf
	for i, p := range proof[:inner] {
		if (index>>i)&1 == 0 {
			h = node(h, p)
		} else {
			h = node(p, h)
		}
	}
	for _, p := range proof[inner:] {
		h = node(p, h)
	}
	return h, nil
}

func node(left, right [32]byte) [32]byte {
	return sha256.Sum256(append(append([]byte{1}, left[:]...), right[:]...))
}

// verifyCheckpoint parses a signed note whose text is the origin, the tree
// size, and the root hash, and whose signature line names the log by the
// first four bytes of its id.
func verifyCheckpoint(envelope string, treeSize uint64, rootHash, logID [32]byte, key *ecdsa.PublicKey) error {
	text, sigs, ok := strings.Cut(envelope, "\n\n")
	if !ok {
		return fmt.Errorf("%w: checkpoint has no signature block", ErrLog)
	}
	text += "\n"
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 || lines[0] == "" {
		return fmt.Errorf("%w: checkpoint has fewer than three lines or no origin", ErrLog)
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || size != treeSize {
		return fmt.Errorf("%w: checkpoint tree size %q is not the proof's %d", ErrLog, lines[1], treeSize)
	}
	hash, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(hash) != 32 || [32]byte(hash) != rootHash {
		return fmt.Errorf("%w: checkpoint root hash is not the proof's", ErrLog)
	}
	digest := sha256.Sum256([]byte(text))
	// Rekor v1 signs a checkpoint once, and sigstore-go refuses one with more signature lines.
	line := strings.TrimSuffix(sigs, "\n")
	_, rest, ok := strings.Cut(line, "— ")
	if strings.Contains(line, "\n") || !ok {
		return fmt.Errorf("%w: checkpoint has other than one signature line", ErrLog)
	}
	_, b64, _ := strings.Cut(rest, " ")
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(sig) < 5 || [4]byte(sig[:4]) != [4]byte(logID[:4]) || !ecdsa.VerifyASN1(key, digest[:], sig[4:]) {
		return fmt.Errorf("%w: no checkpoint signature by the log key", ErrLog)
	}
	return nil
}
