package rekorv2

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
)

func leafHash(body []byte) [32]byte {
	return sha256.Sum256(append([]byte{0}, body...))
}

func nodeHash(left, right [32]byte) [32]byte {
	return sha256.Sum256(append(append([]byte{1}, left[:]...), right[:]...))
}

// rootFromProof is the RFC 9162 Section 2.1.3.2 inclusion check: it folds
// the proof from the leaf at index up to the root of a tree of size.
func rootFromProof(index, size uint64, leaf [32]byte, proof [][32]byte) ([32]byte, error) {
	if index >= size {
		return [32]byte{}, fmt.Errorf("leaf index %d is outside a tree of size %d", index, size)
	}
	inner := bits.Len64(index ^ (size - 1))
	border := bits.OnesCount64(index >> inner)
	if len(proof) != inner+border {
		return [32]byte{}, fmt.Errorf("the inclusion proof has %d hashes, not %d", len(proof), inner+border)
	}
	h := leaf
	for i, p := range proof[:inner] {
		if (index>>i)&1 == 0 {
			h = nodeHash(h, p)
		} else {
			h = nodeHash(p, h)
		}
	}
	for _, p := range proof[inner:] {
		h = nodeHash(p, h)
	}
	return h, nil
}

// VerifyConsistency checks that newer extends older, by the RFC 9162
// Section 2.1.4.2 consistency proof.
func VerifyConsistency(older, newer Checkpoint, proof [][32]byte) error {
	if older.origin != newer.origin {
		return fmt.Errorf("rekorv2: %s and %s are different logs", older.origin, newer.origin)
	}
	return consistent(older.size, newer.size, older.root, newer.root, proof)
}

func consistent(size1, size2 uint64, root1, root2 [32]byte, proof [][32]byte) error {
	switch {
	case size1 > size2:
		return fmt.Errorf("rekorv2: the older tree has %d leaves and the newer %d", size1, size2)
	case size1 == size2:
		if len(proof) != 0 || root1 != root2 {
			return fmt.Errorf("rekorv2: two trees of size %d differ", size1)
		}
		return nil
	case size1 == 0:
		if len(proof) != 0 {
			return fmt.Errorf("rekorv2: a proof from the empty tree has hashes")
		}
		return nil
	case len(proof) == 0:
		return fmt.Errorf("rekorv2: the consistency proof is empty")
	}
	if size1&(size1-1) == 0 {
		proof = append([][32]byte{root1}, proof...)
	}
	fn, sn := size1-1, size2-1
	for fn&1 == 1 {
		fn, sn = fn>>1, sn>>1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return fmt.Errorf("rekorv2: the consistency proof is too long")
		}
		if fn&1 == 1 || fn == sn {
			fr, sr = nodeHash(c, fr), nodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn, sn = fn>>1, sn>>1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn, sn = fn>>1, sn>>1
	}
	if sn != 0 || fr != root1 || sr != root2 {
		return fmt.Errorf("rekorv2: the consistency proof does not join the two roots")
	}
	return nil
}
