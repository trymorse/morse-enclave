package rekorv2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	"morse/backend/internal/strictjson"
)

// entryJSON is a TransparencyLogEntry in protobuf JSON, as a Rekor v2 201
// carries it.
type entryJSON struct {
	LogIndex protoUint `json:"logIndex"`
	LogID    struct {
		KeyID []byte `json:"keyId"`
	} `json:"logId"`
	KindVersion struct {
		Kind    string `json:"kind"`
		Version string `json:"version"`
	} `json:"kindVersion"`
	IntegratedTime   json.RawMessage `json:"integratedTime,omitempty"`
	InclusionPromise json.RawMessage `json:"inclusionPromise,omitempty"`
	InclusionProof   struct {
		LogIndex   protoUint `json:"logIndex"`
		RootHash   []byte    `json:"rootHash"`
		TreeSize   protoUint `json:"treeSize"`
		Hashes     [][]byte  `json:"hashes"`
		Checkpoint struct {
			Envelope string `json:"envelope"`
		} `json:"checkpoint"`
	} `json:"inclusionProof"`
	CanonicalizedBody []byte `json:"canonicalizedBody"`
}

// protoUint is a uint64 that protobuf JSON writes as a string.
type protoUint uint64

func (n *protoUint) UnmarshalJSON(b []byte) error {
	v, err := strconv.ParseUint(string(bytes.Trim(b, `"`)), 10, 64)
	*n = protoUint(v)
	return err
}

func (n protoUint) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strconv.FormatUint(uint64(n), 10) + `"`), nil
}

// entryKeys lists the keys each object of an entry may have. encoding/json
// matches struct fields case-insensitively, so parseEntry checks the exact
// keys before it decodes into entryJSON.
var entryKeys = map[string][]string{
	"":                          {"logIndex", "logId", "kindVersion", "integratedTime", "inclusionPromise", "inclusionProof", "canonicalizedBody"},
	"logId":                     {"keyId"},
	"kindVersion":               {"kind", "version"},
	"inclusionProof":            {"logIndex", "rootHash", "treeSize", "hashes", "checkpoint"},
	"inclusionProof.checkpoint": {"envelope"},
}

func exactKeys(raw []byte, path string) error {
	fields, err := strictjson.Object(bytes.NewReader(raw), entryKeys[path]...)
	if err != nil {
		return err
	}
	for key, value := range fields {
		child := key
		if path != "" {
			child = path + "." + key
		}
		if _, nested := entryKeys[child]; nested {
			if err := exactKeys(value, child); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseEntry(raw []byte) (entryJSON, error) {
	var e entryJSON
	if err := strictjson.UniqueKeys(raw); err != nil {
		return entryJSON{}, err
	}
	if err := exactKeys(raw, ""); err != nil {
		return entryJSON{}, err
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return entryJSON{}, err
	}
	return e, nil
}

func (e entryJSON) hashes() ([][32]byte, error) {
	out := make([][32]byte, len(e.InclusionProof.Hashes))
	for i, h := range e.InclusionProof.Hashes {
		if len(h) != 32 {
			return nil, fmt.Errorf("proof hash %d is %d bytes", i, len(h))
		}
		out[i] = [32]byte(h)
	}
	return out, nil
}

// Entry is an entry that Verify accepted. The caller still compares its
// body with what it expects to have been logged.
type Entry struct {
	index      uint64
	body       HashedRekord
	checkpoint Checkpoint
}

func (e Entry) Index() uint64          { return e.index }
func (e Entry) Origin() string         { return e.checkpoint.origin }
func (e Entry) Body() HashedRekord     { return e.body }
func (e Entry) Checkpoint() Checkpoint { return e.checkpoint }

// Verify checks a Rekor v2 TransparencyLogEntry in the order of the door's
// PUT /door/record, steps 2 to 8, and returns the first failure as a
// *Refusal:
//
//  2. kindVersion is hashedrekord 0.0.2.
//  3. logId names a shard in s whose validFor contains when.
//  4. The leaf hash and the proof give the proof's root hash at logIndex.
//  5. The checkpoint names the shard's origin, treeSize and that root.
//  6. The shard's key signed the checkpoint.
//  7. At least k cosignatures under p, one per name and per operator.
//  8. The body is a strict hashedrekord v0.0.2 with a P-256 certificate.
//
// With Witnessed, step 3's validity check runs after step 7, at the k-th
// earliest counted cosignature time.
func Verify(raw []byte, s Shards, p WitnessPolicy, when When) (Entry, error) {
	e, err := parseEntry(raw)
	if err != nil {
		return Entry{}, refuse(NotV2, "the entry is not a TransparencyLogEntry: "+err.Error())
	}
	if e.KindVersion.Kind != "hashedrekord" || e.KindVersion.Version != "0.0.2" {
		return Entry{}, refuse(NotV2, fmt.Sprintf("the entry is %s %s", e.KindVersion.Kind, e.KindVersion.Version))
	}
	sh, r := s.lookup(e.LogID.KeyID)
	if r != nil {
		return Entry{}, r
	}
	c, err := verifyAt(sh, when, p.k, func() (Checkpoint, *Refusal) {
		proof := e.InclusionProof
		if proof.LogIndex != e.LogIndex {
			return Checkpoint{}, refuse(Inclusion, "the proof is for another index")
		}
		hashes, err := e.hashes()
		if err != nil {
			return Checkpoint{}, refuse(Inclusion, err.Error())
		}
		root, err := rootFromProof(uint64(e.LogIndex), uint64(proof.TreeSize), leafHash(e.CanonicalizedBody), hashes)
		if err != nil {
			return Checkpoint{}, refuse(Inclusion, err.Error())
		}
		if len(proof.RootHash) != 32 || root != [32]byte(proof.RootHash) {
			return Checkpoint{}, refuse(Inclusion, "the proof does not reach its root hash")
		}
		return verifyNote(proof.Checkpoint.Envelope, sh, uint64(proof.TreeSize), root, p)
	})
	if err != nil {
		return Entry{}, err
	}
	body, err := parseHashedRekord(e.CanonicalizedBody)
	if err != nil {
		return Entry{}, refuse(NotThisRecord, "the body is not a strict hashedrekord v0.0.2: "+err.Error())
	}
	return Entry{index: uint64(e.LogIndex), body: body, checkpoint: c}, nil
}
