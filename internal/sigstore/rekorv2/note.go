package rekorv2

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	logSignatureAlg = 0x01
	maxSignatures   = 100
)

type noteSig struct {
	name string
	hash [4]byte
	sig  []byte
}

func parseNote(note string) (text []byte, sigs []noteSig, err error) {
	if !utf8.ValidString(note) || strings.ContainsAny(note, "\r\x00") {
		return nil, nil, fmt.Errorf("the note is not plain UTF-8 text")
	}
	split := strings.LastIndex(note, "\n\n")
	if split < 0 || !strings.HasSuffix(note, "\n") {
		return nil, nil, fmt.Errorf("the note has no signature block")
	}
	text = []byte(note[:split+1])
	lines := strings.Split(strings.TrimSuffix(note[split+2:], "\n"), "\n")
	if len(lines) > maxSignatures {
		return nil, nil, fmt.Errorf("the note has %d signature lines", len(lines))
	}
	for _, line := range lines {
		rest, ok := strings.CutPrefix(line, "— ")
		name, b64, ok2 := strings.Cut(rest, " ")
		raw, err := base64.StdEncoding.DecodeString(b64)
		if !ok || !ok2 || !validName(name) || err != nil || len(raw) < 5 {
			return nil, nil, fmt.Errorf("the signature line %q is malformed", line)
		}
		sigs = append(sigs, noteSig{name: name, hash: [4]byte(raw[:4]), sig: raw[4:]})
	}
	return text, sigs, nil
}

func validName(name string) bool {
	return name != "" && utf8.ValidString(name) && !strings.ContainsAny(name, " +\n\t")
}

// Checkpoint is a checkpoint whose shard signature and witness count
// verified. Its fields are unexported, so holding one is proof of both.
type Checkpoint struct {
	origin    string
	size      uint64
	root      [32]byte
	note      string
	cosigners []Cosigner
}

func (c Checkpoint) Origin() string { return c.origin }
func (c Checkpoint) Size() uint64   { return c.size }
func (c Checkpoint) Root() [32]byte { return c.root }

// Note returns the signed note as it arrived.
func (c Checkpoint) Note() string { return c.note }

// Cosigners returns the counted cosignatures, at most one per witness name
// and one per operator, earliest first.
func (c Checkpoint) Cosigners() []Cosigner { return append([]Cosigner(nil), c.cosigners...) }

type checkpointText struct {
	origin string
	size   uint64
	root   [32]byte
}

// Extension lines may follow the first three, and must not be empty
// (C2SP tlog-checkpoint).
func parseCheckpointText(text []byte) (checkpointText, error) {
	lines := strings.Split(strings.TrimSuffix(string(text), "\n"), "\n")
	if len(lines) < 3 || lines[0] == "" {
		return checkpointText{}, fmt.Errorf("the checkpoint has fewer than three lines")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || strconv.FormatUint(size, 10) != lines[1] {
		return checkpointText{}, fmt.Errorf("the checkpoint's size %q is not a decimal number", lines[1])
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != 32 {
		return checkpointText{}, fmt.Errorf("the checkpoint's root hash is not 32 bytes of base64")
	}
	if slices.Contains(lines[3:], "") {
		return checkpointText{}, fmt.Errorf("the checkpoint has an empty extension line")
	}
	return checkpointText{origin: lines[0], size: size, root: [32]byte(root)}, nil
}

func verifyNote(note string, sh shard, size uint64, root [32]byte, p WitnessPolicy) (Checkpoint, *Refusal) {
	text, sigs, err := parseNote(note)
	if err != nil {
		return Checkpoint{}, refuse(BadCheckpoint, err.Error())
	}
	ct, err := parseCheckpointText(text)
	switch {
	case err != nil:
		return Checkpoint{}, refuse(BadCheckpoint, err.Error())
	case ct.origin != sh.origin:
		return Checkpoint{}, refuse(BadCheckpoint, fmt.Sprintf("the checkpoint's origin %q is not %q", ct.origin, sh.origin))
	case ct.size != size:
		return Checkpoint{}, refuse(BadCheckpoint, fmt.Sprintf("the checkpoint's size %d is not the proof's %d", ct.size, size))
	case ct.root != root:
		return Checkpoint{}, refuse(BadCheckpoint, "the checkpoint's root hash is not the proof's")
	}
	if !signedByLog(text, sigs, sh) {
		return Checkpoint{}, refuse(LogSignature, "no signature line by "+sh.origin+" verifies under its key")
	}
	counted := p.count(text, sigs)
	if p.k < 1 || len(counted) < p.k {
		return Checkpoint{}, refuse(TooFewWitnesses, fmt.Sprintf("%d of the %d cosignatures needed", len(counted), p.k))
	}
	return Checkpoint{origin: ct.origin, size: ct.size, root: ct.root, note: note, cosigners: counted}, nil
}

func signedByLog(text []byte, sigs []noteSig, sh shard) bool {
	hash := keyHash(sh.origin, logSignatureAlg, sh.key)
	for _, s := range sigs {
		if s.name == sh.origin && s.hash == hash && len(s.sig) == ed25519.SignatureSize && ed25519.Verify(sh.key, text, s.sig) {
			return true
		}
	}
	return false
}

// VerifyCheckpoint verifies a bare checkpoint note: its origin names a
// shard valid at when, the shard signed it, and enough witnesses cosigned
// it. A note carries no log id, so it is tried under every shard of its
// origin.
func VerifyCheckpoint(note string, s Shards, p WitnessPolicy, when When) (Checkpoint, error) {
	text, _, err := parseNote(note)
	if err != nil {
		return Checkpoint{}, refuse(BadCheckpoint, err.Error())
	}
	ct, err := parseCheckpointText(text)
	if err != nil {
		return Checkpoint{}, refuse(BadCheckpoint, err.Error())
	}
	var last error = refuse(UnknownLog, "the trusted root lists no Ed25519 log named "+ct.origin)
	for _, id := range slices.SortedFunc(maps.Keys(s.byID), func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) }) {
		sh := s.byID[id]
		if sh.origin != ct.origin {
			continue
		}
		c, err := verifyAt(sh, when, p.k, func() (Checkpoint, *Refusal) { return verifyNote(note, sh, ct.size, ct.root, p) })
		if err == nil {
			return c, nil
		}
		last = err
	}
	return Checkpoint{}, last
}
