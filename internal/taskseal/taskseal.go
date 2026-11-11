// Package taskseal seals what a scheduled task keeps and sends. A task's bundle rests at the relay sealed under the
// task key (Key) of the worker that adopted it, named by the key's Epoch, and each run's result and preview go to the
// task's devices, sealed to each device's X25519 delivery key. Only a worker holding the key opens a bundle, and only
// a device opens a result or a preview: the web app's src/lib/scheduled reads them by the same rules, and
// testdata/vectors.json holds both to the same bytes.
//
//	epoch    = SHA-256("morse-task-epoch-v1" ‖ task key)[0:8]
//	bundle   = 0x01 ‖ epoch(8) ‖ nonce(12) ‖ AES-256-GCM(task key, nonce, pad(json, 1024),
//	           aad = "morse-task-bundle-v1" ‖ task(16) ‖ epoch(8) ‖ u64be(revision))
//	envelope = 0x01 ‖ kid(8) ‖ enc(32) ‖ HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM,
//	           to the device key, info ResultInfo or PreviewInfo, aad = 0x01 ‖ kid(8) ‖ task(16) ‖ run(16),
//	           a result's json pad(json, 1024), a preview's pad(json, 1536) to exactly 1,536 bytes
//	revision = the worker-chosen bundle_rev the relay stores beside the bundle
//	pad(json, n) = u32be(len(json)) ‖ json ‖ zeros to the next whole number of n bytes
package taskseal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"morse/backend/internal/seal"
)

const (
	Version = 1

	EpochInfo   = "morse-task-epoch-v1"
	BundleAAD   = "morse-task-bundle-v1"
	ResultInfo  = "morse-task-result-v1"
	PreviewInfo = "morse-task-preview-v1"

	// Unit is what a bundle's or a result's padded plaintext is a whole number of.
	Unit = 1024
	// PreviewSize is a preview's padded plaintext, exactly.
	PreviewSize = 1536
	// MaxResultSize bounds a result's padded plaintext.
	MaxResultSize = 256 << 10
	// MaxBundleSize bounds a bundle at rest, as the relay stores it.
	MaxBundleSize = 128 << 10

	BundleOverhead   = headSize + nonceSize + tagSize
	EnvelopeOverhead = headSize + encSize + tagSize

	// The most JSON each carries, after the 4-byte length its padding starts with.
	MaxBundleJSON  = (MaxBundleSize-BundleOverhead)/Unit*Unit - lengthSize
	MaxResultJSON  = MaxResultSize - lengthSize
	MaxPreviewJSON = PreviewSize - lengthSize
)

const (
	epochSize  = 8
	secretSize = 32
	headSize   = 1 + epochSize
	nonceSize  = 12
	encSize    = 32
	tagSize    = 16
	lengthSize = 4
)

var (
	// ErrInvalid is a bundle or an envelope that does not open: malformed, of another version, epoch, task, run, or
	// info, under another key, tampered with, or padded against the rules.
	ErrInvalid = errors.New("taskseal: the sealed bytes do not open")
	// ErrKeyUnknown is an envelope sealed to another device key than the one opening it.
	ErrKeyUnknown = errors.New("taskseal: the envelope is sealed to another key")
	// ErrTooLarge is a plaintext past what its envelope carries.
	ErrTooLarge = errors.New("taskseal: the plaintext is past what its envelope carries")
)

var (
	kem  = hpke.DHKEM(ecdh.X25519())
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
)

// Epoch names a task key. A bundle carries the epoch of the key it is sealed under, and the relay claims and strands
// tasks by it. It is not the worker's HPKE key id, so a task key can outlive the identity of the boot that made it.
type Epoch [epochSize]byte

func (e Epoch) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(e[:])), nil }

func (e *Epoch) UnmarshalText(text []byte) error {
	if hex.DecodedLen(len(text)) != epochSize {
		return fmt.Errorf("taskseal: an epoch is %d hex characters, not %q", 2*epochSize, text)
	}
	_, err := hex.Decode(e[:], text)
	return err
}

// Key is the AES-256 key a worker seals task bundles under, with its Epoch.
type Key struct {
	secret [secretSize]byte
	epoch  Epoch
}

func NewKey() *Key {
	var secret [secretSize]byte
	rand.Read(secret[:])
	return KeyFromSecret(secret)
}

// KeyFromSecret is the task key of these 32 bytes, with the epoch they derive.
func KeyFromSecret(secret [secretSize]byte) *Key {
	sum := sha256.Sum256(slices.Concat([]byte(EpochInfo), secret[:]))
	return &Key{secret: secret, epoch: Epoch(sum[:epochSize])}
}

func (k *Key) Epoch() Epoch { return k.epoch }

// SealBundle seals a task's bundle JSON under the task key, for that task alone at that revision.
func SealBundle(key *Key, task [16]byte, revision uint64, plaintext []byte) ([]byte, error) {
	var nonce [nonceSize]byte
	rand.Read(nonce[:])
	return sealBundle(key, task, revision, nonce, plaintext)
}

func sealBundle(key *Key, task [16]byte, revision uint64, nonce [nonceSize]byte, plaintext []byte) ([]byte, error) {
	padded, err := bundleFraming.pad(plaintext)
	if err != nil {
		return nil, err
	}
	return bundleOf(key.secret, headOf(key.epoch), nonce, bundleAAD(task, key.epoch, revision), padded)
}

func bundleOf(secret [secretSize]byte, head []byte, nonce [nonceSize]byte, aad, padded []byte) ([]byte, error) {
	gcm, err := gcmOf(secret)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(slices.Concat(head, nonce[:]), nonce[:], padded, aad), nil
}

// OpenBundle opens a bundle sealed under this task key for this task at this revision, and returns its JSON.
func OpenBundle(key *Key, task [16]byte, revision uint64, bundle []byte) ([]byte, error) {
	if len(bundle) < BundleOverhead || bundle[0] != Version {
		return nil, fmt.Errorf("%w: not a version %d bundle", ErrInvalid, Version)
	}
	if Epoch(bundle[1:headSize]) != key.epoch {
		return nil, fmt.Errorf("%w: sealed under another epoch", ErrInvalid)
	}
	if !bundleFraming.holds(len(bundle) - BundleOverhead) {
		return nil, fmt.Errorf("%w: a bundle of %d bytes", ErrInvalid, len(bundle))
	}
	gcm, err := gcmOf(key.secret)
	if err != nil {
		return nil, err
	}
	nonce, ct := bundle[headSize:headSize+nonceSize], bundle[headSize+nonceSize:]
	padded, err := gcm.Open(nil, nonce, ct, bundleAAD(task, key.epoch, revision))
	if err != nil {
		return nil, fmt.Errorf("%w: not under this task key for this task at this revision", ErrInvalid)
	}
	return bundleFraming.unpad(padded)
}

func bundleAAD(task [16]byte, epoch Epoch, revision uint64) []byte {
	return binary.BigEndian.AppendUint64(slices.Concat([]byte(BundleAAD), task[:], epoch[:]), revision)
}

func gcmOf(key [secretSize]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealResult seals a run's result JSON to one device's X25519 key, for this task and run alone.
func SealResult(pub []byte, task, run [16]byte, result []byte) ([]byte, error) {
	return SealFor(pub, ResultInfo, task, run, result)
}

// SealPreview seals the preview JSON a push shows to one device's X25519 key, for this task and run alone.
func SealPreview(pub []byte, task, run [16]byte, preview []byte) ([]byte, error) {
	return SealFor(pub, PreviewInfo, task, run, preview)
}

// SealFor seals plaintext to the device key pub as info says: a result (ResultInfo), padded to whole units, or a
// preview (PreviewInfo), padded to exactly PreviewSize.
func SealFor(pub []byte, info string, task, run [16]byte, plaintext []byte) ([]byte, error) {
	return sealFor(hpkeEncrypt, pub, info, task, run, plaintext)
}

// An encrypter seals padded to pk in HPKE's base mode, single shot, under info and aad. crypto/hpke draws its own
// ephemeral key, so the vectors pass one that takes a fixed key instead.
type encrypter func(pk hpke.PublicKey, info, aad, padded []byte) (enc, ct []byte, err error)

func hpkeEncrypt(pk hpke.PublicKey, info, aad, padded []byte) ([]byte, []byte, error) {
	enc, sender, err := hpke.NewSender(pk, kdf, aead, info)
	if err != nil {
		return nil, nil, err
	}
	ct, err := sender.Seal(aad, padded)
	return enc, ct, err
}

func sealFor(encrypt encrypter, pub []byte, info string, task, run [16]byte, plaintext []byte) ([]byte, error) {
	f, err := framingOf(info)
	if err != nil {
		return nil, err
	}
	padded, err := f.pad(plaintext)
	if err != nil {
		return nil, err
	}
	return envelopeOf(encrypt, pub, headOf(seal.KeyIDOf(pub)), info, task, run, padded)
}

func envelopeOf(encrypt encrypter, pub, head []byte, info string, task, run [16]byte, padded []byte) ([]byte, error) {
	pk, err := kem.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	enc, ct, err := encrypt(pk, []byte(info), envelopeAAD(head, task, run), padded)
	if err != nil {
		return nil, err
	}
	if len(enc) != encSize {
		return nil, fmt.Errorf("taskseal: a %d-byte encapsulated key", len(enc))
	}
	return slices.Concat(head, enc, ct), nil
}

// Open opens an envelope sealed to the X25519 key priv makes, as info says, for this task and run, and returns its
// JSON.
func Open(priv []byte, info string, task, run [16]byte, envelope []byte) ([]byte, error) {
	f, err := framingOf(info)
	if err != nil {
		return nil, err
	}
	sk, err := kem.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	if len(envelope) < EnvelopeOverhead || envelope[0] != Version {
		return nil, fmt.Errorf("%w: not a version %d envelope", ErrInvalid, Version)
	}
	if seal.KeyID(envelope[1:headSize]) != seal.KeyIDOf(sk.PublicKey().Bytes()) {
		return nil, ErrKeyUnknown
	}
	if !f.holds(len(envelope) - EnvelopeOverhead) {
		return nil, fmt.Errorf("%w: an envelope of %d bytes", ErrInvalid, len(envelope))
	}
	recipient, err := hpke.NewRecipient(envelope[headSize:headSize+encSize], sk, kdf, aead, []byte(info))
	if err != nil {
		return nil, fmt.Errorf("%w: the encapsulated key", ErrInvalid)
	}
	padded, err := recipient.Open(envelopeAAD(envelope[:headSize], task, run), envelope[headSize+encSize:])
	if err != nil {
		return nil, fmt.Errorf("%w: not to this key for this task and run", ErrInvalid)
	}
	return f.unpad(padded)
}

func envelopeAAD(head []byte, task, run [16]byte) []byte { return slices.Concat(head, task[:], run[:]) }

func headOf(id [8]byte) []byte { return append([]byte{Version}, id[:]...) }

// A framing pads a plaintext to a whole number of unit bytes, at most limit.
type framing struct{ unit, limit int }

var (
	bundleFraming  = framing{Unit, MaxBundleSize - BundleOverhead}
	resultFraming  = framing{Unit, MaxResultSize}
	previewFraming = framing{PreviewSize, PreviewSize}
)

func framingOf(info string) (framing, error) {
	switch info {
	case ResultInfo:
		return resultFraming, nil
	case PreviewInfo:
		return previewFraming, nil
	}
	return framing{}, fmt.Errorf("taskseal: %q is neither the result's info nor the preview's", info)
}

func (f framing) pad(plaintext []byte) ([]byte, error) {
	size := (lengthSize + len(plaintext) + f.unit - 1) / f.unit * f.unit
	if size > f.limit {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(plaintext))
	}
	padded := make([]byte, size)
	binary.BigEndian.PutUint32(padded, uint32(len(plaintext)))
	copy(padded[lengthSize:], plaintext)
	return padded, nil
}

func (f framing) holds(size int) bool { return size >= f.unit && size <= f.limit && size%f.unit == 0 }

func (f framing) unpad(padded []byte) ([]byte, error) {
	if !f.holds(len(padded)) {
		return nil, fmt.Errorf("%w: %d bytes of padded plaintext", ErrInvalid, len(padded))
	}
	n := binary.BigEndian.Uint32(padded)
	if uint64(n) > uint64(len(padded)-lengthSize) {
		return nil, fmt.Errorf("%w: a length past the plaintext", ErrInvalid)
	}
	end := lengthSize + int(n)
	if slices.ContainsFunc(padded[end:], func(b byte) bool { return b != 0 }) {
		return nil, fmt.Errorf("%w: padding that is not zeros", ErrInvalid)
	}
	return padded[lengthSize:end], nil
}
