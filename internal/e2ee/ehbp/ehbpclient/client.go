// Package ehbpclient is the client's end of an EHBP exchange: it seals a request to an enclave's attested X25519 key
// and opens the reply. It holds no way to open a request, so a process that links it, the enclave worker sealing its
// own calls to Tinfoil's privacy filter among them, can read only the replies to what it sent.
package ehbpclient

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"

	"morse/backend/internal/e2ee/ehbp"
)

const (
	// RequestInfo is the HPKE info a request is sealed under, and ResponseLabel the export label its reply key comes from.
	RequestInfo   = "ehbp request"
	ResponseLabel = "ehbp response"
	// RequestChunk is how much plaintext a request frame seals.
	RequestChunk = 64 << 10
)

var ErrOpen = errors.New("ehbp: a frame does not open under the exchange's key")

// Suite is EHBP's HPKE KDF and AEAD.
func Suite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.AES256GCM() }

// A Request is a sealed request's context on the client: the encapsulated key it sends, and the sender
// context its reply key derives from.
type Request struct {
	Encapsulated []byte
	sender       *hpke.Sender
}

func (r Request) EncapsulatedHex() string { return hex.EncodeToString(r.Encapsulated) }

// SealRequest seals plaintext to the enclave's X25519 key as framed ciphertext.
func SealRequest(recipient, plaintext []byte) (Request, []byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(recipient)
	if err != nil {
		return Request{}, nil, err
	}
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return Request{}, nil, err
	}
	kdf, aead := Suite()
	enc, sender, err := hpke.NewSender(pk, kdf, aead, []byte(RequestInfo))
	if err != nil {
		return Request{}, nil, err
	}
	var body bytes.Buffer
	for chunk := range slices.Chunk(plaintext, RequestChunk) {
		sealed, err := sender.Seal(nil, chunk)
		if err != nil {
			return Request{}, nil, err
		}
		body.Write(Frame(sealed))
	}
	return Request{Encapsulated: enc, sender: sender}, body.Bytes(), nil
}

// Reply opens the reply frames of a request the enclave answered with nonceHex.
func (r Request) Reply(nonceHex string) (*Opener, error) {
	secret, err := r.sender.Export(ResponseLabel, 32)
	if err != nil {
		return nil, err
	}
	return NewOpener(secret, r.Encapsulated, nonceHex)
}

// An Opener holds a reply's key and opens, or seals, its frames in order.
type Opener struct {
	gcm   cipher.AEAD
	nbase []byte
	seq   uint64
}

// NewOpener derives a reply's keys from the request context's exported secret, salted with the encapsulated key and
// the enclave's response nonce.
func NewOpener(secret, enc []byte, nonceHex string) (*Opener, error) {
	nonce, ok := ehbp.LowerHex(nonceHex, ehbp.NonceLen)
	if !ok {
		return nil, ehbp.ErrNotApplied
	}
	gcm, nbase, err := replyKeys(secret, enc, nonce)
	if err != nil {
		return nil, err
	}
	return &Opener{gcm: gcm, nbase: nbase}, nil
}

// replyKeys derive the reply's AES-256-GCM key and nonce base from the request context's exported secret,
// salted with the encapsulated key and the enclave's response nonce.
func replyKeys(secret, enc, nonce []byte) (cipher.AEAD, []byte, error) {
	prk, err := hkdf.Extract(sha256.New, secret, append(bytes.Clone(enc), nonce...))
	if err != nil {
		return nil, nil, err
	}
	key, err := hkdf.Expand(sha256.New, prk, "key", 32)
	if err != nil {
		return nil, nil, err
	}
	nbase, err := hkdf.Expand(sha256.New, prk, "nonce", 12)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	return gcm, nbase, err
}

func (o *Opener) nonce() []byte {
	n := bytes.Clone(o.nbase)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], o.seq)
	for i, b := range seq {
		n[len(n)-8+i] ^= b
	}
	o.seq++
	return n
}

// Open opens one frame's ciphertext, its length prefix removed.
func (o *Opener) Open(ciphertext []byte) ([]byte, error) {
	plain, err := o.gcm.Open(nil, o.nonce(), ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: frame %d", ErrOpen, o.seq-1)
	}
	return plain, nil
}

// OpenAll opens a whole framed reply.
func (o *Opener) OpenAll(r io.Reader) ([]byte, error) {
	var out bytes.Buffer
	_, err := ehbp.Frames(r, ehbp.MaxFrame, func(f []byte) error {
		if len(f) == ehbp.FrameHeaderLen {
			return nil
		}
		plain, err := o.Open(f[ehbp.FrameHeaderLen:])
		out.Write(plain)
		return err
	})
	return out.Bytes(), err
}

// Seal seals one reply frame with the next nonce, as the enclave does.
func (o *Opener) Seal(plaintext []byte) []byte {
	return Frame(o.gcm.Seal(nil, o.nonce(), plaintext, nil))
}

// Frame prefixes ciphertext with its length.
func Frame(ciphertext []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(ciphertext))), ciphertext...)
}
