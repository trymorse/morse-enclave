package ehbp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
)

// The proxy never opens a body. These are the two ends it sits between, for cmd/e2eechat and for the tests'
// stand-in router: a client seals a request to the enclave's key and opens the reply; an enclave opens the
// request and seals the reply.

const (
	requestInfo   = "ehbp request"
	responseLabel = "ehbp response"
	// requestChunk is how much plaintext a request frame seals.
	requestChunk = 64 << 10
)

var ErrOpen = errors.New("ehbp: a frame does not open under the exchange's key")

func suite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.AES256GCM() }

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
	kdf, aead := suite()
	enc, sender, err := hpke.NewSender(pk, kdf, aead, []byte(requestInfo))
	if err != nil {
		return Request{}, nil, err
	}
	var body bytes.Buffer
	for chunk := range slices.Chunk(plaintext, requestChunk) {
		sealed, err := sender.Seal(nil, chunk)
		if err != nil {
			return Request{}, nil, err
		}
		body.Write(frame(sealed))
	}
	return Request{Encapsulated: enc, sender: sender}, body.Bytes(), nil
}

// Reply opens the reply frames of a request the enclave answered with nonceHex.
func (r Request) Reply(nonceHex string) (*Opener, error) {
	secret, err := r.sender.Export(responseLabel, 32)
	if err != nil {
		return nil, err
	}
	return replyOpener(secret, r.Encapsulated, nonceHex)
}

// An Opener opens a reply's frames in order.
type Opener struct {
	gcm   cipher.AEAD
	nbase []byte
	seq   uint64
}

func replyOpener(secret, enc []byte, nonceHex string) (*Opener, error) {
	nonce, ok := lowerHex(nonceHex, nonceLen)
	if !ok {
		return nil, errNotApplied
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
	_, err := Frames(r, MaxFrame, func(f []byte) error {
		if len(f) == frameHeaderLen {
			return nil
		}
		plain, err := o.Open(f[frameHeaderLen:])
		out.Write(plain)
		return err
	})
	return out.Bytes(), err
}

// A Responder is the enclave's end of one exchange: it opened the request, and seals the reply.
type Responder struct {
	Nonce string
	gcm   *Opener
}

// OpenRequest opens a framed request sealed to key, as an enclave does, and readies the reply's sealing.
func OpenRequest(key *ecdh.PrivateKey, encHex string, body io.Reader) ([]byte, *Responder, error) {
	enc, ok := lowerHex(encHex, keyLen)
	if !ok {
		return nil, nil, ErrInvalidKey
	}
	sk, err := hpke.NewDHKEMPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	kdf, aead := suite()
	recipient, err := hpke.NewRecipient(enc, sk, kdf, aead, []byte(requestInfo))
	if err != nil {
		return nil, nil, err
	}
	var plain bytes.Buffer
	if _, err := Frames(body, requestChunk+gcmTagLen, func(f []byte) error {
		if len(f) == frameHeaderLen {
			return nil
		}
		p, err := recipient.Open(nil, f[frameHeaderLen:])
		plain.Write(p)
		return err
	}); err != nil {
		return nil, nil, err
	}
	secret, err := recipient.Export(responseLabel, 32)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, nonceLen)
	rand.Read(nonce)
	nonceHex := hex.EncodeToString(nonce)
	keys, err := replyOpener(secret, enc, nonceHex)
	if err != nil {
		return nil, nil, err
	}
	return plain.Bytes(), &Responder{Nonce: nonceHex, gcm: keys}, nil
}

// Seal seals one reply frame.
func (r *Responder) Seal(plaintext []byte) []byte {
	return frame(r.gcm.gcm.Seal(nil, r.gcm.nonce(), plaintext, nil))
}

func frame(ciphertext []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(ciphertext))), ciphertext...)
}
