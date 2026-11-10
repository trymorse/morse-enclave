// Package seal is the sealed transport between the web app and the proxy: a request sealed to the proxy's per-boot
// HPKE key, and a reply framed under the request's content key. It is the wire format POST /v1/sealed takes.
package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	Version  = 1
	MaxKeys  = 4
	Pad      = 1024
	MaxSkew  = 120 * time.Second
	MaxHead  = 8 << 10
	Overhead = prefixSize + MaxKeys*entrySize + 4 + MaxHead + Pad + tagSize

	keyIDSize   = 8
	encSize     = 32
	cekSize     = 32
	tagSize     = 16
	wrappedSize = cekSize + tagSize
	entrySize   = keyIDSize + encSize + wrappedSize
	prefixSize  = 2
	infoCEK     = "morse-seal-v1 cek"
)

var (
	ErrKeyUnknown   = errors.New("seal: no entry is sealed to this key")
	ErrInvalid      = errors.New("seal: the sealed request does not open")
	ErrHeadTooLarge = errors.New("seal: the head is over MaxHead")
)

var (
	kem  = hpke.DHKEM(ecdh.X25519())
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
)

type KeyID [keyIDSize]byte

func KeyIDOf(publicKey []byte) KeyID {
	sum := sha256.Sum256(publicKey)
	return KeyID(sum[:keyIDSize])
}

func (k KeyID) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(k[:])), nil }

func (k *KeyID) UnmarshalText(text []byte) error {
	if hex.DecodedLen(len(text)) != keyIDSize {
		return fmt.Errorf("seal: a key id is %d hex characters, not %q", 2*keyIDSize, text)
	}
	_, err := hex.Decode(k[:], text)
	return err
}

type Identity struct {
	key hpke.PrivateKey
	pub []byte
	id  KeyID
}

func NewIdentity() (*Identity, error) {
	key, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	return identityOf(key), nil
}

func IdentityFromKey(privateKey []byte) (*Identity, error) {
	key, err := kem.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return identityOf(key), nil
}

func identityOf(key hpke.PrivateKey) *Identity {
	pub := key.PublicKey().Bytes()
	return &Identity{key: key, pub: pub, id: KeyIDOf(pub)}
}

func (i *Identity) PublicKey() []byte { return bytes.Clone(i.pub) }

func (i *Identity) KeyID() KeyID { return i.id }

type Head struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	TS      int64             `json:"ts"`
	// PrivacyVeil is a chat's privacy_veil, asked inside the seal so the relay can't drop it. A worker from before the
	// Veil refuses any head that carries it, rather than serve the chat unveiled. PrivacyVeilPartition is the client's
	// random id for the chat, at least 16 bytes in base64url, under which the worker may cache where details were.
	PrivacyVeil          json.RawMessage `json:"privacy_veil,omitempty"`
	PrivacyVeilPartition string          `json:"privacy_veil_partition,omitempty"`
}

type wireHead struct {
	Head
	BodyLen int `json:"body_len"`
}

type Request struct {
	Head
	Body []byte
	CEK  [cekSize]byte
	Enc  [encSize]byte
}

func (r Request) Fresh(now, started time.Time) bool {
	skew := now.Unix() - r.TS
	return skew <= int64(MaxSkew/time.Second) && -skew <= int64(MaxSkew/time.Second) && r.TS >= started.Unix()
}

type entry struct {
	id      KeyID
	enc     []byte
	wrapped []byte
}

func (i *Identity) Open(sealed []byte) (Request, error) {
	if len(sealed) < prefixSize || sealed[0] != Version {
		return Request{}, fmt.Errorf("%w: version", ErrInvalid)
	}
	count := int(sealed[1])
	if count < 1 || count > MaxKeys || len(sealed) < prefixSize+count*entrySize {
		return Request{}, fmt.Errorf("%w: entries", ErrInvalid)
	}
	aad, ct := sealed[:prefixSize+count*entrySize], sealed[prefixSize+count*entrySize:]
	var own *entry
	for n := range count {
		e := parseEntry(aad[prefixSize+n*entrySize:])
		if e.id == i.id {
			own = &e
			break
		}
	}
	if own == nil {
		return Request{}, ErrKeyUnknown
	}
	if len(ct) < Pad || len(ct)%Pad != 0 {
		return Request{}, fmt.Errorf("%w: ciphertext length", ErrInvalid)
	}
	recipient, err := hpke.NewRecipient(own.enc, i.key, kdf, aead, []byte(infoCEK))
	if err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	cek, err := recipient.Open(own.id[:], own.wrapped)
	if err != nil || len(cek) != cekSize {
		return Request{}, fmt.Errorf("%w: wrapped key", ErrInvalid)
	}
	content, err := contentCipher(cek)
	if err != nil {
		return Request{}, err
	}
	inner, err := content.Open(nil, zeroNonce[:], ct, aad)
	if err != nil {
		return Request{}, fmt.Errorf("%w: content", ErrInvalid)
	}
	head, body, err := parseInner(inner)
	if err != nil {
		return Request{}, err
	}
	r := Request{Head: head, Body: body, CEK: [cekSize]byte(cek), Enc: [encSize]byte(own.enc)}
	return r, nil
}

var zeroNonce [12]byte

func contentCipher(cek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func parseEntry(b []byte) entry {
	return entry{id: KeyID(b[:keyIDSize]), enc: b[keyIDSize : keyIDSize+encSize], wrapped: b[keyIDSize+encSize : entrySize]}
}

func parseInner(inner []byte) (Head, []byte, error) {
	if len(inner) < 4 {
		return Head{}, nil, fmt.Errorf("%w: inner length", ErrInvalid)
	}
	headLen := int(binary.BigEndian.Uint32(inner))
	if headLen > len(inner)-4 || headLen > MaxHead {
		return Head{}, nil, fmt.Errorf("%w: head length", ErrInvalid)
	}
	var head wireHead
	dec := json.NewDecoder(bytes.NewReader(inner[4 : 4+headLen]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&head); err != nil || dec.More() {
		return Head{}, nil, fmt.Errorf("%w: head", ErrInvalid)
	}
	rest := inner[4+headLen:]
	if head.BodyLen < 0 || head.BodyLen > len(rest) {
		return Head{}, nil, fmt.Errorf("%w: body length", ErrInvalid)
	}
	body, padding := rest[:head.BodyLen], rest[head.BodyLen:]
	if bytes.ContainsFunc(padding, func(r rune) bool { return r != 0 }) {
		return Head{}, nil, fmt.Errorf("%w: padding", ErrInvalid)
	}
	return head.Head, bytes.Clone(body), nil
}

type Inner struct{ buf []byte }

const (
	innerFront = prefixSize + MaxKeys*entrySize + 4 + MaxHead
	innerTail  = Pad + tagSize
)

func (i Inner) Len() int { return max(0, len(i.buf)-innerFront) }

func (i Inner) Room() int { return max(0, cap(i.buf)-innerFront-innerTail) }

func (i Inner) Body() []byte {
	if len(i.buf) < innerFront {
		return nil
	}
	return i.buf[innerFront:]
}

func (i *Inner) Grow(room int) {
	grown := make([]byte, innerFront+i.Len(), innerFront+max(room, i.Len())+innerTail)
	copy(grown[innerFront:], i.Body())
	i.buf = grown
}

func (i *Inner) Fill(r io.Reader) error {
	if i.buf == nil {
		i.Grow(0)
	}
	for i.Len() < i.Room() {
		n, err := r.Read(i.buf[len(i.buf) : innerFront+i.Room()])
		i.buf = i.buf[:len(i.buf)+n]
		if err != nil {
			return err
		}
	}
	return nil
}

func (i Inner) Seal(keys [][]byte, head Head) (sealed []byte, cek [cekSize]byte, err error) {
	rand.Read(cek[:])
	sealed, err = i.sealUnder(keys, head, cek, wrapCEK)
	return sealed, cek, err
}

func Seal(keys [][]byte, head Head, body []byte) ([]byte, [cekSize]byte, error) {
	var inner Inner
	inner.Grow(len(body))
	inner.Fill(bytes.NewReader(body))
	return inner.Seal(keys, head)
}

type wrapper func(publicKey []byte, id KeyID, cek []byte) (enc, wrapped []byte, err error)

func wrapCEK(publicKey []byte, id KeyID, cek []byte) ([]byte, []byte, error) {
	pk, err := kem.NewPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	enc, sender, err := hpke.NewSender(pk, kdf, aead, []byte(infoCEK))
	if err != nil {
		return nil, nil, err
	}
	wrapped, err := sender.Seal(id[:], cek)
	return enc, wrapped, err
}

func (i Inner) sealUnder(keys [][]byte, head Head, cek [cekSize]byte, wrap wrapper) ([]byte, error) {
	if len(keys) < 1 || len(keys) > MaxKeys {
		return nil, fmt.Errorf("seal: %d keys, want 1 to %d", len(keys), MaxKeys)
	}
	headJSON, err := json.Marshal(wireHead{Head: head, BodyLen: i.Len()})
	if err != nil {
		return nil, err
	}
	if len(headJSON) > MaxHead {
		return nil, fmt.Errorf("%w: %d bytes", ErrHeadTooLarge, len(headJSON))
	}
	if i.buf == nil {
		i.Grow(0)
	}
	start := innerFront - 4 - len(headJSON) - prefixSize - len(keys)*entrySize
	out := append(i.buf[start:start], Version, byte(len(keys)))
	for _, key := range keys {
		id := KeyIDOf(key)
		enc, wrapped, err := wrap(key, id, cek[:])
		if err != nil {
			return nil, err
		}
		if len(enc) != encSize || len(wrapped) != wrappedSize {
			return nil, fmt.Errorf("seal: wrapped a %d-byte enc and a %d-byte key", len(enc), len(wrapped))
		}
		out = append(out, id[:]...)
		out = append(out, enc...)
		out = append(out, wrapped...)
	}
	aad := out
	out = binary.BigEndian.AppendUint32(out, uint32(len(headJSON)))
	out = append(out, headJSON...)
	plain := i.buf[start+len(aad) : len(i.buf)]
	pad := padding(len(plain) + tagSize)
	plain = plain[:len(plain)+pad]
	clear(plain[len(plain)-pad:])
	content, err := contentCipher(cek[:])
	if err != nil {
		return nil, err
	}
	sealed := content.Seal(plain[:0], zeroNonce[:], plain, aad)
	return i.buf[start : start+len(aad)+len(sealed)], nil
}

func padding(n int) int { return (Pad - n%Pad) % Pad }
