package clip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	UploadPath    = "/v1/vendor-upload/"
	UploadPattern = "PUT " + UploadPath + "{ticket}"

	EpochSize = 8

	ticketVersion = 1
	ticketHead    = 1 + EpochSize
	maxTicket     = 4 << 10
	infoTicketKey = "morse-clip-ticket-v1"
)

var (
	ErrTicket      = errors.New("clip: not an upload ticket")
	ErrTicketEpoch = errors.New("clip: the upload ticket is sealed under another fleet key")
)

type Ticket struct {
	Key      Key
	Clip     string
	Store    string
	Deadline time.Time
}

type ticketWire struct {
	Key      []byte `json:"k"`
	Clip     string `json:"c"`
	Store    string `json:"s"`
	Deadline int64  `json:"d"`
}

type TicketKey struct {
	aead  cipher.AEAD
	epoch [EpochSize]byte
}

type TicketKeys func() (*TicketKey, bool)

// why: the fleet secret is the enclaves' task key (internal/taskseal), which only an attested enclave of this image
// takes from a peer, so one HKDF label apart from the task bundles' gives every instance the same ticket key.
func NewTicketKey(fleet [KeySize]byte, epoch [EpochSize]byte) (*TicketKey, error) {
	sub, err := hkdf.Key(sha256.New, fleet[:], nil, infoTicketKey, KeySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sub)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &TicketKey{aead: aead, epoch: epoch}, nil
}

func (t Ticket) URL(origin Origin, k *TicketKey) string {
	plain, _ := json.Marshal(ticketWire{Key: t.Key[:], Clip: t.Clip, Store: t.Store, Deadline: t.Deadline.Unix()})
	head := append([]byte{ticketVersion}, k.epoch[:]...)
	nonce := make([]byte, nonceSize)
	rand.Read(nonce)
	sealed := k.aead.Seal(append(head, nonce...), nonce, plain, head)
	return origin.String() + UploadPath + base64.RawURLEncoding.EncodeToString(sealed)
}

func ParseTicket(k *TicketKey, s string) (Ticket, error) {
	if len(s) > maxTicket {
		return Ticket{}, ErrTicket
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < ticketHead+nonceSize+TagSize || raw[0] != ticketVersion {
		return Ticket{}, ErrTicket
	}
	if [EpochSize]byte(raw[1:ticketHead]) != k.epoch {
		return Ticket{}, ErrTicketEpoch
	}
	plain, err := k.aead.Open(nil, raw[ticketHead:ticketHead+nonceSize], raw[ticketHead+nonceSize:], raw[:ticketHead])
	if err != nil {
		return Ticket{}, ErrTicket
	}
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	var w ticketWire
	if dec.Decode(&w) != nil || dec.More() || len(w.Key) != KeySize || w.Clip == "" || w.Store == "" || w.Deadline <= 0 {
		return Ticket{}, ErrTicket
	}
	return Ticket{Key: Key(w.Key), Clip: w.Clip, Store: w.Store, Deadline: time.Unix(w.Deadline, 0)}, nil
}

type Origin struct{ u *url.URL }

func ParseOrigin(name, raw string) (Origin, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.TrimRight(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return Origin{}, fmt.Errorf("%s must be the https origin the vendor uploads each clip to, with no path, such as https://inference.trymorse.ai", name)
	}
	return Origin{u: &url.URL{Scheme: u.Scheme, Host: u.Host}}, nil
}

func (o Origin) String() string { return o.u.String() }

type Store struct{ u *url.URL }

func ParseStore(name, raw string) (Store, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Store{}, fmt.Errorf("%s must be the https URL of the bucket that holds sealed clips, as VIDEO_STORE_URL names it, such as https://account.r2.cloudflarestorage.com/bucket", name)
	}
	return Store{u: &url.URL{Scheme: u.Scheme, Host: u.Host, Path: strings.TrimRight(u.Path, "/")}}, nil
}

func (s Store) Holds(dest string) bool {
	u, err := url.Parse(dest)
	return err == nil && s.u != nil && u.Scheme == s.u.Scheme && u.Host == s.u.Host && u.User == nil && u.Fragment == "" &&
		strings.HasPrefix(u.Path, s.u.Path+"/") && len(u.Path) > len(s.u.Path)+1 && path.Clean(u.Path) == u.Path
}
