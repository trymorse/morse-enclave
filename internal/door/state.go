package door

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"morse/backend/internal/nitro/verify"
	"morse/backend/internal/seal"
)

var sharedNames = map[string]string{"prod": "inference.trymorse.ai", "dev": "inference.watermark.ac"}

const (
	maxChain      = 64 << 10
	PinsMaxAge    = 7 * 24 * time.Hour
	originType    = "morse-door-origin-v1"
	answerRetries = 3
)

type Origin struct {
	Born  time.Time
	From  *seal.KeyID
	Floor uint64
}

type State interface{ wire() string }

type Unserved struct{ selfSigned *tls.Certificate }

type Serving struct {
	Chain    []*x509.Certificate
	NotAfter time.Time
	served   *tls.Certificate
}

func (Unserved) wire() string { return StateUnserved }
func (Serving) wire() string  { return StateServing }

const (
	StateUnserved = "unserved"
	StateServing  = "serving"
)

type custody struct {
	key    held
	origin Origin
	state  State
}

type held struct {
	private *ecdsa.PrivateKey
	spki    []byte
	names   []string
	csr     []byte
}

type Door struct {
	environment string
	roots       *x509.CertPool
	enclave     Enclave
	trust       Trust
	custody     atomic.Pointer[custody]
	ready       chan struct{}
}

type Enclave interface {
	Attest(ctx context.Context, tls, nonce []byte) ([]byte, error)
	Time(document []byte) (time.Time, error)
	Peer(document []byte, expect verify.Expectation) ([]byte, verify.Key, error)
	Open(sealed []byte) (seal.Request, error)
}

func New(environment string, enclave Enclave, trust Trust, floor uint64) (*Door, error) {
	var roots *x509.CertPool
	if environment == "prod" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("door: the image's CA bundle: %w", err)
		}
		roots = pool
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return newDoor(environment, roots, enclave, trust, key, floor)
}

func newDoor(environment string, roots *x509.CertPool, enclave Enclave, trust Trust, key *ecdsa.PrivateKey, floor uint64) (*Door, error) {
	if _, known := sharedNames[environment]; !known {
		return nil, fmt.Errorf("door: environment %q is neither dev nor prod", environment)
	}
	if environment == "prod" && roots == nil {
		return nil, errors.New("door: prod verifies each chain to the image's CA bundle, and has none")
	}
	h, err := hold(sharedNames[environment], key)
	if err != nil {
		return nil, err
	}
	var unserved Unserved
	if environment == "dev" {
		if unserved.selfSigned, err = selfSigned(h); err != nil {
			return nil, err
		}
	}
	document, err := enclave.Attest(context.Background(), h.spki, nil)
	if err != nil {
		return nil, fmt.Errorf("door: the enclave's time at boot: %w", err)
	}
	born, err := enclave.Time(document)
	if err != nil {
		return nil, fmt.Errorf("door: the enclave's time at boot: %w", err)
	}
	d := &Door{environment: environment, roots: roots, enclave: enclave, trust: trust, ready: make(chan struct{})}
	d.custody.Store(&custody{key: h, origin: Origin{Born: born, Floor: floor}, state: unserved})
	return d, nil
}

func hold(shared string, key *ecdsa.PrivateKey) (held, error) {
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return held{}, err
	}
	sum := sha256.Sum256(spki)
	names := []string{shared, hex.EncodeToString(sum[:8]) + ".k." + shared}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		return held{}, err
	}
	return held{private: key, spki: spki, names: names, csr: csr}, nil
}

func (h held) spkiSHA256() string {
	sum := sha256.Sum256(h.spki)
	return hex.EncodeToString(sum[:])
}

func (d *Door) update(change func(*custody) (*custody, *Refusal)) (*custody, *Refusal) {
	for {
		current := d.custody.Load()
		next, refused := change(current)
		if refused != nil || next == current {
			return current, refused
		}
		if d.custody.CompareAndSwap(current, next) {
			_, was := current.state.(Unserved)
			if _, is := next.state.(Serving); was && is {
				close(d.ready)
			}
			return next, nil
		}
	}
}

func (d *Door) attest(ctx context.Context, nonce func(*custody) []byte) ([]byte, *custody, error) {
	c := d.custody.Load()
	var n []byte
	if nonce != nil {
		n = nonce(c)
	}
	document, err := d.enclave.Attest(ctx, c.key.spki, n)
	return document, c, err
}

func (d *Door) Attest(ctx context.Context) ([]byte, error) {
	document, _, err := d.attest(ctx, nil)
	return document, err
}

func (d *Door) now(ctx context.Context) (time.Time, error) {
	document, _, err := d.attest(ctx, nil)
	if err != nil {
		return time.Time{}, err
	}
	return d.enclave.Time(document)
}

func (d *Door) Ready() <-chan struct{} { return d.ready }

func (d *Door) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	switch state := d.custody.Load().state.(type) {
	case Serving:
		return state.served, nil
	case Unserved:
		if state.selfSigned != nil {
			return state.selfSigned, nil
		}
	}
	return nil, errors.New("door: no certificate yet")
}

func selfSigned(key held) (*tls.Certificate, error) {
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), DNSNames: key.names, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.private.PublicKey, key.private)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key.private}, nil
}

type Answer struct {
	Object      string             `json:"object"`
	State       string             `json:"state"`
	Environment string             `json:"environment"`
	SPKISHA256  string             `json:"spki_sha256"`
	Names       []string           `json:"names"`
	CSR         string             `json:"csr"`
	Origin      AnswerOrigin       `json:"origin"`
	Certificate *AnswerCertificate `json:"certificate,omitempty"`
	Document    []byte             `json:"document"`
}

type AnswerOrigin struct {
	Born  time.Time   `json:"born"`
	From  *seal.KeyID `json:"from"`
	Floor uint64      `json:"floor"`
}

type AnswerCertificate struct {
	Issuer    string    `json:"issuer"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

type originStatement struct {
	Origin struct {
		Born  time.Time   `json:"born"`
		Floor uint64      `json:"floor"`
		From  *seal.KeyID `json:"from"`
	} `json:"origin"`
	SPKISHA256 string `json:"spki_sha256"`
	Type       string `json:"type"`
}

func OriginNonce(spkiSHA256 string, o Origin) []byte {
	s := originStatement{SPKISHA256: spkiSHA256, Type: originType}
	s.Origin.Born, s.Origin.Floor, s.Origin.From = o.Born.UTC(), o.Floor, o.From
	return canonicalSum(s)
}

func canonicalSum(v any) []byte {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		panic(err)
	}
	sum := sha256.Sum256(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
	return sum[:]
}

func (d *Door) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /door", func(w http.ResponseWriter, r *http.Request) {
		for range answerRetries {
			document, attested, err := d.attest(r.Context(), func(c *custody) []byte { return OriginNonce(c.key.spkiSHA256(), c.origin) })
			if err != nil {
				break
			}
			if d.custody.Load() == attested {
				writeJSON(w, http.StatusOK, d.answer(attested, document))
				return
			}
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	mux.HandleFunc("POST /door/handoff", func(w http.ResponseWriter, r *http.Request) {
		var req Handoff
		if refused := readJSON(w, r, &req); refused != nil {
			writeJSON(w, refused.status, refused)
			return
		}
		handed, refused := d.handoff(r.Context(), req)
		if refused != nil {
			writeJSON(w, refused.status, refused)
			return
		}
		writeJSON(w, http.StatusOK, handed)
	})
	mux.HandleFunc("PUT /door/key", func(w http.ResponseWriter, r *http.Request) {
		var req Handed
		if refused := readJSON(w, r, &req); refused != nil {
			writeJSON(w, refused.status, refused)
			return
		}
		if refused := d.take(r.Context(), req); refused != nil {
			writeJSON(w, refused.status, refused)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /door/certificate", func(w http.ResponseWriter, r *http.Request) {
		chain, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxChain))
		if err != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, refuse(http.StatusRequestEntityTooLarge, "chain_too_large", "the chain is over %d bytes", maxChain))
			return
		}
		if refused := d.install(r.Context(), chain); refused != nil {
			writeJSON(w, refused.status, refused)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func (d *Door) answer(c *custody, document []byte) Answer {
	a := Answer{
		Object: "door", State: c.state.wire(), Environment: d.environment, SPKISHA256: c.key.spkiSHA256(),
		Names: c.key.names, CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: c.key.csr})),
		Origin: AnswerOrigin{Born: c.origin.Born.UTC(), From: c.origin.From, Floor: c.origin.Floor}, Document: document,
	}
	if serving, ok := c.state.(Serving); ok {
		leaf := serving.Chain[0]
		a.Certificate = &AnswerCertificate{Issuer: leaf.Issuer.String(), Serial: leaf.SerialNumber.Text(16), NotBefore: leaf.NotBefore, NotAfter: serving.NotAfter}
	}
	return a
}

type Refusal struct {
	status  int
	Object  string `json:"object"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func refuse(status int, reason, format string, args ...any) *Refusal {
	return &Refusal{status: status, Object: "error", Reason: reason, Message: fmt.Sprintf(format, args...)}
}

func (d *Door) install(ctx context.Context, chainPEM []byte) *Refusal {
	chain, refused := parseChain(chainPEM)
	if refused != nil {
		return refused
	}
	now, err := d.now(ctx)
	if err != nil {
		return refuse(http.StatusServiceUnavailable, "unattested", "this enclave could not read its time: %v", err)
	}
	_, refused = d.update(func(c *custody) (*custody, *Refusal) {
		if refused := d.checkChain(chain, c.key, now); refused != nil {
			return nil, refused
		}
		return &custody{key: c.key, origin: c.origin, state: serving(chain, c.key)}, nil
	})
	return refused
}

func parseChain(chainPEM []byte) ([]*x509.Certificate, *Refusal) {
	var chain []*x509.Certificate
	for rest := chainPEM; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, refuse(http.StatusUnprocessableEntity, "chain_unreadable", "the chain holds a %s block", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, refuse(http.StatusUnprocessableEntity, "chain_unreadable", "a certificate does not parse: %v", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, refuse(http.StatusUnprocessableEntity, "chain_unreadable", "the body holds no PEM certificate")
	}
	return chain, nil
}

func (d *Door) checkChain(chain []*x509.Certificate, key held, now time.Time) *Refusal {
	leaf := chain[0]
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, key.spki) {
		return refuse(http.StatusUnprocessableEntity, "key_mismatch", "the leaf's key is not the door's key")
	}
	for _, name := range key.names {
		if !slices.Contains(leaf.DNSNames, name) {
			return refuse(http.StatusUnprocessableEntity, "name_missing", "the leaf does not name %s", name)
		}
	}
	if now.Before(leaf.NotBefore) {
		return refuse(http.StatusUnprocessableEntity, "not_yet_valid", "the leaf is valid from %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return refuse(http.StatusUnprocessableEntity, "expired", "the leaf expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if d.roots != nil {
		intermediates := x509.NewCertPool()
		for _, cert := range chain[1:] {
			intermediates.AddCert(cert)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: key.names[0], Roots: d.roots, CurrentTime: now, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return refuse(http.StatusUnprocessableEntity, "untrusted", "the chain does not verify to the image's CA bundle: %v", err)
		}
	}
	return nil
}

func serving(chain []*x509.Certificate, key held) Serving {
	served := &tls.Certificate{PrivateKey: key.private, Leaf: chain[0]}
	for _, cert := range chain {
		served.Certificate = append(served.Certificate, cert.Raw)
	}
	return Serving{Chain: chain, NotAfter: chain[0].NotAfter, served: served}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}
