package door

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"morse/backend/internal/sigstore/rekorv2"
	"morse/backend/internal/sigstore/tuf"
)

// morsePEN is Morse's IANA Private Enterprise Number, the arc under which
// the record extension's OID lives.
const morsePEN = 67561

// KeyAgeMargin is how long before MaxKeyAge a key stops being taken, handed
// or ordered for, so every certificate an honest host orders starts before
// the key reaches MaxKeyAge.
const KeyAgeMargin = 24 * time.Hour

// RecordOID marks the record certificate's extension, which carries the
// record's JSON as a DER OCTET STRING.
var RecordOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, morsePEN, 1}

// Receipt is the proof that the log holds this custody's record. prove is
// its only constructor, and update refuses a state whose receipt is zero.
type Receipt struct {
	log   string
	index uint64
}

func (r Receipt) logged() Logged { return Logged{Log: r.log, Index: r.index} }

// RecordDigest is H, the digest K signs for every entry of its record, and
// the digest a watcher requires of every entry it counts.
func RecordDigest(spkiSHA256 string) [32]byte {
	return sha256.Sum256([]byte(RecordType + "\n" + spkiSHA256 + "\n"))
}

func recordCertificate(key held, r Record, start time.Time) ([]byte, error) {
	recordJSON, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	value, err := asn1.Marshal(recordJSON)
	if err != nil {
		return nil, err
	}
	// A handed key starts a second custody with another record, so the
	// serial is random rather than derived from the key.
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:    new(big.Int).SetBytes(append([]byte{1}, random...)),
		Subject:         pkix.Name{CommonName: RecordType + " " + r.SPKISHA256},
		NotBefore:       start,
		NotAfter:        start.Add(MaxKeyAge),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: RecordOID, Value: value}},
	}
	return x509.CreateCertificate(rand.Reader, template, template, &key.private.PublicKey, key.private)
}

// ReadRecordCertificate returns the record that a record certificate
// carries. It checks no signature: the record is genuine only if its Nitro
// document verifies.
func ReadRecordCertificate(der []byte) (Record, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return Record{}, err
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(RecordOID) {
			continue
		}
		var recordJSON []byte
		if rest, err := asn1.Unmarshal(ext.Value, &recordJSON); err != nil || len(rest) > 0 {
			return Record{}, errors.New("the record extension is not one OCTET STRING")
		}
		var r Record
		if err := json.Unmarshal(recordJSON, &r); err != nil {
			return Record{}, fmt.Errorf("the record does not parse: %w", err)
		}
		return r, nil
	}
	return Record{}, errors.New("the certificate carries no record extension")
}

// startCustody attests key with origin and makes the custody's record
// certificate, which names this boot through the document.
func (d *Door) startCustody(ctx context.Context, key held, origin Origin, start time.Time) ([]byte, error) {
	document, err := d.enclave.Attest(ctx, key.spki, OriginNonce(key.spkiSHA256(), origin))
	if err != nil {
		return nil, err
	}
	r := Record{Type: RecordType, Environment: d.environment, Document: document, SPKISHA256: key.spkiSHA256(),
		Origin: AnswerOrigin{Born: origin.Born.UTC(), From: origin.From, Floor: origin.Floor}}
	return recordCertificate(key, r, start)
}

func (d *Door) entry() (Entry, *Refusal) {
	c := d.custody.Load()
	if _, unrecorded := c.state.(Unrecorded); !unrecorded {
		return Entry{}, refuse(http.StatusConflict, "recorded", "this door's record is already proven")
	}
	digest := RecordDigest(c.key.spkiSHA256())
	signature, err := ecdsa.SignASN1(rand.Reader, c.key.private, digest[:])
	if err != nil {
		return Entry{}, refuse(http.StatusInternalServerError, "unsigned", "%v", err)
	}
	return Entry{Certificate: c.record, Digest: digest[:], Signature: signature}, nil
}

// prove is step 8 of PUT /door/record: the verified entry carries this
// custody's record certificate and a signature by its key over H.
func prove(c *custody, e rekorv2.Entry) (Receipt, *Refusal) {
	body := e.Body()
	digest := RecordDigest(c.key.spkiSHA256())
	if body.Digest != digest || !bytes.Equal(body.Certificate, c.record) || !ecdsa.VerifyASN1(&c.key.private.PublicKey, digest[:], body.Signature) {
		return Receipt{}, refuse(http.StatusUnprocessableEntity, string(rekorv2.NotThisRecord), "the entry does not carry this custody's record and a signature by its key")
	}
	return Receipt{log: e.Origin(), index: e.Index()}, nil
}

func (d *Door) record(ctx context.Context, p Proof) *Refusal {
	if _, unrecorded := d.custody.Load().state.(Unrecorded); !unrecorded {
		return nil
	}
	now, err := d.now(ctx)
	if err != nil {
		return refuse(http.StatusServiceUnavailable, "unattested", "this enclave could not read its time: %v", err)
	}
	trusted, err := tuf.Verify(d.trust.TUFRoot, p.TUF, now)
	if err != nil {
		return refuse(http.StatusUnprocessableEntity, "tuf_unverified", "%v", err)
	}
	shards, err := rekorv2.ParseShards(trusted)
	if err != nil {
		return refuse(http.StatusUnprocessableEntity, "tuf_unverified", "%v", err)
	}
	e, err := rekorv2.Verify(p.Entry, shards, d.trust.Witnesses, rekorv2.At(now))
	if err != nil {
		var r *rekorv2.Refusal
		if !errors.As(err, &r) {
			return refuse(http.StatusUnprocessableEntity, string(rekorv2.NotV2), "%v", err)
		}
		return refuse(http.StatusUnprocessableEntity, string(r.Reason), "%s", r.Detail)
	}
	_, refused := d.update(func(c *custody) (*custody, *Refusal) {
		unrecorded, ok := c.state.(Unrecorded)
		if !ok {
			return c, nil
		}
		receipt, refused := prove(c, e)
		if refused != nil {
			return nil, refused
		}
		next := *c
		if unrecorded.handed != nil && now.Sub(c.origin.Born) < MaxKeyAge && d.checkChain(unrecorded.handed, c.key, now) == nil {
			next.state = servingOn(unrecorded.handed, c.key, receipt)
			return &next, nil
		}
		self, err := d.selfSigned(c.key)
		if err != nil {
			return nil, refuse(http.StatusInternalServerError, "unsigned", "%v", err)
		}
		next.state = newUnserved(receipt, self)
		return &next, nil
	})
	return refused
}

// selfSigned is what a dev door serves once recorded, and nil in prod.
func (d *Door) selfSigned(key held) (*tls.Certificate, error) {
	if d.environment != "dev" {
		return nil, nil
	}
	return selfSigned(key)
}
