package door

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"morse/backend/internal/nitro/verify"
	"morse/backend/internal/pinsig"
	"morse/backend/internal/seal"
)

const (
	MaxKeyAge   = 60 * 24 * time.Hour
	payloadType = "morse-door-key-v1"
	keyPath     = "/door/key"
	maxHandoff  = 256 << 10
)

type Pins struct {
	Statement []byte `json:"statement"`
	Bundle    []byte `json:"bundle"`
}

type Handoff struct {
	Receiver []byte `json:"receiver"`
	Pins     Pins   `json:"pins"`
}

type Handed struct {
	Blob     []byte `json:"blob"`
	Document []byte `json:"document"`
	Pins     Pins   `json:"pins"`
}

type payload struct {
	Type    string    `json:"type"`
	Key     []byte    `json:"key"`
	Chain   string    `json:"chain"`
	Born    time.Time `json:"born"`
	Floor   uint64    `json:"floor"`
	Records []Logged  `json:"records"`
}

type admitted struct {
	statement pinsig.Statement
	now       time.Time
	custody   *custody
}

type handoffStatement struct {
	BlobSHA256 string `json:"blob_sha256"`
	Type       string `json:"type"`
}

func HandoffNonce(blob []byte) []byte {
	sum := sha256.Sum256(blob)
	return canonicalSum(handoffStatement{BlobSHA256: hex.EncodeToString(sum[:]), Type: payloadType})
}

func (d *Door) admit(ctx context.Context, pins Pins) (admitted, *Refusal) {
	now, err := d.now(ctx)
	if err != nil {
		return admitted{}, refuse(http.StatusServiceUnavailable, "unattested", "this enclave could not read its time: %v", err)
	}
	st, logged, err := pinsig.Verify(pins.Statement, pins.Bundle, d.trust.Root, d.trust.Identity)
	if err != nil {
		return admitted{}, refuse(http.StatusUnprocessableEntity, "pins_unverified", "%v", err)
	}
	c, refused := d.update(func(c *custody) (*custody, *Refusal) {
		if err := pinsig.Admit(st, d.environment, c.floor, logged, now, PinsMaxAge); err != nil {
			return nil, refuse(http.StatusUnprocessableEntity, "pins_refused", "%v", err)
		}
		if st.Sequence == c.floor {
			return c, nil
		}
		raised := *c
		raised.floor = st.Sequence
		return &raised, nil
	})
	if refused != nil {
		return admitted{}, refused
	}
	return admitted{statement: st, now: now, custody: c}, nil
}

func (a admitted) expect(environment string) verify.Expectation {
	pins := make([]verify.Pin, len(a.statement.Images))
	for i, img := range a.statement.Images {
		pins[i] = verify.Pin{
			Image:       verify.Built(a.statement.PinsCommit, fmt.Sprintf("sequence %d", a.statement.Sequence)),
			Environment: a.statement.Environment,
			PCR0:        hex.EncodeToString(img.PCRs[0][:]),
			PCR1:        hex.EncodeToString(img.PCRs[1][:]),
			PCR2:        hex.EncodeToString(img.PCRs[2][:]),
			Revoked:     img.Revoked,
		}
	}
	return verify.Expectation{Environment: environment, Pins: pins, Now: a.now}
}

func (d *Door) handoff(ctx context.Context, req Handoff) (Handed, *Refusal) {
	in, refused := d.admit(ctx, req.Pins)
	if refused != nil {
		return Handed{}, refused
	}
	c := in.custody
	serving, isServing := c.state.(Serving)
	if !isServing {
		return Handed{}, refuse(http.StatusConflict, "unserved", "this door holds no certificate to hand off")
	}
	_, receiver, err := d.enclave.Peer(req.Receiver, in.expect(d.environment))
	if err != nil {
		return Handed{}, refuse(http.StatusUnprocessableEntity, "receiver_refused", "%v", err)
	}
	if age := in.now.Sub(c.origin.Born); age > MaxKeyAge-KeyAgeMargin {
		return Handed{}, refuse(http.StatusUnprocessableEntity, "key_too_old", "the key was born %s ago, past %s", age.Round(time.Hour), MaxKeyAge-KeyAgeMargin)
	}
	der, err := x509.MarshalPKCS8PrivateKey(c.key.private)
	if err != nil {
		return Handed{}, refuse(http.StatusInternalServerError, "unsealed", "%v", err)
	}
	var chain bytes.Buffer
	for _, cert := range serving.Chain {
		pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	records := append(append([]Logged{}, c.records...), serving.receipt.logged())
	body, err := json.Marshal(payload{Type: payloadType, Key: der, Chain: chain.String(), Born: c.origin.Born, Floor: c.floor, Records: records})
	if err != nil {
		return Handed{}, refuse(http.StatusInternalServerError, "unsealed", "%v", err)
	}
	blob, _, err := seal.Seal([][]byte{receiver.PublicKey}, seal.Head{Method: http.MethodPut, Path: keyPath, TS: in.now.Unix()}, body)
	if err != nil {
		return Handed{}, refuse(http.StatusUnprocessableEntity, "unsealed", "%v", err)
	}
	document, _, err := d.attest(ctx, func(*custody) []byte { return HandoffNonce(blob) })
	if err != nil {
		return Handed{}, refuse(http.StatusServiceUnavailable, "unattested", "this enclave could not attest: %v", err)
	}
	return Handed{Blob: blob, Document: document, Pins: req.Pins}, nil
}

func (d *Door) take(ctx context.Context, req Handed) *Refusal {
	if d.custody.Load().took {
		return refusedHolding()
	}
	in, refused := d.admit(ctx, req.Pins)
	if refused != nil {
		return refused
	}
	spki, sender, err := d.enclave.Peer(req.Document, in.expect(d.environment))
	if err != nil {
		return refuse(http.StatusUnprocessableEntity, "sender_refused", "%v", err)
	}
	if !bytes.Equal(sender.Nonce, HandoffNonce(req.Blob)) {
		return refuse(http.StatusUnprocessableEntity, "nonce_mismatch", "the sender's document does not name this blob")
	}
	opened, err := d.enclave.Open(req.Blob)
	if err == nil && (opened.Method != http.MethodPut || opened.Path != keyPath) {
		err = fmt.Errorf("the blob is sealed for %s %s", opened.Method, opened.Path)
	}
	if err != nil {
		return refuse(http.StatusUnprocessableEntity, "unopened", "%v", err)
	}
	p, private, refused := readPayload(opened.Body)
	if refused != nil {
		return refused
	}
	key, err := hold(sharedNames[d.environment], private)
	if err != nil {
		return refuse(http.StatusUnprocessableEntity, "payload_unreadable", "%v", err)
	}
	if !bytes.Equal(key.spki, spki) {
		return refuse(http.StatusUnprocessableEntity, "key_not_attested", "the key in the blob is not the key the sender's document attests")
	}
	if age := in.now.Sub(p.Born); age > MaxKeyAge-KeyAgeMargin || age < -verify.MaxAhead {
		return refuse(http.StatusUnprocessableEntity, "key_too_old", "the key was born %s before this enclave's time, outside 0 to %s", age.Round(time.Hour), MaxKeyAge-KeyAgeMargin)
	}
	if in.statement.Sequence < p.Floor {
		return refuse(http.StatusUnprocessableEntity, "pins_below_sender", "the statement's sequence %d is below the sender's floor %d", in.statement.Sequence, p.Floor)
	}
	chain, refused := parseChain([]byte(p.Chain))
	if refused != nil {
		return refused
	}
	if refused := d.checkChain(chain, key, in.now); refused != nil {
		return refused
	}
	from := seal.KeyIDOf(sender.PublicKey)
	origin := Origin{Born: p.Born.UTC(), From: &from, Floor: in.custody.floor}
	record, err := d.startCustody(ctx, key, origin, in.now)
	if err != nil {
		return refuse(http.StatusServiceUnavailable, "unattested", "this enclave could not attest the handed key: %v", err)
	}
	_, refused = d.update(func(c *custody) (*custody, *Refusal) {
		if _, was := c.state.(Serving); was {
			return nil, refuse(http.StatusConflict, "serving", "this door already serves a certificate")
		}
		if c.took {
			return nil, refusedHolding()
		}
		return &custody{key: key, origin: origin, record: record, records: p.Records, state: Unrecorded{handed: chain}, floor: c.floor, took: true}, nil
	})
	return refused
}

func readPayload(body []byte) (payload, *ecdsa.PrivateKey, *Refusal) {
	var p payload
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil || p.Type != payloadType {
		return payload{}, nil, refuse(http.StatusUnprocessableEntity, "payload_unreadable", "the blob holds no %s payload", payloadType)
	}
	parsed, _ := x509.ParsePKCS8PrivateKey(p.Key)
	private, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || private.Curve != elliptic.P256() {
		return payload{}, nil, refuse(http.StatusUnprocessableEntity, "payload_unreadable", "the key is not a PKCS#8 P-256 key")
	}
	return p, private, nil
}

func readJSON(w http.ResponseWriter, r *http.Request, into any) *Refusal {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxHandoff))
	if err != nil {
		return refuse(http.StatusRequestEntityTooLarge, "body_too_large", "the body is over %d bytes", maxHandoff)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return refuse(http.StatusBadRequest, "body_unreadable", "%v", err)
	}
	return nil
}

func refusedHolding() *Refusal {
	return refuse(http.StatusConflict, "holding", "this boot already took a handed key")
}
