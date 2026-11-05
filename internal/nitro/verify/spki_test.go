package verify_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/nitro/verify"
)

func someSPKI(curve elliptic.Curve) []byte {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	return spki
}

func TestAttestedSPKIReturnsTheP256KeyTheEnclaveBindsBesideTheVerifiedKey(t *testing.T) {
	f := newForge(t)
	hpke, spki := somePublicKey(), someSPKI(elliptic.P256())
	got, key, err := verify.AttestedSPKI(f.document(documentOptions{timestamp: f.now, publicKey: hpke, tls: spki}), f.expect(f.now))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, spki) || !bytes.Equal(key.TLS, spki) {
		t.Errorf("spki %x, key.TLS %x, want %x", got, key.TLS, spki)
	}
	if !bytes.Equal(key.PublicKey, hpke) || !key.IssuedAt.Equal(f.now) || key.Pin.Name() != "v1.2.3" {
		t.Errorf("key %+v, want the HPKE key, timestamp and pin Document returns", key)
	}
}

func TestAttestedSPKIRefusesADocumentWhosePublicKeyIsMissingJunkOrNotP256(t *testing.T) {
	f := newForge(t)
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edSPKI, err := x509.MarshalPKIXPublicKey(edPublic)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		tls  []byte
		want string
	}{
		"none":            {nil, "SubjectPublicKeyInfo"},
		"empty":           {[]byte{}, "SubjectPublicKeyInfo"},
		"junk":            {[]byte{1, 2, 3}, "SubjectPublicKeyInfo"},
		"the HPKE key":    {somePublicKey(), "SubjectPublicKeyInfo"},
		"a truncated key": {someSPKI(elliptic.P256())[:60], "SubjectPublicKeyInfo"},
		"P-384":           {someSPKI(elliptic.P384()), "P-256"},
		"Ed25519":         {edSPKI, "P-256"},
	} {
		spki, key, err := verify.AttestedSPKI(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), tls: c.tls}), f.expect(f.now))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a refusal mentioning %q", name, err, c.want)
		}
		if spki != nil || key.PublicKey != nil {
			t.Errorf("%s: returned %x and %+v beside the refusal", name, spki, key)
		}
	}
}

func TestAttestedSPKIRefusesWhateverDocumentRefusesBeforeItReadsTheKey(t *testing.T) {
	f := newForge(t)
	spki := someSPKI(elliptic.P256())
	_, _, err := verify.AttestedSPKI(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), tls: spki, environment: "prod"}), f.expect(f.now))
	refused(t, err, "user_data does not name a dev key")
	other := pcr
	other.pcr0 = strings.Repeat("b0", 48)
	_, _, err = verify.AttestedSPKI(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), tls: spki, pcrs: &other}), f.expect(f.now))
	if !errors.Is(err, verify.ErrUnpinned) {
		t.Errorf("unpinned PCRs: %v, want ErrUnpinned", err)
	}
	_, _, err = verify.AttestedSPKI(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), tls: spki}), f.expect(f.now.Add(time.Hour)))
	refused(t, err, "minutes old")
}

func TestDocumentCarriesPublicKeyAsItIsAndAcceptsADocumentWithAnyOrNone(t *testing.T) {
	f := newForge(t)
	for name, tls := range map[string][]byte{"none": nil, "junk": {1, 2, 3}, "P-256": someSPKI(elliptic.P256())} {
		key, err := verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), tls: tls}), f.expect(f.now))
		if err != nil {
			t.Errorf("%s: a user_data reader refused the document: %v", name, err)
		}
		if !bytes.Equal(key.TLS, tls) {
			t.Errorf("%s: key.TLS %x, want %x", name, key.TLS, tls)
		}
	}
}

func TestTheRealNitroDocumentBindsNoTLSKeySoOnlyAttestedSPKIRefusesIt(t *testing.T) {
	encoded, err := os.ReadFile("testdata/nitro_document.b64")
	if err != nil {
		t.Fatal(err)
	}
	document, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.UnixMilli(1792280904626)
	pin := verify.Pin{Image: verify.Built("c0ffee", "v1.2.3"), Environment: "dev", BuiltAt: "2026-10-01T00:00:00Z",
		PCR0: "1dab5ad4c661f95a9e7e3f57bcd83efd9fced7f749ac21ea85a1853131bb5e43b41eb58615efef998d478ce485fcff53",
		PCR1: "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03",
		PCR2: "f9d2c68436810c46556535a583870e2913ec1f05ecca361b4e78eaa00d0b365dee6570e7699c4f34165fbf635bf35c6a"}
	expect := verify.Expectation{Environment: "dev", Pins: []verify.Pin{pin}, Root: verify.Root, Now: issuedAt.Add(time.Minute)}
	key, err := verify.Document(document, expect)
	if err != nil || key.TLS != nil {
		t.Fatalf("Document: key.TLS %x, %v; want nil and no error", key.TLS, err)
	}
	_, _, err = verify.AttestedSPKI(document, expect)
	refused(t, err, "SubjectPublicKeyInfo")
}
