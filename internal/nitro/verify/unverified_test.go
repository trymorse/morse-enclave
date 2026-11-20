package verify_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/nitro/verify"
)

func TestKeyUnverifiedReadsTheKeyANitroOrStandInDocumentNamesInAnyEnvironmentAndNothingElse(t *testing.T) {
	encoded, err := os.ReadFile("testdata/nitro_document.b64")
	if err != nil {
		t.Fatal(err)
	}
	real, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if key, err := verify.KeyUnverified(real); err != nil || hex.EncodeToString(key) != "48895025406095a204ddcf391e72f6a517af868796cd3167d9ddceef13c9ae5e" {
		t.Errorf("the real Nitro document: %x %v", key, err)
	}
	f := newForge(t)
	publicKey := somePublicKey()
	for name, document := range map[string][]byte{
		"a stale forged dev document": f.document(documentOptions{timestamp: f.now.Add(-time.Hour), publicKey: publicKey}),
		"a forged prod document":      f.document(documentOptions{timestamp: f.now, publicKey: publicKey, environment: "prod"}),
		"a prod stand-in":             verify.StandIn{Environment: "prod", PublicKey: publicKey}.Document(),
	} {
		if key, err := verify.KeyUnverified(document); err != nil || !bytes.Equal(key, publicKey) {
			t.Errorf("%s: %x %v, want %x", name, key, err, publicKey)
		}
	}
	for name, document := range map[string][]byte{
		"no user_data":   f.document(documentOptions{timestamp: f.now, publicKey: publicKey, noUserData: true}),
		"another prefix": f.document(documentOptions{timestamp: f.now, userData: append([]byte("morse-proxy-hpke-v2|dev|"), publicKey...)}),
		"no environment": f.document(documentOptions{timestamp: f.now, userData: append([]byte(verify.UserDataPrefix), publicKey...)}),
		"a short key":    f.document(documentOptions{timestamp: f.now, userData: append([]byte(verify.UserDataPrefix+"dev|"), publicKey[:31]...)}),
		"other json":     []byte(`{"object":"attestation","user_data":"bW9yc2UtcHJveHktaHBrZS12MXxkZXZ8"}`),
		"cbor junk":      {0xd2, 0x84},
		"empty":          nil,
	} {
		if key, err := verify.KeyUnverified(document); err == nil {
			t.Errorf("%s: read key %x", name, key)
		}
	}
}
