package aci_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/aci"
	"morse/backend/internal/jcs"
)

const (
	liveSigningKey = "110f3824daeeef29dbeba9677a5794ffed257b1082d9fd4599b3c0819953aa0a"
	liveKeyID      = "dstack-kms-receipt-ed25519-v1"
	liveE2EEKey    = "408e82d159832cfae15007781bcade0badee7d50e9f76d50eaa1777464006537"
	liveE2EEKeyID  = "dstack-kms-e2ee-x25519-v1"
	liveE2EEAlgo   = "x25519-aes-256-gcm-hkdf-sha256"
	liveDigest     = "sha256:ef8a03c0c5e349310394c0d5865f766f8a1258f1acdb5fcb6ed2ebcd757e5f5a"
	liveTLSDomain  = "inference.phala.com"
	liveTLSSPKI    = "8e89a8a01e12098065037be187dcd2f03071dc1e7c9bb8527160f4c56ebc728f"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "attestation.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func liveKeyset(t *testing.T) aci.Keyset {
	t.Helper()
	ks, err := aci.ParseKeyset(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func TestParseKeysetBindsTheSigningKeyToTheReportsDigest(t *testing.T) {
	ks := liveKeyset(t)
	if ks.Digest.String() != liveDigest || ks.WorkloadID != "" || len(ks.SigningKeys) != 1 {
		t.Fatalf("keyset %+v", ks)
	}
	if k := ks.SigningKeys[0]; k.ID != liveKeyID || k.Algo != aci.AlgoEd25519 || hex.EncodeToString(k.Public) != liveSigningKey {
		t.Errorf("signing key %+v", k)
	}
	forged := bytes.Replace(fixture(t), []byte(liveSigningKey), []byte(strings.Repeat("ab", 32)), 1)
	if _, err := aci.ParseKeyset(forged); !errors.Is(err, aci.ErrReportDigest) {
		t.Errorf("a report whose keyset does not hash to its digest parsed: %v", err)
	}
	if _, err := aci.ParseKeyset([]byte(`{"workload_keyset_digest":"sha256:00"}`)); err == nil {
		t.Error("a report without a keyset parsed")
	}
}

func TestParseKeysetReadsNotAfterAndTheE2EEKeysFromTheHashedKeyset(t *testing.T) {
	ks := liveKeyset(t)
	if want := time.Date(2026, 10, 17, 15, 25, 55, 0, time.UTC); !ks.NotAfter.Equal(want) {
		t.Errorf("not_after %v, want %v", ks.NotAfter, want)
	}
	var x25519 []aci.Key
	for _, k := range ks.E2EEKeys {
		if k.Algo == liveE2EEAlgo {
			x25519 = append(x25519, k)
		}
	}
	if len(ks.E2EEKeys) != 2 || len(x25519) != 1 || x25519[0].ID != liveE2EEKeyID || hex.EncodeToString(x25519[0].Public) != liveE2EEKey {
		t.Errorf("e2ee keys %+v", ks.E2EEKeys)
	}
}

func TestParseKeysetReadsTheTLSKeysFromTheHashedKeyset(t *testing.T) {
	ks := liveKeyset(t)
	byDomain := map[string]string{}
	for _, k := range ks.TLSKeys {
		byDomain[k.Domain] = hex.EncodeToString(k.SPKI[:])
	}
	if len(ks.TLSKeys) != 4 || byDomain[liveTLSDomain] != liveTLSSPKI {
		t.Errorf("tls keys %+v", ks.TLSKeys)
	}
	forged := bytes.Replace(fixture(t), []byte(liveTLSSPKI), []byte(strings.Repeat("ab", 32)), 1)
	if _, err := aci.ParseKeyset(forged); !errors.Is(err, aci.ErrReportDigest) {
		t.Errorf("a report whose tls key was swapped parsed: %v", err)
	}
	for _, bad := range []map[string]any{
		{"domain": liveTLSDomain, "spki_sha256": liveTLSSPKI[:62]},
		{"domain": liveTLSDomain, "spki_sha256": liveTLSSPKI + "00"},
		{"domain": liveTLSDomain, "spki_sha256": strings.Repeat("zz", 32)},
		{"domain": "", "spki_sha256": liveTLSSPKI},
	} {
		report := reportWithKeyset(t, map[string]any{"not_after": json.Number("1"), "tls_public_keys": []any{bad}})
		if _, err := aci.ParseKeyset(report); err == nil || !strings.HasPrefix(err.Error(), "aci: tls key") {
			t.Errorf("tls key %v parsed: %v", bad, err)
		}
	}
}

func reportWithKeyset(t *testing.T, keyset map[string]any) []byte {
	t.Helper()
	canonical, err := jcs.Marshal(keyset)
	if err != nil {
		t.Fatal(err)
	}
	report, err := json.Marshal(map[string]any{
		"workload_keyset_digest": aci.Sum(canonical).String(),
		"attestation":            map[string]any{"workload_keyset": keyset},
	})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestParseKeysetRefusesAKeysetWithoutNotAfter(t *testing.T) {
	keyset := `{"receipt_signing_keys":[]}`
	canonical, err := jcs.Canonicalize([]byte(keyset))
	if err != nil {
		t.Fatal(err)
	}
	report := `{"workload_keyset_digest":"` + aci.Sum(canonical).String() + `","attestation":{"workload_keyset":` + keyset + `}}`
	if _, err := aci.ParseKeyset([]byte(report)); !errors.Is(err, aci.ErrNoNotAfter) {
		t.Errorf("a keyset without not_after parsed: %v", err)
	}
}

func TestHashRoundTripsThroughItsTextForm(t *testing.T) {
	h := aci.Sum([]byte("x"))
	parsed, err := aci.ParseHash(h.String())
	if err != nil || parsed != h {
		t.Errorf("ParseHash(%s) = %v, %v", h, parsed, err)
	}
	for _, bad := range []string{"", "sha256:", "sha256:zz", "sha1:" + strings.Repeat("00", 20), strings.Repeat("00", 32)} {
		if _, err := aci.ParseHash(bad); err == nil {
			t.Errorf("ParseHash(%q) accepted", bad)
		}
	}
}
