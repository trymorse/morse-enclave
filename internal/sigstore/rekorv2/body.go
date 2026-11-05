package rekorv2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"morse/backend/internal/strictjson"
)

// HashedRekord is the body of a hashedrekord v0.0.2 entry whose verifier is
// an X.509 certificate with a P-256 key.
type HashedRekord struct {
	Digest      [32]byte
	Signature   []byte // DER ECDSA
	Certificate []byte // DER, as logged
}

// encoding/json matches struct fields case-insensitively, so the body is
// never decoded into a struct.
func parseHashedRekord(body []byte) (HashedRekord, error) {
	if err := strictjson.UniqueKeys(body); err != nil {
		return HashedRekord{}, err
	}
	top, err := exactFields(body, "apiVersion", "kind", "spec")
	if err != nil {
		return HashedRekord{}, err
	}
	if err := wantString(top["apiVersion"], "0.0.2"); err != nil {
		return HashedRekord{}, fmt.Errorf("apiVersion: %v", err)
	}
	if err := wantString(top["kind"], "hashedrekord"); err != nil {
		return HashedRekord{}, fmt.Errorf("kind: %v", err)
	}
	spec, err := exactFields(top["spec"], "hashedRekordV002")
	if err != nil {
		return HashedRekord{}, err
	}
	v002, err := exactFields(spec["hashedRekordV002"], "data", "signature")
	if err != nil {
		return HashedRekord{}, err
	}
	data, err := exactFields(v002["data"], "algorithm", "digest")
	if err != nil {
		return HashedRekord{}, err
	}
	if err := wantString(data["algorithm"], "SHA2_256"); err != nil {
		return HashedRekord{}, fmt.Errorf("algorithm: %v", err)
	}
	digest, err := base64Field(data["digest"])
	if err != nil || len(digest) != 32 {
		return HashedRekord{}, fmt.Errorf("the digest is not 32 bytes of base64")
	}
	sig, err := exactFields(v002["signature"], "content", "verifier")
	if err != nil {
		return HashedRekord{}, err
	}
	content, err := base64Field(sig["content"])
	if err != nil || len(content) == 0 {
		return HashedRekord{}, fmt.Errorf("the signature is not base64")
	}
	verifier, err := exactFields(sig["verifier"], "keyDetails", "x509Certificate")
	if err != nil {
		return HashedRekord{}, err
	}
	if err := wantString(verifier["keyDetails"], "PKIX_ECDSA_P256_SHA_256"); err != nil {
		return HashedRekord{}, fmt.Errorf("keyDetails: %v", err)
	}
	cert, err := exactFields(verifier["x509Certificate"], "rawBytes")
	if err != nil {
		return HashedRekord{}, err
	}
	der, err := base64Field(cert["rawBytes"])
	if err != nil || len(der) == 0 {
		return HashedRekord{}, fmt.Errorf("the certificate is not base64")
	}
	return HashedRekord{Digest: [32]byte(digest), Signature: content, Certificate: der}, nil
}

func exactFields(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	fields, err := strictjson.Object(bytes.NewReader(raw), keys...)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if v, ok := fields[k]; !ok || string(v) == "null" {
			return nil, fmt.Errorf("no %s", k)
		}
	}
	return fields, nil
}

func wantString(raw json.RawMessage, want string) error {
	var got string
	if err := json.Unmarshal(raw, &got); err != nil || got != want {
		return fmt.Errorf("is %s, not %q", raw, want)
	}
	return nil
}

func base64Field(raw json.RawMessage) ([]byte, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}
