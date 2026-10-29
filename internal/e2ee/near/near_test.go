package near

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"

	"filippo.io/edwards25519"

	"morse/backend/internal/e2ee"
)

// RFC 8032 test 1. NEAR's inference-proxy pins the same seed and the X25519
// keys libsodium derives from it (src/encryption.rs test_nacl_libsodium_cross_compat).
const (
	vectorSeed       = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	vectorPublicKey  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	vectorX25519Pub  = "d85e07ec22b0ad881537c2f44d662d1a143cf830c57aca4305d85c7a90f6b62e"
	otherPublicKey   = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	vectorPlaintext  = "near e2ee v2 known answer"
	notOnTheCurveKey = "0200000000000000000000000000000000000000000000000000000000000000"
)

const vectorSealed = "76c49873392c7f0bd4cbc02f585cab0b05656046c20686c517db3806c199c440" +
	"000102030405060708090a0b0c0d0e0f1011121314151617" +
	"a59e295dd48c2b3eb690b2a8a5e5f1f74c6dfada995e09288e7353689c9dfb0bf0533a109a9ec2decd"

func vectorKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(vectorSeed)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestOpenReadsAValueSealedByLibsodium(t *testing.T) {
	got, err := Open(vectorKey(t), vectorSealed)
	if err != nil || string(got) != vectorPlaintext {
		t.Fatalf("Open = %q, %v; want %q", got, err, vectorPlaintext)
	}
}

func TestOpenRefusesATamperedOrTruncatedValue(t *testing.T) {
	flipped := []byte(vectorSealed)
	flipped[len(flipped)-1] ^= 1
	for name, sealed := range map[string]string{
		"tag flipped":          string(flipped),
		"one byte short":       vectorSealed[:MinCiphertextHex-2],
		"not hex":              strings.Repeat("zz", MinCiphertextHex/2),
		"nonce from elsewhere": vectorSealed[:64] + strings.Repeat("ff", 24) + vectorSealed[112:],
	} {
		if got, err := Open(vectorKey(t), sealed); err == nil {
			t.Errorf("%s: Open = %q, want an error", name, got)
		}
	}
}

func TestTheKeyConversionMatchesLibsodium(t *testing.T) {
	key := vectorKey(t)
	if got := hex.EncodeToString(key.Public().(ed25519.PublicKey)); got != vectorPublicKey {
		t.Fatalf("public key %s", got)
	}
	point, err := new(edwards25519.Point).SetBytes(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(point.BytesMontgomery()); got != vectorX25519Pub {
		t.Errorf("public key on X25519 %s, want %s", got, vectorX25519Pub)
	}
	digest := sha512.Sum512(key.Seed())
	private, err := ecdh.X25519().NewPrivateKey(digest[:32])
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(private.PublicKey().Bytes()); got != vectorX25519Pub {
		t.Errorf("private key on X25519 gives public %s, want %s", got, vectorX25519Pub)
	}
}

func TestSealLaysOutEphemeralKeyNonceAndCiphertextInLowercaseHex(t *testing.T) {
	key := vectorKey(t)
	plaintext := "hello"
	first, err := Seal(key.Public().(ed25519.PublicKey), []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	if want := 2 * (32 + 24 + len(plaintext) + 16); len(first) != want {
		t.Errorf("sealed length %d, want %d", len(first), want)
	}
	if first != strings.ToLower(first) {
		t.Errorf("sealed %s is not lowercase", first)
	}
	got, err := Open(key, first)
	if err != nil || string(got) != plaintext {
		t.Fatalf("Open = %q, %v", got, err)
	}
	second, err := Seal(key.Public().(ed25519.PublicKey), []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	if first[:64] == second[:64] || first[64:112] == second[64:112] {
		t.Errorf("two seals share an ephemeral key or nonce:\n%s\n%s", first, second)
	}
}

func TestSealRefusesAKeyOffTheCurve(t *testing.T) {
	key, _ := hex.DecodeString(notOnTheCurveKey)
	if got, err := Seal(key, []byte("x")); err == nil {
		t.Errorf("Seal = %q, want an error", got)
	}
}

func TestIsCiphertextAdmitsOnlyLowercaseHexAtLeastTheFloor(t *testing.T) {
	floor := strings.Repeat("ab", MinCiphertextHex/2)
	for raw, want := range map[string]bool{
		`"` + vectorSealed + `"`:           true,
		`"` + floor + `"`:                  true,
		`"` + floor[2:] + `"`:              false,
		`"` + floor + `a"`:                 false,
		`"` + strings.ToUpper(floor) + `"`: false,
		`"` + floor[:len(floor)-1] + `g"`:  false,
		floor:                              false,
		`""`:                               false,
		`["` + floor + `"]`:                false,
	} {
		if got := IsCiphertext([]byte(raw)); got != want {
			t.Errorf("IsCiphertext(%.20s...) = %t, want %t", raw, got, want)
		}
	}
	if MinCiphertextHex != 144 {
		t.Errorf("MinCiphertextHex = %d, want 144", MinCiphertextHex)
	}
}

func headers(pairs ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	return func(name string) string { return m[name] }
}

func validHeaders() []string {
	return []string{HeaderSigningAlgo, "ed25519", HeaderClientKey, otherPublicKey, HeaderModelKey, vectorPublicKey, HeaderVersion, "2", HeaderAllFields, "true"}
}

func TestParseHeadersReadsNEARsEd25519V2Set(t *testing.T) {
	params, sealed, err := ParseHeaders(headers(append(validHeaders(), HeaderSigningAlgo, "Ed25519", HeaderAllFields, "TRUE")...))
	if !sealed || err != nil {
		t.Fatalf("sealed %t err %v", sealed, err)
	}
	if hex.EncodeToString(params.Client) != otherPublicKey || hex.EncodeToString(params.Model) != vectorPublicKey {
		t.Errorf("client %x model %x", params.Client, params.Model)
	}
}

func TestParseHeadersRefusesEveryOtherNEARSet(t *testing.T) {
	cases := []struct {
		name  string
		pairs []string
		want  *e2ee.Error
	}{
		{"ecdsa", append(validHeaders(), HeaderSigningAlgo, "ecdsa", HeaderClientKey, strings.Repeat("ab", 64)), ErrInvalidAlgo},
		{"unknown algo", append(validHeaders(), HeaderSigningAlgo, "rsa"), ErrInvalidAlgo},
		{"version 1", append(validHeaders(), HeaderVersion, "1"), ErrInvalidVersion},
		{"no version, which NEAR reads as 1", append(validHeaders(), HeaderVersion, ""), ErrInvalidVersion},
		{"all fields false", append(validHeaders(), HeaderAllFields, "false"), ErrPartialFields},
		{"no all fields", append(validHeaders(), HeaderAllFields, ""), ErrPartialFields},
		{"no model key", append(validHeaders(), HeaderModelKey, ""), ErrHeaderMissing},
		{"no client key", append(validHeaders(), HeaderClientKey, ""), ErrHeaderMissing},
		{"client key 31 bytes", append(validHeaders(), HeaderClientKey, otherPublicKey[:62]), ErrInvalidKey},
		{"client key not hex", append(validHeaders(), HeaderClientKey, strings.Repeat("zz", 32)), ErrInvalidKey},
		{"model key off the curve", append(validHeaders(), HeaderModelKey, notOnTheCurveKey), ErrInvalidKey},
	}
	for _, tc := range cases {
		params, sealed, err := ParseHeaders(headers(tc.pairs...))
		var got *e2ee.Error
		if !sealed || !errors.As(err, &got) || got != tc.want || params.Client != nil || params.Model != nil {
			t.Errorf("%s: sealed %t params %v err %v, want %v", tc.name, sealed, params, err, tc.want)
		}
	}
}

func TestParseHeadersLeavesTheSigningAlgoWithoutNEARsOwnHeadersToOtherProtocols(t *testing.T) {
	for name, pairs := range map[string][]string{
		"none":                       {"Content-Type", "application/json"},
		"signing algo alone":         {HeaderSigningAlgo, "ecdsa"},
		"signing algo and both keys": {HeaderSigningAlgo, "ed25519", HeaderClientKey, otherPublicKey, HeaderModelKey, vectorPublicKey},
		"NEAR set without the algo":  validHeaders()[2:],
	} {
		if _, sealed, err := ParseHeaders(headers(pairs...)); sealed || err != nil {
			t.Errorf("%s: sealed %t err %v", name, sealed, err)
		}
	}
}

func TestRequestHeadersAreExactlyTheHeadersForwardSends(t *testing.T) {
	params, _, err := ParseHeaders(headers(validHeaders()...))
	if err != nil {
		t.Fatal(err)
	}
	var forwarded []string
	params.Forward(func(name, _ string) { forwarded = append(forwarded, name) })
	listed := RequestHeaders[:]
	if !slices.Equal(slices.Sorted(slices.Values(forwarded)), slices.Sorted(slices.Values(listed))) {
		t.Errorf("Forward sends %v but RequestHeaders, the list CORS allows a browser to send, is %v", forwarded, listed)
	}
}
