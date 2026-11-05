package verify_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"morse/backend/internal/nitro/verify"
	"morse/backend/internal/seal"
)

var pcr = struct{ pcr0, pcr1, pcr2 string }{strings.Repeat("a0", 48), strings.Repeat("a1", 48), strings.Repeat("a2", 48)}

func pinOf(mutate func(*verify.Pin)) verify.Pin {
	p := verify.Pin{Image: verify.Built("c0ffee", "v1.2.3"), Environment: "dev", PCR0: pcr.pcr0, PCR1: pcr.pcr1, PCR2: pcr.pcr2, BuiltAt: "2026-10-01T00:00:00Z"}
	if mutate != nil {
		mutate(&p)
	}
	return p
}

type party struct {
	key  *ecdsa.PrivateKey
	name string
}

func newParty(name string, curve elliptic.Curve) party {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	return party{key: key, name: name}
}

type window struct{ notBefore, notAfter time.Time }

type issuer struct {
	party
	cert *x509.Certificate
}

func issue(subject party, by *issuer, serial int64, ca bool, w window) []byte {
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: subject.name},
		NotBefore:             w.notBefore,
		NotAfter:              w.notAfter,
		BasicConstraintsValid: true,
		IsCA:                  ca,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
	}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign
	}
	parent, signer := template, subject.key
	if by != nil {
		parent, signer = by.cert, by.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &subject.key.PublicKey, signer)
	if err != nil {
		panic(err)
	}
	return der
}

func parse(der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}

type documentOptions struct {
	timestamp   time.Time
	publicKey   []byte
	tls         []byte
	environment string
	userData    []byte
	pcrs        *struct{ pcr0, pcr1, pcr2 string }
	digest      string
	alg         int64
	signer      *party
	tagged      bool
	leaf        []byte
	bundle      [][]byte
}

type forge struct {
	root, intermediate, stranger      issuer
	leaf                              party
	rootDER, intermediateDER, leafDER []byte
	now                               time.Time
}

func newForge(t *testing.T) *forge {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	f := &forge{
		root:         issuer{party: newParty("aws.nitro-enclaves", elliptic.P384())},
		intermediate: issuer{party: newParty("zonal.aws.nitro-enclaves", elliptic.P384())},
		stranger:     issuer{party: newParty("stranger", elliptic.P384())},
		leaf:         newParty("i-0123.enc0123.aws", elliptic.P384()),
		now:          now,
	}
	w := window{now.Add(-30 * 24 * time.Hour), now.Add(30 * 24 * time.Hour)}
	f.rootDER = issue(f.root.party, nil, 1, true, w)
	f.root.cert = parse(f.rootDER)
	f.intermediateDER = issue(f.intermediate.party, &f.root, 2, true, w)
	f.intermediate.cert = parse(f.intermediateDER)
	f.stranger.cert = parse(issue(f.stranger.party, nil, 4, true, w))
	f.leafDER = issue(f.leaf, &f.intermediate, 3, false, w)
	return f
}

func (f *forge) document(o documentOptions) []byte {
	pcrs := pcr
	if o.pcrs != nil {
		pcrs = *o.pcrs
	}
	if o.environment == "" {
		o.environment = "dev"
	}
	if o.digest == "" {
		o.digest = "SHA384"
	}
	if o.alg == 0 {
		o.alg = -35
	}
	if o.userData == nil {
		o.userData = append([]byte(verify.UserDataPrefix+o.environment+"|"), o.publicKey...)
	}
	if o.leaf == nil {
		o.leaf = f.leafDER
	}
	if o.bundle == nil {
		o.bundle = [][]byte{f.rootDER, f.intermediateDER}
	}
	signer := f.leaf
	if o.signer != nil {
		signer = *o.signer
	}
	payload, err := cbor.Marshal(map[string]any{
		"module_id":   "i-0123-enc0123",
		"digest":      o.digest,
		"timestamp":   o.timestamp.UnixMilli(),
		"pcrs":        map[uint][]byte{0: unhex(pcrs.pcr0), 1: unhex(pcrs.pcr1), 2: unhex(pcrs.pcr2), 3: make([]byte, 48)},
		"certificate": o.leaf,
		"cabundle":    o.bundle,
		"public_key":  o.tls,
		"user_data":   o.userData,
		"nonce":       nil,
	})
	if err != nil {
		panic(err)
	}
	protected, _ := cbor.Marshal(map[int64]int64{1: o.alg})
	signed, _ := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	sum := sha512.Sum384(signed)
	r, s, err := ecdsa.Sign(rand.Reader, signer.key, sum[:])
	if err != nil {
		panic(err)
	}
	signature := append(r.FillBytes(make([]byte, 48)), s.FillBytes(make([]byte, 48))...)
	doc, _ := cbor.Marshal([]any{protected, map[any]any{}, payload, signature})
	if o.tagged {
		doc = append([]byte{0xd2}, doc...)
	}
	return doc
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func somePublicKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

func (f *forge) expect(now time.Time) verify.Expectation {
	return verify.Expectation{Environment: "dev", Pins: []verify.Pin{pinOf(nil)}, Root: f.root.cert, Now: now}
}

func refused(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("accepted; want a refusal mentioning %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refused with %q; want a refusal mentioning %q", err, want)
	}
}

func TestPinsTheAWSNitroRootByTheFingerprintAWSPublishes(t *testing.T) {
	sum := sha256.Sum256(verify.Root.Raw)
	if hex.EncodeToString(sum[:]) != verify.RootFingerprint || verify.Root.Subject.CommonName != "aws.nitro-enclaves" {
		t.Fatalf("root %s has fingerprint %x", verify.Root.Subject, sum)
	}
}

func TestAStandInAnnouncesItselfCarriesItsKeyAndRefusesEveryOtherDocument(t *testing.T) {
	publicKey, spki := bytes.Repeat([]byte{7}, 32), someSPKI(elliptic.P256())
	issuedAt := time.UnixMilli(time.Now().UnixMilli())
	document := verify.StandIn{Environment: "dev", PublicKey: publicKey, TLS: spki, IssuedAt: issuedAt}.Document()
	if !bytes.HasPrefix(document, []byte(`{"object":"proxy_attestation_stand_in","warning":"not an AWS Nitro attestation`)) {
		t.Errorf("stand-in %s does not announce itself first", document)
	}
	standIn, err := verify.ParseStandIn(document)
	if err != nil || standIn.Environment != "dev" || !bytes.Equal(standIn.PublicKey, publicKey) || !bytes.Equal(standIn.TLS, spki) || !standIn.IssuedAt.Equal(issuedAt) {
		t.Errorf("parsed %+v %v", standIn, err)
	}
	for name, bad := range map[string][]byte{
		"cose":        {0xd2, 0x84},
		"other json":  []byte(`{"object":"attestation"}`),
		"short key":   []byte(`{"object":"proxy_attestation_stand_in","environment":"dev","user_data":"bW9yc2UtcHJveHktaHBrZS12MXxkZXZ8YWJj"}`),
		"wrong env":   []byte(`{"object":"proxy_attestation_stand_in","environment":"prod","user_data":"` + "bW9yc2UtcHJveHktaHBrZS12MXxkZXZ8" + strings.Repeat("QUJD", 11) + `"}`),
		"no key":      []byte(`{"object":"proxy_attestation_stand_in","environment":"dev"}`),
		"empty":       nil,
		"not an obj":  []byte(`[]`),
		"bare string": []byte(`"x"`),
	} {
		if _, err := verify.ParseStandIn(bad); err == nil {
			t.Errorf("%s parsed as a stand-in", name)
		}
	}
}

func TestParsePinsRefusesAnAllZeroEntryAndMalformedPins(t *testing.T) {
	zero := strings.Repeat("0", 96)
	good := `[{"commit":"c0ffee","version":"v1","environment":"dev","pcr0":"` + pcr.pcr0 + `","pcr1":"` + pcr.pcr1 + `","pcr2":"` + pcr.pcr2 + `","built_at":"2026-10-01T00:00:00Z","revoked":false}]`
	pins, err := verify.ParsePins([]byte(good))
	if err != nil || len(pins) != 1 || pins[0].Image != verify.Built("c0ffee", "v1") {
		t.Fatalf("good pins: %v, %v", pins, err)
	}
	if pins, err := verify.ParsePins([]byte(strings.Replace(good, `"revoked"`, `"signed_by":"morse","revoked"`, 1))); err != nil || len(pins) != 1 {
		t.Fatalf("a field morse-pins adds: %v, %v", pins, err)
	}
	if pins, err := verify.ParsePins([]byte(strings.Replace(good, "}]", "},"+strings.Replace(good[1:], `"environment":"dev"`, `"environment":"prod"`, 1), 1))); err != nil || len(pins) != 2 {
		t.Fatalf("one image pinned for dev and prod: %v, %v", pins, err)
	}
	for name, bad := range map[string]string{
		"all-zero":       strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(good, pcr.pcr0, zero), pcr.pcr1, zero), pcr.pcr2, zero),
		"short pcr":      strings.ReplaceAll(good, pcr.pcr1, "abc"),
		"uppercase pcr":  strings.ReplaceAll(good, pcr.pcr2, strings.ToUpper(pcr.pcr2)),
		"no version":     strings.Replace(good, `"version":"v1"`, `"version":""`, 1),
		"bad built_at":   strings.Replace(good, "2026-10-01T00:00:00Z", "yesterday", 1),
		"duplicate pcrs": strings.Replace(good, "}]", "},"+strings.Replace(good[1:], `"version":"v1"`, `"version":"v1-rebuild"`, 1), 1),
	} {
		if _, err := verify.ParsePins([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParsePinsReadsMorsePinsPublicFormatAndRefusesAMixOfBoth(t *testing.T) {
	public := `[{"tag":"v2026.11.0","environment":"prod","pcr0":"` + pcr.pcr0 + `","pcr1":"` + pcr.pcr1 + `","pcr2":"` + pcr.pcr2 + `","built_at":"2026-11-02T00:30:17Z","revoked":false}]`
	pins, err := verify.ParsePins([]byte(public))
	if err != nil || len(pins) != 1 || pins[0].Image != verify.Tagged("v2026.11.0") {
		t.Fatalf("public pins: %v, %v", pins, err)
	}
	for name, bad := range map[string]string{
		"tag and version": strings.Replace(public, `"tag":"v2026.11.0"`, `"tag":"v2026.11.0","commit":"c0ffee","version":"v1"`, 1),
		"no tag":          strings.Replace(public, `"tag":"v2026.11.0",`, ``, 1),
		"no environment":  strings.Replace(public, `"environment":"prod",`, ``, 1),
	} {
		if _, err := verify.ParsePins([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAcceptsAForgedDocumentAndVouchesForTheKeyItsUserDataNames(t *testing.T) {
	f := newForge(t)
	publicKey := somePublicKey()
	for name, o := range map[string]documentOptions{
		"untagged": {timestamp: f.now, publicKey: publicKey},
		"tag 18":   {timestamp: f.now, publicKey: publicKey, tagged: true},
	} {
		key, err := verify.Document(f.document(o), f.expect(f.now.Add(time.Minute)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(key.PublicKey) != string(publicKey) || !key.IssuedAt.Equal(f.now) || key.Pin.Name() != "v1.2.3" {
			t.Fatalf("%s: key %x issued %v pin %+v", name, key.PublicKey, key.IssuedAt, key.Pin)
		}
	}
}

func TestRefusesADocumentThatIsNotACOSESign1(t *testing.T) {
	f := newForge(t)
	three, _ := cbor.Marshal([]any{[]byte{0xa1, 0x01, 0x38, 0x22}, map[any]any{}, []byte{}})
	for name, doc := range map[string][]byte{
		"three elements": three,
		"a map":          []byte{0xa0},
		"empty":          {},
		"detached":       f.detached(),
	} {
		_, err := verify.Document(doc, f.expect(f.now))
		refused(t, err, "not a COSE_Sign1")
		_ = name
	}
}

func (f *forge) detached() []byte {
	protected, _ := cbor.Marshal(map[int64]int64{1: -35})
	doc, _ := cbor.Marshal([]any{protected, map[any]any{}, nil, make([]byte, 96)})
	return doc
}

func TestRefusesAnAlgorithmOtherThanES384(t *testing.T) {
	f := newForge(t)
	_, err := verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), alg: -7}), f.expect(f.now))
	refused(t, err, "not signed with ES384")
}

func TestRefusesADigestOtherThanSHA384(t *testing.T) {
	f := newForge(t)
	_, err := verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), digest: "SHA256"}), f.expect(f.now))
	refused(t, err, "digest is not SHA384")
}

func TestRefusesASigningCertificateThatIsNotAP384Leaf(t *testing.T) {
	f := newForge(t)
	w := window{f.now.Add(-time.Hour), f.now.Add(time.Hour)}
	p256 := newParty("i-0123.enc0123.aws", elliptic.P256())
	p256Leaf := issue(p256, &f.intermediate, 9, false, w)
	_, err := verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), leaf: p256Leaf, signer: &p256}), f.expect(f.now))
	refused(t, err, "not a P-384 leaf")
	caLeaf := issue(f.leaf, &f.intermediate, 10, true, w)
	_, err = verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), leaf: caLeaf}), f.expect(f.now))
	refused(t, err, "not a P-384 leaf")
}

func TestRefusesAChainThatDoesNotReachThePinnedRoot(t *testing.T) {
	f := newForge(t)
	doc := f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey()})
	underAWS := f.expect(f.now)
	underAWS.Root = verify.Root
	_, err := verify.Document(doc, underAWS)
	refused(t, err, "is not signed by")

	other := newForge(t)
	_, err = verify.Document(doc, other.expect(f.now))
	refused(t, err, "is not signed by")

	w := window{f.now.Add(-time.Hour), f.now.Add(time.Hour)}
	strayIntermediate := issue(f.intermediate.party, &f.stranger, 11, true, w)
	_, err = verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), bundle: [][]byte{f.rootDER, strayIntermediate}}), f.expect(f.now))
	refused(t, err, "is not signed by")

	_, err = verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), bundle: [][]byte{}}), f.expect(f.now))
	refused(t, err, "cabundle is empty")

	_, err = verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), bundle: [][]byte{f.rootDER, []byte("junk")}}), f.expect(f.now))
	refused(t, err, "does not parse")

	if _, err := verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), bundle: [][]byte{[]byte("ignored: the pinned root stands in for cabundle[0]"), f.intermediateDER}}), f.expect(f.now)); err != nil {
		t.Fatalf("cabundle[0] is replaced by the pinned root, as check-enclave.py does, yet: %v", err)
	}
}

func TestRefusesACertificateNotValidAtTheDocumentsTimestamp(t *testing.T) {
	f := newForge(t)
	for name, at := range map[string]time.Time{
		"before the chain's notBefore": f.now.Add(-31 * 24 * time.Hour),
		"after the chain's notAfter":   f.now.Add(31 * 24 * time.Hour),
	} {
		_, err := verify.Document(f.document(documentOptions{timestamp: at, publicKey: somePublicKey()}), f.expect(at))
		refused(t, err, "was not valid when the document was issued")
		_ = name
	}
	w := window{f.now.Add(time.Hour), f.now.Add(2 * time.Hour)}
	futureLeaf := issue(f.leaf, &f.intermediate, 12, false, w)
	_, err := verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), leaf: futureLeaf}), f.expect(f.now))
	refused(t, err, "was not valid when the document was issued")
}

func TestRefusesASignatureThatDoesNotVerify(t *testing.T) {
	f := newForge(t)
	doc := f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey()})
	flipped := append([]byte{}, doc...)
	flipped[len(flipped)-1] ^= 0x01
	_, err := verify.Document(flipped, f.expect(f.now))
	refused(t, err, "signature does not verify")

	_, err = verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), signer: &f.stranger.party}), f.expect(f.now))
	refused(t, err, "signature does not verify")

	_, err = verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), signer: &f.intermediate.party}), f.expect(f.now))
	refused(t, err, "signature does not verify")

	payloadIndex := strings.Index(string(doc), "i-0123-enc0123")
	edited := append([]byte{}, doc...)
	edited[payloadIndex] = 'j'
	_, err = verify.Document(edited, f.expect(f.now))
	refused(t, err, "signature does not verify")
}

func TestRefusesADocumentOlderThan30MinutesOrMoreThan5MinutesAhead(t *testing.T) {
	f := newForge(t)
	doc := f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey()})
	for name, now := range map[string]time.Time{
		"30 minutes after": f.now.Add(30 * time.Minute),
		"5 minutes before": f.now.Add(-5 * time.Minute),
	} {
		if _, err := verify.Document(doc, f.expect(now)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	_, err := verify.Document(doc, f.expect(f.now.Add(31*time.Minute)))
	refused(t, err, "31 minutes old")
	_, err = verify.Document(doc, f.expect(f.now.Add(-6*time.Minute)))
	refused(t, err, "6 minutes ahead")
}

func TestRefusesAllZeroPCRs(t *testing.T) {
	f := newForge(t)
	zero := strings.Repeat("0", 96)
	expect := f.expect(f.now)
	expect.Pins = append(expect.Pins, pinOf(func(p *verify.Pin) { p.PCR0, p.PCR1, p.PCR2 = zero, zero, zero }))
	zeros := struct{ pcr0, pcr1, pcr2 string }{zero, zero, zero}
	_, err := verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), pcrs: &zeros}), expect)
	refused(t, err, "all-zero PCRs")
}

func TestRefusesPCRsNoPinNamesOrARevokedOrOtherEnvironmentPin(t *testing.T) {
	f := newForge(t)
	doc := f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey()})

	unpinned := f.expect(f.now)
	unpinned.Pins = []verify.Pin{pinOf(func(p *verify.Pin) { p.PCR2 = strings.Repeat("b2", 48) })}
	_, err := verify.Document(doc, unpinned)
	if !errors.Is(err, verify.ErrUnpinned) {
		t.Fatalf("unpinned: %v", err)
	}

	revoked := f.expect(f.now)
	revoked.Pins = []verify.Pin{pinOf(func(p *verify.Pin) { p.Revoked = true })}
	_, err = verify.Document(doc, revoked)
	refused(t, err, "is revoked")
	if errors.Is(err, verify.ErrUnpinned) {
		t.Fatal("a revoked pin reported as unpinned, which would invite a pins refetch")
	}

	revokedRebuild := f.expect(f.now)
	revokedRebuild.Pins = []verify.Pin{pinOf(nil), pinOf(func(p *verify.Pin) { p.Image, p.Revoked = verify.Built("c0ffee", "v1.2.3-rebuild"), true })}
	_, err = verify.Document(doc, revokedRebuild)
	refused(t, err, "v1.2.3-rebuild is revoked")

	otherEnvironment := f.expect(f.now)
	otherEnvironment.Pins = []verify.Pin{pinOf(func(p *verify.Pin) { p.Environment = "prod" })}
	_, err = verify.Document(doc, otherEnvironment)
	if !errors.Is(err, verify.ErrUnpinned) {
		t.Fatalf("a prod pin vouched for a dev document: %v", err)
	}

	for i, pcrs := range []struct{ pcr0, pcr1, pcr2 string }{
		{strings.Repeat("ff", 48), pcr.pcr1, pcr.pcr2},
		{pcr.pcr0, strings.Repeat("ff", 48), pcr.pcr2},
		{pcr.pcr0, pcr.pcr1, strings.Repeat("ff", 48)},
	} {
		_, err := verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: somePublicKey(), pcrs: &pcrs}), f.expect(f.now))
		if !errors.Is(err, verify.ErrUnpinned) {
			t.Fatalf("PCR%d changed: %v", i, err)
		}
	}
}

func TestRefusesUserDataThatDoesNotNameAKeyOfTheEnvironment(t *testing.T) {
	f := newForge(t)
	publicKey := somePublicKey()
	for name, userData := range map[string][]byte{
		"prod key":       append([]byte(verify.UserDataPrefix+"prod|"), publicKey...),
		"short key":      append([]byte(verify.UserDataPrefix+"dev|"), publicKey[:31]...),
		"long key":       append(append([]byte(verify.UserDataPrefix+"dev|"), publicKey...), 0),
		"another prefix": append([]byte("morse-proxy-hpke-v2|dev|"), publicKey...),
		"empty":          {},
	} {
		_, err := verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: publicKey, userData: userData}), f.expect(f.now))
		refused(t, err, "user_data does not name a dev key")
		_ = name
	}
	expectProd := f.expect(f.now)
	expectProd.Environment = "prod"
	expectProd.Pins = []verify.Pin{pinOf(func(p *verify.Pin) { p.Environment = "prod" })}
	_, err := verify.Document(f.document(documentOptions{timestamp: f.now, publicKey: publicKey}), expectProd)
	refused(t, err, "user_data does not name a prod key")
}

func TestVerifiesARealNitroDocumentAgainstTheAWSRoot(t *testing.T) {
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
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key.PublicKey) != "48895025406095a204ddcf391e72f6a517af868796cd3167d9ddceef13c9ae5e" {
		t.Fatalf("public key %x", key.PublicKey)
	}
	if id, _ := seal.KeyIDOf(key.PublicKey).MarshalText(); string(id) != "d074a9212978f332" {
		t.Fatalf("key id %s", id)
	}
	if !key.IssuedAt.Equal(issuedAt) {
		t.Fatalf("issued at %v", key.IssuedAt)
	}
	expect.Now = time.Now()
	_, err = verify.Document(document, expect)
	refused(t, err, "minutes old")
	expect.Now = issuedAt.Add(time.Minute)
	expect.Environment = "prod"
	expect.Pins = []verify.Pin{func() verify.Pin { p := pin; p.Environment = "prod"; return p }()}
	_, err = verify.Document(document, expect)
	refused(t, err, "user_data does not name a prod key")
}
