package pinsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"math/bits"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/jcs"
)

var update = flag.Bool("update", false, "rewrite testdata/forged from a fresh forgery under a fresh test CA and log key")

// pinsIdentity is what the enclave will pin for Watermark-Labs/pins sign.yml.
var pinsIdentity = Identity{
	Issuer:              "https://token.actions.githubusercontent.com",
	BuildSignerURI:      "https://github.com/Watermark-Labs/pins/.github/workflows/sign.yml@refs/heads/main",
	BuildConfigURI:      "https://github.com/Watermark-Labs/pins/.github/workflows/sign.yml@refs/heads/main",
	SourceRepositoryURI: "https://github.com/Watermark-Labs/pins",
	SourceRepositoryID:  "1405118053",
	SourceOwnerID:       "334112171",
	Ref:                 "refs/heads/main",
	Triggers:            []string{"push", "schedule"},
}

var integratedAt = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

const runInvocation = "https://github.com/Watermark-Labs/pins/actions/runs/40609597243/attempts/1"

// forge is a test Fulcio CA (root and intermediate) and a test Rekor v1 key,
// with the trusted root JSON that names them.
type forge struct {
	rekorKey  *ecdsa.PrivateKey
	logID     [32]byte
	root      *x509.Certificate
	inter     *x509.Certificate
	interKey  *ecdsa.PrivateKey
	trustRoot []byte
}

func newForge(t *testing.T) *forge {
	t.Helper()
	f := &forge{rekorKey: newKey(t)}
	rekorDER, err := x509.MarshalPKIXPublicKey(&f.rekorKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f.logID = sha256.Sum256(rekorDER)
	ca := func(name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, key *ecdsa.PrivateKey, pathLen int) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber:          serial(t),
			Subject:               pkix.Name{Organization: []string{"pinsig test"}, CommonName: name},
			NotBefore:             time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:              time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLen:            pathLen,
			MaxPathLenZero:        pathLen == 0,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		return issue(t, tmpl, parent, &key.PublicKey, parentKey)
	}
	rootKey := newKey(t)
	f.root = ca("root", nil, nil, rootKey, 1)
	f.interKey = newKey(t)
	f.inter = ca("intermediate", f.root, rootKey, f.interKey, 0)
	f.trustRoot, err = json.MarshalIndent(map[string]any{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": []any{map[string]any{
			"baseUrl":       "https://rekor.test",
			"hashAlgorithm": "SHA2_256",
			"publicKey": map[string]any{
				"rawBytes":   rekorDER,
				"keyDetails": "PKIX_ECDSA_P256_SHA_256",
				"validFor":   map[string]any{"start": "2025-01-01T00:00:00Z"},
			},
			"logId": map[string]any{"keyId": f.logID[:]},
		}},
		"certificateAuthorities": []any{map[string]any{
			"subject":   map[string]any{"organization": "pinsig test", "commonName": "fulcio.test"},
			"uri":       "https://fulcio.test",
			"certChain": map[string]any{"certificates": []any{map[string]any{"rawBytes": f.inter.Raw}, map[string]any{"rawBytes": f.root.Raw}}},
			"validFor":  map[string]any{"start": "2025-01-01T00:00:00Z"},
		}},
		"ctlogs":               []any{},
		"timestampAuthorities": []any{},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func issue(t *testing.T, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// forgery is one signing run with every input the cases vary. build turns
// it into a bundle the way cosign sign-blob and Rekor v1 would, except where
// a case says otherwise.
type forgery struct {
	blob              []byte
	ext               map[int]string
	san               string
	notBefore         time.Time
	notAfter          time.Time
	criticalExtension bool
	signOver          []byte
	bodyDigest        *[32]byte
	bodySignature     []byte
	bodyCert          []byte
	logID             [32]byte
	treeSize, index   uint64
	checkpointTree    *struct {
		size uint64
		root [32]byte
	}
	flipProof, flipSET bool
	leafEdit           func(*x509.Certificate)
	edit               func(bundle map[string]any)
}

func newForgery(f *forge, blob []byte, sourceDigest string) *forgery {
	return &forgery{
		blob: blob,
		ext: map[int]string{
			8:  pinsIdentity.Issuer,
			9:  pinsIdentity.BuildSignerURI,
			11: githubHostedRunner,
			12: pinsIdentity.SourceRepositoryURI,
			13: sourceDigest,
			14: pinsIdentity.Ref,
			15: pinsIdentity.SourceRepositoryID,
			17: pinsIdentity.SourceOwnerID,
			18: pinsIdentity.BuildConfigURI,
			19: sourceDigest,
			20: "push",
			21: runInvocation,
		},
		san:       pinsIdentity.BuildSignerURI,
		notBefore: integratedAt.Add(-time.Minute),
		notAfter:  integratedAt.Add(9 * time.Minute),
		signOver:  blob,
		logID:     f.logID,
		treeSize:  7,
		index:     4,
	}
}

func (g *forgery) leaf(t *testing.T, f *forge, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: serial(t),
		NotBefore:    g.notBefore,
		NotAfter:     g.notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	if g.san != "" {
		tmpl.URIs = []*url.URL{mustURL(t, g.san)}
	}
	for arc, value := range g.ext {
		der, err := asn1.MarshalWithParams(value, "utf8")
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, arc}, Value: der})
	}
	if g.criticalExtension {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 99}, Critical: true, Value: []byte{5, 0}})
	}
	if g.leafEdit != nil {
		g.leafEdit(tmpl)
	}
	return issue(t, tmpl, f.inter, &key.PublicKey, f.interKey)
}

func (g *forgery) build(t *testing.T, f *forge) []byte {
	t.Helper()
	key := newKey(t)
	leaf := g.leaf(t, f, key)
	digest := sha256.Sum256(g.blob)
	signed := sha256.Sum256(g.signOver)
	sig, err := ecdsa.SignASN1(rand.Reader, key, signed[:])
	if err != nil {
		t.Fatal(err)
	}

	bodyDigest, bodySig, bodyCert := digest, sig, leaf.Raw
	if g.bodyDigest != nil {
		bodyDigest = *g.bodyDigest
	}
	if g.bodySignature != nil {
		bodySig = g.bodySignature
	}
	if g.bodyCert != nil {
		bodyCert = g.bodyCert
	}
	body, err := jcs.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "hashedrekord",
		"spec": map[string]any{
			"data": map[string]any{"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(bodyDigest[:])}},
			"signature": map[string]any{
				"content":   base64.StdEncoding.EncodeToString(bodySig),
				"publicKey": map[string]any{"content": base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: bodyCert}))},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	leaves := make([][32]byte, g.treeSize)
	for i := range leaves {
		if _, err := rand.Read(leaves[i][:]); err != nil {
			t.Fatal(err)
		}
	}
	leaves[g.index] = sha256.Sum256(append([]byte{0}, body...))
	root, proof := merkleRoot(leaves), merklePath(int(g.index), leaves)
	if g.flipProof {
		proof[0][0] ^= 1
	}
	cpSize, cpRoot := g.treeSize, root
	if g.checkpointTree != nil {
		cpSize, cpRoot = g.checkpointTree.size, g.checkpointTree.root
	}
	text := fmt.Sprintf("rekor.test - 1\n%d\n%s\n", cpSize, base64.StdEncoding.EncodeToString(cpRoot[:]))
	textDigest := sha256.Sum256([]byte(text))
	cpSig, err := ecdsa.SignASN1(rand.Reader, f.rekorKey, textDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := text + "\n— rekor.test " + base64.StdEncoding.EncodeToString(append(append([]byte{}, f.logID[:4]...), cpSig...)) + "\n"

	logIndex := uint64(1000) + g.index
	payload, err := jcs.Marshal(map[string]any{
		"body":           base64.StdEncoding.EncodeToString(body),
		"integratedTime": json.Number(strconv.FormatInt(integratedAt.Unix(), 10)),
		"logID":          hex.EncodeToString(g.logID[:]),
		"logIndex":       json.Number(strconv.FormatUint(logIndex, 10)),
	})
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := sha256.Sum256(payload)
	set, err := ecdsa.SignASN1(rand.Reader, f.rekorKey, payloadDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	if g.flipSET {
		set[len(set)-1] ^= 1
	}

	hashes := make([][]byte, len(proof))
	for i := range proof {
		hashes[i] = proof[i][:]
	}
	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"certificate": map[string]any{"rawBytes": leaf.Raw},
			"tlogEntries": []any{map[string]any{
				"logIndex":         strconv.FormatUint(logIndex, 10),
				"logId":            map[string]any{"keyId": g.logID[:]},
				"kindVersion":      map[string]any{"kind": "hashedrekord", "version": "0.0.1"},
				"integratedTime":   strconv.FormatInt(integratedAt.Unix(), 10),
				"inclusionPromise": map[string]any{"signedEntryTimestamp": set},
				"inclusionProof": map[string]any{
					"logIndex":   strconv.FormatUint(g.index, 10),
					"rootHash":   root[:],
					"treeSize":   strconv.FormatUint(g.treeSize, 10),
					"hashes":     hashes,
					"checkpoint": map[string]any{"envelope": checkpoint},
				},
				"canonicalizedBody": body,
			}},
		},
		"messageSignature": map[string]any{
			"messageDigest": map[string]any{"algorithm": "SHA2_256", "digest": digest[:]},
			"signature":     sig,
		},
	}
	if g.edit != nil {
		g.edit(bundle)
	}
	out, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func merkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := 1 << (bits.Len(uint(len(leaves)-1)) - 1)
	return node(merkleRoot(leaves[:k]), merkleRoot(leaves[k:]))
}

func merklePath(m int, leaves [][32]byte) [][32]byte {
	if len(leaves) == 1 {
		return nil
	}
	k := 1 << (bits.Len(uint(len(leaves)-1)) - 1)
	if m < k {
		return append(merklePath(m, leaves[:k]), merkleRoot(leaves[k:]))
	}
	return append(merklePath(m-k, leaves[k:]), merkleRoot(leaves[:k]))
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func entry(bundle map[string]any) map[string]any {
	return bundle["verificationMaterial"].(map[string]any)["tlogEntries"].([]any)[0].(map[string]any)
}

func withStatement(t *testing.T, edit func(map[string]any)) func(*forgery) {
	t.Helper()
	return func(g *forgery) {
		v, err := jcs.Decode(g.blob)
		if err != nil {
			t.Fatal(err)
		}
		edit(v.(map[string]any))
		if g.blob, err = jcs.Marshal(v); err != nil {
			t.Fatal(err)
		}
		g.signOver = g.blob
	}
}

type forgedCase struct {
	name  string
	err   error
	apply func(t *testing.T, f *forge, g *forgery)
}

// forgedCases is every forgery, with the error family Verify must answer.
func forgedCases(t *testing.T) []forgedCase {
	t.Helper()
	otherBlob := []byte("not the statement")
	return []forgedCase{
		{"valid", nil, nil},
		{"issuer", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) { g.ext[8] = "https://accounts.google.com" }},
		{"build-signer", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) {
			g.san = "https://github.com/Watermark-Labs/pins/.github/workflows/check.yml@refs/heads/main"
			g.ext[9] = g.san
		}},
		{"san-only", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) {
			g.san = "https://github.com/Watermark-Labs/pins/.github/workflows/check.yml@refs/heads/main"
		}},
		{"source-repository-uri", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) { g.ext[12] = "https://github.com/Watermark-Labs/pins-fork" }},
		{"repository-id", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) { g.ext[15] = "1" }},
		{"owner-id", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) { g.ext[17] = "1" }},
		{"ref", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) { g.ext[14] = "refs/heads/feature" }},
		{"trigger", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) { g.ext[20] = "workflow_dispatch" }},
		{"runner", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) { g.ext[11] = "self-hosted" }},
		{"no-trigger-extension", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) { delete(g.ext, 20) }},
		{"build-config-uri", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) {
			g.ext[18] = "https://github.com/Watermark-Labs/pins/.github/workflows/other.yml@refs/heads/main"
		}},
		{"build-config-digest", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) { g.ext[19] = strings.Repeat("ab", 20) }},
		{"run-attempt-2", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) {
			g.ext[21] = "https://github.com/Watermark-Labs/pins/actions/runs/40609597243/attempts/2"
		}},
		{"run-other-repository", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) {
			g.ext[21] = "https://github.com/Watermark-Labs/pins-fork/actions/runs/1/attempts/1"
		}},
		{"expired", ErrCertificate, func(_ *testing.T, _ *forge, g *forgery) {
			g.notBefore, g.notAfter = integratedAt.Add(-11*time.Minute), integratedAt.Add(-time.Minute)
		}},
		{"critical-extension", ErrCertificate, func(_ *testing.T, _ *forge, g *forgery) { g.criticalExtension = true }},
		{"no-eku", ErrCertificate, func(_ *testing.T, _ *forge, g *forgery) {
			g.leafEdit = func(c *x509.Certificate) { c.ExtKeyUsage = nil }
		}},
		{"signature", ErrSignature, func(_ *testing.T, _ *forge, g *forgery) { g.signOver = otherBlob }},
		{"body-digest", ErrBody, func(_ *testing.T, _ *forge, g *forgery) {
			d := sha256.Sum256(otherBlob)
			g.bodyDigest = &d
		}},
		{"body-signature", ErrBody, func(t *testing.T, _ *forge, g *forgery) {
			d := sha256.Sum256(otherBlob)
			sig, err := ecdsa.SignASN1(rand.Reader, newKey(t), d[:])
			if err != nil {
				t.Fatal(err)
			}
			g.bodySignature = sig
		}},
		{"body-certificate", ErrBody, func(t *testing.T, f *forge, g *forgery) { g.bodyCert = g.leaf(t, f, newKey(t)).Raw }},
		{"set", ErrLog, func(_ *testing.T, _ *forge, g *forgery) { g.flipSET = true }},
		{"inclusion", ErrLog, func(_ *testing.T, _ *forge, g *forgery) { g.flipProof = true }},
		{"checkpoint-other-tree", ErrLog, func(t *testing.T, _ *forge, g *forgery) {
			g.checkpointTree = &struct {
				size uint64
				root [32]byte
			}{size: g.treeSize + 1}
			if _, err := rand.Read(g.checkpointTree.root[:]); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown-log", ErrLog, func(_ *testing.T, _ *forge, g *forgery) { g.logID[0] ^= 1 }},
		{"two-entries", ErrBundle, func(_ *testing.T, _ *forge, g *forgery) {
			g.edit = func(b map[string]any) {
				vm := b["verificationMaterial"].(map[string]any)
				vm["tlogEntries"] = append(vm["tlogEntries"].([]any), entry(b))
			}
		}},
		{"dsse", ErrBundle, func(_ *testing.T, _ *forge, g *forgery) {
			g.edit = func(b map[string]any) {
				sig := b["messageSignature"].(map[string]any)["signature"]
				delete(b, "messageSignature")
				b["dsseEnvelope"] = map[string]any{"payload": g.blob, "payloadType": "application/vnd.in-toto+json", "signatures": []any{map[string]any{"sig": sig}}}
			}
		}},
		{"short-log-id", ErrBundle, func(_ *testing.T, _ *forge, g *forgery) {
			g.edit = func(b map[string]any) { entry(b)["logId"] = map[string]any{"keyId": g.logID[:31]} }
		}},
		{"checkpoint-short-hash", ErrLog, func(_ *testing.T, _ *forge, g *forgery) {
			g.edit = func(b map[string]any) {
				cp := entry(b)["inclusionProof"].(map[string]any)["checkpoint"].(map[string]any)
				lines := strings.SplitN(cp["envelope"].(string), "\n", 4)
				lines[2] = lines[2][:8]
				cp["envelope"] = strings.Join(lines, "\n")
			}
		}},
		{"checkpoint-two-signatures", ErrLog, func(_ *testing.T, _ *forge, g *forgery) {
			g.edit = func(b map[string]any) {
				cp := entry(b)["inclusionProof"].(map[string]any)["checkpoint"].(map[string]any)
				cp["envelope"] = strings.Replace(cp["envelope"].(string), "\n\n", "\n\n— other.test AAAAAAAA\n", 1)
			}
		}},
		{"deprecated-issuer", ErrIdentity, func(_ *testing.T, _ *forge, g *forgery) {
			g.leafEdit = func(c *x509.Certificate) {
				c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: oidIssuerV1, Value: []byte("https://accounts.google.com")})
			}
		}},
		{"no-promise", ErrBundle, func(_ *testing.T, _ *forge, g *forgery) {
			g.edit = func(b map[string]any) { delete(entry(b), "inclusionPromise") }
		}},
		{"no-proof", ErrBundle, func(_ *testing.T, _ *forge, g *forgery) {
			g.edit = func(b map[string]any) { delete(entry(b), "inclusionProof") }
		}},
		{"statement-non-canonical", ErrStatement, func(t *testing.T, _ *forge, g *forgery) {
			var v any
			if err := json.Unmarshal(g.blob, &v); err != nil {
				t.Fatal(err)
			}
			g.blob, _ = json.MarshalIndent(v, "", " ")
			g.signOver = g.blob
		}},
		{"statement-type", ErrStatement, func(t *testing.T, _ *forge, g *forgery) {
			withStatement(t, func(m map[string]any) { m["type"] = "morse-enclave-pins-v2" })(g)
		}},
		{"statement-commit", ErrStatement, func(t *testing.T, _ *forge, g *forgery) {
			withStatement(t, func(m map[string]any) { m["pins_commit"] = strings.Repeat("ab", 20) })(g)
		}},
		{"statement-folded-key", ErrStatement, func(t *testing.T, _ *forge, g *forgery) {
			withStatement(t, func(m map[string]any) { m["\u017fequence"] = json.Number("999999") })(g)
		}},
		{"statement-null-revoked", ErrStatement, func(t *testing.T, _ *forge, g *forgery) {
			withStatement(t, func(m map[string]any) { m["images"].([]any)[0].(map[string]any)["revoked"] = nil })(g)
		}},
		{"statement-no-images", ErrStatement, func(t *testing.T, _ *forge, g *forgery) {
			withStatement(t, func(m map[string]any) { m["images"] = []any{} })(g)
		}},
	}
}

type storedCase struct {
	Name          string       `json:"name"`
	Blob          string       `json:"blob"`
	Bundle        string       `json:"bundle"`
	Identity      identityJSON `json:"identity"`
	Error         string       `json:"error"`
	BundleAccepts bool         `json:"bundle_accepts"`
}

func (id Identity) json() identityJSON {
	return identityJSON{
		Issuer:              id.Issuer,
		BuildSignerURI:      id.BuildSignerURI,
		BuildConfigURI:      id.BuildConfigURI,
		SourceRepositoryURI: id.SourceRepositoryURI,
		SourceRepositoryID:  id.SourceRepositoryID,
		SourceOwnerID:       id.SourceOwnerID,
		Ref:                 id.Ref,
		Triggers:            id.Triggers,
	}
}

func family(err error) string {
	for _, e := range []error{ErrBundle, ErrLog, ErrBody, ErrCertificate, ErrSignature, ErrIdentity, ErrStatement} {
		if errors.Is(err, e) {
			return strings.TrimPrefix(e.Error(), "pinsig: ")
		}
	}
	return ""
}

func TestEveryForgeryGetsItsVerdict(t *testing.T) {
	f := newForge(t)
	root, err := ParseTrustRoot(f.trustRoot)
	if err != nil {
		t.Fatal(err)
	}
	statement := readTestdata(t, "statements/prod.json")
	parsed, err := ParseStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	var stored []storedCase
	if *update {
		if err := os.RemoveAll(filepath.Join("testdata", "forged")); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join("testdata", "forged"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", "forged", "trusted_root.json"), append(f.trustRoot, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range forgedCases(t) {
		t.Run(c.name, func(t *testing.T) {
			g := newForgery(f, statement, parsed.PinsCommit)
			if c.apply != nil {
				c.apply(t, f, g)
			}
			bundle := g.build(t, f)
			_, _, err := Verify(g.blob, bundle, root, pinsIdentity)
			if c.err == nil && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if c.err != nil && !errors.Is(err, c.err) {
				t.Fatalf("got %v, want %v", err, c.err)
			}
			_, bundleErr := VerifyBundle(g.blob, bundle, root, pinsIdentity)
			if !*update {
				return
			}
			blobPath := "statements/prod.json"
			if string(g.blob) != string(statement) {
				blobPath = "forged/" + c.name + ".statement.json"
				if err := os.WriteFile(filepath.Join("testdata", blobPath), g.blob, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			bundlePath := "forged/" + c.name + ".sigstore.json"
			if err := os.WriteFile(filepath.Join("testdata", bundlePath), append(bundle, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			stored = append(stored, storedCase{Name: c.name, Blob: blobPath, Bundle: bundlePath, Identity: pinsIdentity.json(), Error: family(err), BundleAccepts: bundleErr == nil})
		})
	}
	if *update {
		out, _ := json.MarshalIndent(stored, "", "  ")
		if err := os.WriteFile(filepath.Join("testdata", "forged", "cases.json"), append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTheStoredForgeriesKeepTheirVerdicts(t *testing.T) {
	root, err := ParseTrustRoot(readTestdata(t, "forged/trusted_root.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []storedCase
	if err := json.Unmarshal(readTestdata(t, "forged/cases.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(forgedCases(t)) {
		t.Fatalf("%d stored cases, %d in the table; rerun with -update", len(cases), len(forgedCases(t)))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			blob, bundle, id := readTestdata(t, c.Blob), readTestdata(t, c.Bundle), c.Identity.identity()
			_, _, err := Verify(blob, bundle, root, id)
			if got := family(err); got != c.Error || (err == nil) != (c.Error == "") {
				t.Errorf("Verify: %v, stored family %q", err, c.Error)
			}
			if _, err := VerifyBundle(blob, bundle, root, id); (err == nil) != c.BundleAccepts {
				t.Errorf("VerifyBundle: %v, stored accepts %v", err, c.BundleAccepts)
			}
		})
	}
}
