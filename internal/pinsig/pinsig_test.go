package pinsig

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// identityJSON is how testdata names an Identity, so the differential module
// reads the same cases.
type identityJSON struct {
	Issuer              string   `json:"issuer"`
	BuildSignerURI      string   `json:"build_signer_uri"`
	BuildConfigURI      string   `json:"build_config_uri"`
	SourceRepositoryURI string   `json:"source_repository_uri"`
	SourceRepositoryID  string   `json:"source_repository_id"`
	SourceOwnerID       string   `json:"source_owner_id"`
	Ref                 string   `json:"ref"`
	Triggers            []string `json:"triggers"`
}

func (j identityJSON) identity() Identity {
	return Identity{
		Issuer:              j.Issuer,
		BuildSignerURI:      j.BuildSignerURI,
		BuildConfigURI:      j.BuildConfigURI,
		SourceRepositoryURI: j.SourceRepositoryURI,
		SourceRepositoryID:  j.SourceRepositoryID,
		SourceOwnerID:       j.SourceOwnerID,
		Ref:                 j.Ref,
		Triggers:            j.Triggers,
	}
}

type realCase struct {
	Name             string       `json:"name"`
	Blob             string       `json:"blob"`
	Bundle           string       `json:"bundle"`
	Identity         identityJSON `json:"identity"`
	SourceDigest     string       `json:"source_digest"`
	RunInvocationURI string       `json:"run_invocation_uri"`
	IntegratedTime   int64        `json:"integrated_time"`
}

func readTestdata(tb testing.TB, name string) []byte {
	tb.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func publicRoot(t *testing.T) TrustRoot {
	t.Helper()
	root, err := PublicGood()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func realCases(t *testing.T) []realCase {
	t.Helper()
	var cases []realCase
	if err := json.Unmarshal(readTestdata(t, "real.json"), &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

func TestARealGitHubActionsBundleVerifiesUnderItsIdentity(t *testing.T) {
	root := publicRoot(t)
	for _, c := range realCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			rec, err := VerifyBundle(readTestdata(t, c.Blob), readTestdata(t, c.Bundle), root, c.Identity.identity())
			if err != nil {
				t.Fatal(err)
			}
			if rec.SourceDigest != c.SourceDigest {
				t.Errorf("source digest %s, want %s", rec.SourceDigest, c.SourceDigest)
			}
			if rec.RunInvocationURI != c.RunInvocationURI {
				t.Errorf("run invocation %s, want %s", rec.RunInvocationURI, c.RunInvocationURI)
			}
			if want := time.Unix(c.IntegratedTime, 0).UTC(); !rec.IntegratedTime.Equal(want) {
				t.Errorf("integrated time %s, want %s", rec.IntegratedTime, want)
			}
		})
	}
}

func TestARealBundleIsRefusedWhenOneIdentityFieldDiffers(t *testing.T) {
	root := publicRoot(t)
	c := realCases(t)[0]
	blob, bundle := readTestdata(t, c.Blob), readTestdata(t, c.Bundle)
	for name, change := range map[string]func(*Identity){
		"issuer":             func(id *Identity) { id.Issuer = "https://accounts.google.com" },
		"build signer":       func(id *Identity) { id.BuildSignerURI += "x" },
		"build config":       func(id *Identity) { id.BuildConfigURI += "x" },
		"source repository":  func(id *Identity) { id.SourceRepositoryURI = "https://github.com/getsops/sops-fork" },
		"repository id":      func(id *Identity) { id.SourceRepositoryID = "1" },
		"owner id":           func(id *Identity) { id.SourceOwnerID = "1" },
		"ref":                func(id *Identity) { id.Ref = "refs/heads/main" },
		"trigger":            func(id *Identity) { id.Triggers = []string{"workflow_dispatch", "schedule"} },
		"no trigger allowed": func(id *Identity) { id.Triggers = nil },
	} {
		id := c.Identity.identity()
		change(&id)
		if _, err := VerifyBundle(blob, bundle, root, id); !errors.Is(err, ErrIdentity) {
			t.Errorf("%s: got %v, want ErrIdentity", name, err)
		}
	}
}

func TestARealBundleIsRefusedOverAnotherBlob(t *testing.T) {
	root := publicRoot(t)
	c := realCases(t)[0]
	blob := append(readTestdata(t, c.Blob), '\n')
	if _, err := VerifyBundle(blob, readTestdata(t, c.Bundle), root, c.Identity.identity()); !errors.Is(err, ErrBody) {
		t.Errorf("got %v, want ErrBody", err)
	}
}

func TestATrustRootWithoutARekorV1KeyOrACAIsRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":        `{}`,
		"only v2 logs": `{"tlogs":[{"hashAlgorithm":"SHA2_256","publicKey":{"keyDetails":"PKIX_ED25519","rawBytes":"AA==","validFor":{"start":"2025-01-01T00:00:00Z"}},"logId":{"keyId":"AA=="}}]}`,
	} {
		if _, err := ParseTrustRoot([]byte(raw)); !errors.Is(err, ErrTrustRoot) {
			t.Errorf("%s: got %v, want ErrTrustRoot", name, err)
		}
	}
}
