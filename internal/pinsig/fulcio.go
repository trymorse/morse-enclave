package pinsig

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Fulcio extension OIDs, from
// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md. Those from
// .8 on are DER UTF8Strings. .18 and .19 name the workflow that started the
// run and its commit; .21 names the run, on GitHub Actions
// https://github.com/<owner>/<repo>/actions/runs/<id>/attempts/<n>.
var (
	oidIssuerV1          = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuer            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidBuildSignerURI    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 9}
	oidRunnerEnvironment = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 11}
	oidSourceRepoURI     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 12}
	oidSourceRepoDigest  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 13}
	oidSourceRepoRef     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 14}
	oidSourceRepoID      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 15}
	oidSourceRepoOwnerID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 17}
	oidBuildConfigURI    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 18}
	oidBuildConfigDigest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 19}
	oidBuildTrigger      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 20}
	oidRunInvocationURI  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 21}
	githubHostedRunner   = "github-hosted"
)

// x509.Verify refuses a leaf with an unhandled critical extension but takes
// one with no extended key usage as fit for any purpose, so verifyChain
// requires the code-signing usage on the leaf itself.
func verifyChain(leafDER []byte, root TrustRoot, at time.Time) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificate, err)
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageCodeSigning) {
		return nil, fmt.Errorf("%w: no code-signing extended key usage", ErrCertificate)
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	for _, a := range root.authorities {
		if !a.window.contains(at) {
			continue
		}
		roots.AddCert(a.chain[len(a.chain)-1])
		for _, c := range a.chain[:len(a.chain)-1] {
			intermediates.AddCert(c)
		}
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificate, err)
	}
	return leaf, nil
}

// The build config (the workflow that started the run, at the commit it ran
// from) must be the signer's own workflow at the source digest, or a workflow
// at another ref or commit could call ours as a reusable one. The run must be
// the first attempt, since a re-run of an old run signs that commit's pins
// again under a fresh Rekor time.
type signer struct {
	sourceDigest, runInvocation, ref string
}

func checkIdentity(leaf *x509.Certificate, id Identity) (signer, error) {
	if len(leaf.URIs) != 1 || len(leaf.DNSNames)+len(leaf.EmailAddresses)+len(leaf.IPAddresses) != 0 {
		return signer{}, fmt.Errorf("%w: the SAN is not exactly one URI", ErrIdentity)
	}
	ext := func(oid asn1.ObjectIdentifier) (string, error) {
		for _, e := range leaf.Extensions {
			if !e.Id.Equal(oid) {
				continue
			}
			var s string
			rest, err := asn1.UnmarshalWithParams(e.Value, &s, "utf8")
			if err != nil || len(rest) != 0 {
				return "", fmt.Errorf("%w: extension %s is not a UTF8String", ErrIdentity, oid)
			}
			return s, nil
		}
		return "", fmt.Errorf("%w: no extension %s", ErrIdentity, oid)
	}
	ref, err := ext(oidSourceRepoRef)
	if err != nil {
		return signer{}, err
	}
	if id.Ref == nil || !id.Ref.admits(ref) {
		return signer{}, fmt.Errorf("%w: source ref %q is not one the identity admits", ErrIdentity, ref)
	}
	workflowAtRef := id.SourceRepositoryURI + "/" + id.Workflow + "@" + ref
	if leaf.URIs[0].String() != workflowAtRef {
		return signer{}, fmt.Errorf("%w: SAN %s is not the build signer %s", ErrIdentity, leaf.URIs[0], workflowAtRef)
	}
	for _, want := range []struct {
		oid   asn1.ObjectIdentifier
		value string
	}{
		{oidIssuer, id.Issuer},
		{oidBuildSignerURI, workflowAtRef},
		{oidRunnerEnvironment, githubHostedRunner},
		{oidSourceRepoURI, id.SourceRepositoryURI},
		{oidSourceRepoID, id.SourceRepositoryID},
		{oidSourceRepoOwnerID, id.SourceOwnerID},
		{oidBuildConfigURI, workflowAtRef},
	} {
		got, err := ext(want.oid)
		if err != nil {
			return signer{}, err
		}
		if got != want.value {
			return signer{}, fmt.Errorf("%w: extension %s is %q, not %q", ErrIdentity, want.oid, got, want.value)
		}
	}
	// The deprecated issuer extension is the raw issuer, not DER, and sigstore-go reads it first.
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidIssuerV1) && string(e.Value) != id.Issuer {
			return signer{}, fmt.Errorf("%w: deprecated issuer %q is not %q", ErrIdentity, e.Value, id.Issuer)
		}
	}
	trigger, err := ext(oidBuildTrigger)
	if err != nil {
		return signer{}, err
	}
	if !slices.Contains(id.Triggers, trigger) {
		return signer{}, fmt.Errorf("%w: build trigger %q is not one of %v", ErrIdentity, trigger, id.Triggers)
	}
	s := signer{ref: ref}
	if s.sourceDigest, err = ext(oidSourceRepoDigest); err != nil {
		return signer{}, err
	}
	buildConfigDigest, err := ext(oidBuildConfigDigest)
	if err != nil {
		return signer{}, err
	}
	if buildConfigDigest != s.sourceDigest {
		return signer{}, fmt.Errorf("%w: build config digest %s is not the source digest %s", ErrIdentity, buildConfigDigest, s.sourceDigest)
	}
	if s.runInvocation, err = ext(oidRunInvocationURI); err != nil {
		return signer{}, err
	}
	run, isRun := strings.CutPrefix(s.runInvocation, id.SourceRepositoryURI+"/actions/runs/")
	run, isFirstAttempt := strings.CutSuffix(run, "/attempts/1")
	if !isRun || !isFirstAttempt || run == "" || strings.ContainsFunc(run, func(r rune) bool { return r < '0' || r > '9' }) {
		return signer{}, fmt.Errorf("%w: run invocation %q is not the first attempt of a run in %s", ErrIdentity, s.runInvocation, id.SourceRepositoryURI)
	}
	return s, nil
}
