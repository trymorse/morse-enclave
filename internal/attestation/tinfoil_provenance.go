package attestation

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"morse/backend/internal/exactjson"
	"morse/backend/internal/pinsig"
)

// Tinfoil's router serves, beside its SEV-SNP report, the Sigstore bundle its release workflow
// published for the release it runs: an in-toto statement whose predicate names the release's
// measurement. The bundle proves itself, so nothing beside it in the collateral is trusted. The
// tag comes from the signing certificate's source ref, the measurement from the signed predicate,
// and the digest from the statement's subject. A release the pins don't list is served when that
// proof names the report's measurement at a tag newer than every pinned release.

const (
	TinfoilCodeCollateral = "https://tinfoil.sh/collateral/sigstore-code/v1"
	routerPredicate       = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
	inTotoPayload         = "application/vnd.in-toto+json"
	inTotoStatement       = "https://in-toto.io/Statement/v1"
	routerSubject         = "tinfoil-deployment.json"
	// RouterReleasePrefix starts every pinned router release's name; the tag follows it.
	RouterReleasePrefix = "confidential-model-router "
)

var (
	ErrNoProvenance     = errors.New("attestation: the router offered no release provenance")
	ErrRouterCollateral = errors.New("attestation: the router's sigstore-code collateral carries no bundle")
	ErrRouterProvenance = errors.New("attestation: the router's release provenance")
)

var routerSigner = pinsig.Identity{
	Issuer:              "https://token.actions.githubusercontent.com",
	SourceRepositoryURI: "https://github.com/tinfoilsh/confidential-model-router",
	SourceRepositoryID:  "1077094187",
	SourceOwnerID:       "168487856",
	Workflow:            ".github/workflows/tinfoil-release-publish.yml",
	Ref:                 pinsig.SemverTags(),
	Triggers:            []string{"workflow_dispatch"},
}

// routerTag is pinsig.SemverTags without the refs/tags/ prefix: at most nine digits per
// component, which both this side's int and the browser's number order exactly.
var (
	measurementShape = regexp.MustCompile(`^[0-9a-f]{96}$`)
	digestShape      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	routerTag        = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
)

// ProvenRelease is a router release Sigstore proves Tinfoil's release workflow published.
type ProvenRelease struct {
	Tag         string    // vX.Y.Z, from the certificate's source ref, never from the collateral's tag
	Measurement string    // predicate.snp_measurement, 96 lowercase hex
	Digest      string    // the statement's one subject, tinfoil-deployment.json, sha256 hex
	Run         string    // the run invocation URI
	Logged      time.Time // Rekor's integrated time
}

func (r ProvenRelease) Name() string { return RouterReleasePrefix + r.Tag }

// Provenance is what the router's code collateral proved. Only ProveRouterRelease builds a proven
// one. The zero value means none was offered.
type Provenance struct {
	release ProvenRelease
	proven  bool
	refusal error
}

func (p Provenance) Release() (ProvenRelease, bool) { return p.release, p.proven }

// Refusal says why nothing was proven: no collateral, or the first check the bundle failed. It is
// nil when a release was proven.
func (p Provenance) Refusal() error {
	switch {
	case p.proven:
		return nil
	case p.refusal == nil:
		return ErrNoProvenance
	}
	return p.refusal
}

// ProveRouterRelease verifies code, the data of a sigstore-code collateral item or nil, against the
// embedded public-good root and Tinfoil's release identity. It never errors: a refusal is a Provenance.
func ProveRouterRelease(code json.RawMessage) Provenance {
	root, err := pinsig.PublicGood()
	if err != nil {
		return Provenance{refusal: err}
	}
	return proveRouterRelease(code, root, routerSigner)
}

func proveRouterRelease(code json.RawMessage, root pinsig.TrustRoot, id pinsig.Identity) Provenance {
	if code == nil {
		return Provenance{refusal: ErrNoProvenance}
	}
	bundle := exactjson.Parse(code).Key("sigstore_bundle")
	if bundle.Err() != nil {
		return Provenance{refusal: ErrRouterCollateral}
	}
	env, rec, err := pinsig.VerifyDSSE(bundle.Raw(), root, id)
	if err != nil {
		return Provenance{refusal: err}
	}
	rel, err := routerStatement(env)
	if err != nil {
		return Provenance{refusal: err}
	}
	rel.Tag, rel.Run, rel.Logged = strings.TrimPrefix(rec.Ref, "refs/tags/"), rec.RunInvocationURI, rec.IntegratedTime
	return Provenance{release: rel, proven: true}
}

// routerStatement reads the measurement and digest from a verified envelope: an in-toto v1 statement
// of Tinfoil's multiplatform predicate over the one deployment file.
func routerStatement(env pinsig.Envelope) (ProvenRelease, error) {
	if env.PayloadType != inTotoPayload {
		return ProvenRelease{}, fmt.Errorf("%w: payload type %q is not %s", ErrRouterProvenance, env.PayloadType, inTotoPayload)
	}
	st := exactjson.Parse(env.Payload)
	typ, predicateType := st.Key("_type").Text(), st.Key("predicateType").Text()
	subjects := st.Key("subject").Items()
	measurement := st.Key("predicate").Key("snp_measurement").Text()
	if err := st.Err(); err != nil {
		return ProvenRelease{}, fmt.Errorf("%w: %v", ErrRouterProvenance, err)
	}
	switch {
	case typ != inTotoStatement:
		return ProvenRelease{}, fmt.Errorf("%w: statement type %q is not %s", ErrRouterProvenance, typ, inTotoStatement)
	case predicateType != routerPredicate:
		return ProvenRelease{}, fmt.Errorf("%w: predicate type %q is not %s", ErrRouterProvenance, predicateType, routerPredicate)
	case len(subjects) != 1:
		return ProvenRelease{}, fmt.Errorf("%w: the subject is not the one file %s", ErrRouterProvenance, routerSubject)
	case !measurementShape.MatchString(measurement):
		return ProvenRelease{}, fmt.Errorf("%w: snp_measurement is not 96 lowercase hex characters", ErrRouterProvenance)
	}
	name, digest := subjects[0].Key("name").Text(), subjects[0].Key("digest").Key("sha256").Text()
	if err := st.Err(); err != nil {
		return ProvenRelease{}, fmt.Errorf("%w: %v", ErrRouterProvenance, err)
	}
	switch {
	case name != routerSubject:
		return ProvenRelease{}, fmt.Errorf("%w: the subject is not the one file %s", ErrRouterProvenance, routerSubject)
	case !digestShape.MatchString(digest):
		return ProvenRelease{}, fmt.Errorf("%w: the subject's sha256 is not 64 lowercase hex characters", ErrRouterProvenance)
	}
	return ProvenRelease{Measurement: measurement, Digest: digest}, nil
}

// TinfoilCode is the sigstore-code collateral data of a v3 document, or nil. It verifies nothing.
func TinfoilCode(doc []byte) json.RawMessage {
	var d TinfoilNonced
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil
	}
	return d.Code()
}
