package attestation

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"morse/backend/internal/aci"
)

const registerLen = 48

type Register [registerLen]byte

func (r Register) String() string { return hex.EncodeToString(r[:]) }

func (r Register) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r *Register) UnmarshalText(text []byte) error {
	if hex.DecodedLen(len(text)) != registerLen {
		return fmt.Errorf("register %q is not %d hex bytes", text, registerLen)
	}
	_, err := hex.Decode(r[:], text)
	return err
}

type Boot struct {
	MRTD  Register `json:"mrtd"`
	RTMR0 Register `json:"rtmr0"`
	RTMR1 Register `json:"rtmr1"`
	RTMR2 Register `json:"rtmr2"`
}

type OSMeasurement struct {
	OSImageHash string `json:"os_image_hash"`
	Boot
}

type GatewayAnchors struct {
	TDAttributes  string `json:"td_attributes,omitempty"`
	AppID         string `json:"app_id,omitempty"`
	KeyProviderID string `json:"key_provider_id,omitempty"`
}

var registerNames = []string{"mrtd", "rtmr0", "rtmr1", "rtmr2"}

// osRegisters are the boot-time registers a dstack OS release fixes.
type osRegisters [4]Register

func (m OSMeasurement) registers() osRegisters {
	return osRegisters{m.MRTD, m.RTMR0, m.RTMR1, m.RTMR2}
}

func (r osRegisters) String() string { return joinRegisters(r[:]) }

func (r osRegisters) complete() bool { return !slices.Contains(r[:], Register{}) }

func joinRegisters(r []Register) string {
	parts := make([]string, len(r))
	for i, v := range r {
		parts[i] = v.String()
	}
	return strings.Join(parts, ":")
}

type Release struct {
	Source        string `json:"source"`
	ComposeHash   string `json:"compose_hash"`
	LauncherImage string `json:"launcher_image"`
}

func (r Release) String() string { return r.Source + " " + r.ComposeHash + " " + r.LauncherImage }

func (r Release) RepoCommit() (repoURL, commit string, ok bool) {
	i := strings.LastIndex(r.Source, sourceCommitSep)
	if i < 0 {
		return "", "", false
	}
	return r.Source[:i], r.Source[i+len(sourceCommitSep):], true
}

type Pinset[V Verified] interface {
	Check(V) []Drift
}

type IdentityPins struct {
	GatewayAnchors
	Releases  []Release `json:"releases,omitempty"`
	Images    []OSImage `json:"images,omitempty"`
	Instances []string  `json:"instances,omitempty"`
}

type OSImage struct {
	Name string `json:"name"`
	OSMeasurement
}

func (i OSImage) String() string { return i.Name }

func (m OSMeasurement) RegisterDrift(observed OSMeasurement) []Drift {
	pinned, seen := m.registers(), observed.registers()
	var drifts []Drift
	for i := range pinned {
		if pinned[i] != seen[i] {
			drifts = append(drifts, Drift{Kind: DriftAnchor, Field: registerNames[i], Pinned: pinned[i].String(), Observed: seen[i].String()})
		}
	}
	return drifts
}

func findImage(images []OSImage, r osRegisters) (OSImage, bool) {
	for _, i := range images {
		if i.registers() == r {
			return i, true
		}
	}
	return OSImage{}, false
}

func imageDrift(images []OSImage, observed OSMeasurement) []Drift {
	var hashes []string
	for _, i := range images {
		if i.registers() != observed.registers() {
			continue
		}
		if i.OSImageHash == observed.OSImageHash {
			return nil
		}
		hashes = append(hashes, i.OSImageHash)
	}
	if hashes == nil {
		return []Drift{{Kind: DriftAnchor, Field: ImagesField, Observed: observed.registers().String()}}
	}
	return []Drift{{Kind: DriftRelease, Field: osImageHashField, Pinned: strings.Join(hashes, ", "), Observed: observed.OSImageHash}}
}

func instanceDrift(instances []string, observed string) []Drift {
	if slices.Contains(instances, observed) {
		return nil
	}
	return []Drift{{Kind: DriftNewInstance, Field: instancesField, Observed: observed}}
}

func checkImages(images []OSImage) error {
	if len(images) == 0 {
		return fmt.Errorf("%s is missing", ImagesField)
	}
	seen := map[OSMeasurement]bool{}
	for _, i := range images {
		if i.Name == "" || i.OSImageHash == "" {
			return fmt.Errorf("image %q needs a name and an %s", i.Name, osImageHashField)
		}
		if !i.registers().complete() {
			return fmt.Errorf("image %s is missing a register of %d hex bytes", i, registerLen)
		}
		if seen[i.OSMeasurement] {
			return fmt.Errorf("image %s repeats another image's registers and %s", i, osImageHashField)
		}
		seen[i.OSMeasurement] = true
	}
	return nil
}

type DriftKind string

const (
	DriftAnchor      DriftKind = "anchor"
	DriftRelease     DriftKind = "release"
	DriftNewInstance DriftKind = "new_instance"
)

const (
	instancesField    = "instances"
	ReleasesField     = "releases"
	osImageHashField  = "os_image_hash"
	tdAttributesField = "td_attributes"
	ImagesField       = "images"
)

var (
	ErrAnchor = errors.New("attestation: the verified report is not the pinned gateway")
	ErrPins   = errors.New("attestation: pins")
)

type Drift struct {
	Kind     DriftKind `json:"kind"`
	Field    string    `json:"field"`
	Pinned   string    `json:"pinned,omitempty"`
	Observed string    `json:"observed"`
}

type anchorField struct {
	name  string
	value string
}

func (a GatewayAnchors) fields() []anchorField {
	return []anchorField{
		{tdAttributesField, a.TDAttributes},
		{"app_id", a.AppID},
		{"key_provider_id", a.KeyProviderID},
	}
}

func ObservedIdentity(v PhalaReport) IdentityPins {
	return IdentityPins{GatewayAnchors: v.GatewayAnchors, Releases: []Release{v.Release}, Images: []OSImage{{OSMeasurement: v.OSMeasurement}}, Instances: []string{v.InstanceID}}
}

func (a GatewayAnchors) drift(observed GatewayAnchors) []Drift {
	var drifts []Drift
	seen := observed.fields()
	for i, p := range a.fields() {
		if p.value != seen[i].value {
			drifts = append(drifts, Drift{Kind: DriftAnchor, Field: p.name, Pinned: p.value, Observed: seen[i].value})
		}
	}
	return drifts
}

func (p IdentityPins) Pinned(m OSMeasurement) (OSImage, bool) {
	return findImage(p.Images, m.registers())
}

func (p IdentityPins) Check(v PhalaReport) []Drift {
	return slices.Concat(imageDrift(p.Images, v.OSMeasurement), p.gatewayDrift(v), instanceDrift(p.Instances, v.InstanceID))
}

func (p IdentityPins) gatewayDrift(v PhalaReport) []Drift {
	drifts := p.drift(v.GatewayAnchors)
	if r := v.Release; !slices.Contains(p.Releases, r) {
		drifts = append(drifts, p.releaseDrift(r))
	}
	return drifts
}

// releaseDrift serves an unpinned release when a pinned release of the same repository ran the same
// launcher image, and leaves the rest for review after it ships, so a Phala gateway upgrade is no outage.
// checkProvenance has shown that the launcher is the one service the measured compose configures with
// this repository and commit, as literals, and app_id and key_provider_id bind the release to Phala's
// gateway app on Phala's KMS. What the commit changed, and what else the compose runs, is the review's
// question. A new launcher image is an anchor until a person pins it.
func (p IdentityPins) releaseDrift(r Release) Drift {
	repo, _, ok := r.RepoCommit()
	reviewed := ok && slices.ContainsFunc(p.Releases, func(pinned Release) bool {
		u, _, ok := pinned.RepoCommit()
		return ok && u == repo && pinned.LauncherImage == r.LauncherImage
	})
	if !reviewed {
		return Drift{Kind: DriftAnchor, Field: ReleasesField, Observed: r.String()}
	}
	pinned := make([]string, len(p.Releases))
	for i, pr := range p.Releases {
		pinned[i] = pr.String()
	}
	return Drift{Kind: DriftRelease, Field: ReleasesField, Pinned: strings.Join(pinned, ", "), Observed: r.String()}
}

func Enforce[V Verified](p Pinset[V], v V) ([]Drift, error) {
	drifts := p.Check(v)
	return drifts, refuseAnchors(drifts)
}

// Judge refuses the whole report on drift: a Phala report speaks for one host, so there is no endpoint to
// drop short of the scope.
func (p IdentityPins) Judge(r PhalaReport) (Verdicts[aci.SPKI], error) {
	drift, err := Enforce(p, r)
	if err != nil {
		return Verdicts[aci.SPKI]{}, err
	}
	return Verdicts[aci.SPKI]{Endpoints: []Judged[aci.SPKI]{{Endpoint: r.Endpoint, Drift: drift, Verified: r}}}, nil
}

func (p IdentityPins) EnforceGateway(v PhalaReport) error {
	return refuseAnchors(p.gatewayDrift(v))
}

type AnchorRefusal struct{ Drifts []Drift }

func (r *AnchorRefusal) Error() string {
	anchors := make([]string, len(r.Drifts))
	for i, d := range r.Drifts {
		anchors[i] = anchorText(d)
	}
	return fmt.Sprintf("%s: %s", ErrAnchor, strings.Join(anchors, "; "))
}

func (r *AnchorRefusal) Unwrap() error { return ErrAnchor }

func refuseAnchors(drifts []Drift) error {
	var anchors []Drift
	for _, d := range drifts {
		if d.Kind == DriftAnchor {
			anchors = append(anchors, d)
		}
	}
	if anchors != nil {
		return &AnchorRefusal{Drifts: anchors}
	}
	return nil
}

func anchorText(d Drift) string {
	if d.Pinned == "" {
		return fmt.Sprintf("%s %s matches no pinned entry", d.Field, d.Observed)
	}
	return fmt.Sprintf("%s %s, pinned %s", d.Field, d.Observed, d.Pinned)
}

func decodePins(raw []byte, p any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return fmt.Errorf("%w: %w", ErrPins, err)
	}
	return nil
}

func readPins[P any](path string, parse func([]byte) (P, error)) (P, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		var zero P
		return zero, err
	}
	return parse(raw)
}

func EncodePins[P any](pins P, parse func([]byte) (P, error)) ([]byte, error) {
	raw, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if _, err := parse(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func ParseIdentityPins(raw []byte) (IdentityPins, error) {
	var p IdentityPins
	if err := decodePins(raw, &p); err != nil {
		return IdentityPins{}, err
	}
	for _, f := range p.fields() {
		if f.value == "" {
			return IdentityPins{}, fmt.Errorf("%w: %s is missing", ErrPins, f.name)
		}
	}
	if len(p.Releases) == 0 {
		return IdentityPins{}, fmt.Errorf("%w: %s is missing", ErrPins, ReleasesField)
	}
	for i, r := range p.Releases {
		if r.Source == "" || r.ComposeHash == "" || !digestPinnedImage.MatchString(r.LauncherImage) {
			return IdentityPins{}, fmt.Errorf("%w: every %s entry needs a source, a compose_hash, and a launcher_image pinned by sha256 digest", ErrPins, ReleasesField)
		}
		if slices.Contains(p.Releases[:i], r) {
			return IdentityPins{}, fmt.Errorf("%w: %s repeats %s", ErrPins, ReleasesField, r)
		}
	}
	if err := checkImages(p.Images); err != nil {
		return IdentityPins{}, fmt.Errorf("%w: %w", ErrPins, err)
	}
	if len(p.Instances) == 0 {
		return IdentityPins{}, fmt.Errorf("%w: %s is missing", ErrPins, instancesField)
	}
	if slices.Contains(p.Instances, "") {
		return IdentityPins{}, fmt.Errorf("%w: every %s entry needs an id", ErrPins, instancesField)
	}
	return p, nil
}
