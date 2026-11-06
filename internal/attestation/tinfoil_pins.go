package attestation

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"morse/backend/internal/aci"
)

// RouterPins name what may serve Tinfoil's routes: the router hosts, each router release by the
// measurement its Sigstore provenance publishes (checked with gh attestation verify before it is
// pinned), and the platform a release must boot on.
type RouterPins struct {
	Hosts    []string        `json:"hosts"`
	Releases []RouterRelease `json:"releases"`
	Policy   string          `json:"policy"`
	VMPL     uint32          `json:"vmpl"`
	MinTCB   SNPTCB          `json:"min_tcb"`
	Chips    []string        `json:"chips"`
}

type RouterRelease struct {
	Name        string `json:"name"`
	Digest      string `json:"digest"`
	Measurement string `json:"measurement"`
}

func (r RouterRelease) String() string { return r.Name + " " + r.Measurement }

const (
	hostsField       = "hosts"
	measurementField = "measurement"
	policyField      = "policy"
	vmplField        = "vmpl"
	minTCBField      = "min_tcb"
	chipsField       = "chips"
	measurementLen   = 48
)

// Check judges a verified report: a host, release, policy, VMPL or TCB the pins don't name is an
// anchor; a chip they don't list is a new instance.
func (p RouterPins) Check(r TinfoilReport) []Drift {
	var drifts []Drift
	if !slices.Contains(p.Hosts, r.Host) {
		drifts = append(drifts, Drift{Kind: DriftAnchor, Field: hostsField, Pinned: strings.Join(p.Hosts, ", "), Observed: r.Host})
	}
	if !slices.ContainsFunc(p.Releases, func(rel RouterRelease) bool { return rel.Measurement == r.Measurement }) {
		pinned := make([]string, len(p.Releases))
		for i, rel := range p.Releases {
			pinned[i] = rel.String()
		}
		drifts = append(drifts, Drift{Kind: DriftAnchor, Field: ReleasesField, Pinned: strings.Join(pinned, ", "), Observed: r.Measurement})
	}
	if observed := policyText(r.Policy); observed != p.Policy {
		drifts = append(drifts, Drift{Kind: DriftAnchor, Field: policyField, Pinned: p.Policy, Observed: observed})
	}
	if r.VMPL != p.VMPL {
		drifts = append(drifts, Drift{Kind: DriftAnchor, Field: vmplField, Pinned: strconv.FormatUint(uint64(p.VMPL), 10), Observed: strconv.FormatUint(uint64(r.VMPL), 10)})
	}
	if r.TCB.below(p.MinTCB) {
		drifts = append(drifts, Drift{Kind: DriftAnchor, Field: minTCBField, Pinned: p.MinTCB.String(), Observed: r.TCB.String()})
	}
	for _, d := range instanceDrift(p.Chips, r.ChipID) {
		d.Field = chipsField
		drifts = append(drifts, d)
	}
	return drifts
}

// Judge refuses the whole report on an anchor, as a router host is one guest: there is no endpoint
// to drop short of the scope.
func (p RouterPins) Judge(r TinfoilReport) (Verdicts[aci.SPKI], error) {
	drift, err := Enforce(p, r)
	if err != nil {
		return Verdicts[aci.SPKI]{}, err
	}
	return Verdicts[aci.SPKI]{Endpoints: []Judged[aci.SPKI]{{Endpoint: r.Endpoint, Drift: drift, Verified: r}}}, nil
}

func policyText(policy uint64) string { return fmt.Sprintf("%#x", policy) }

func ParseTinfoilPins(raw []byte) (RouterPins, error) {
	var p RouterPins
	if err := decodePins(raw, &p); err != nil {
		return RouterPins{}, err
	}
	if err := p.check(); err != nil {
		return RouterPins{}, fmt.Errorf("%w: %w", ErrPins, err)
	}
	return p, nil
}

func (p RouterPins) check() error {
	if err := distinctNonEmpty(hostsField, p.Hosts); err != nil {
		return err
	}
	if len(p.Releases) == 0 {
		return fmt.Errorf("%s is missing", ReleasesField)
	}
	for i, r := range p.Releases {
		if r.Name == "" || r.Digest == "" {
			return fmt.Errorf("every %s entry needs a name and a digest", ReleasesField)
		}
		if m, err := hex.DecodeString(r.Measurement); err != nil || len(m) != measurementLen || r.Measurement != strings.ToLower(r.Measurement) {
			return fmt.Errorf("release %s needs a %s of %d lowercase hex bytes", r.Name, measurementField, measurementLen)
		}
		if slices.ContainsFunc(p.Releases[:i], func(o RouterRelease) bool { return o.Measurement == r.Measurement }) {
			return fmt.Errorf("%s repeats %s", ReleasesField, r)
		}
	}
	policy, err := strconv.ParseUint(strings.TrimPrefix(p.Policy, "0x"), 16, 64)
	if err != nil || policyText(policy) != p.Policy {
		return fmt.Errorf("%s %q is not a guest policy in 0x-prefixed lowercase hex", policyField, p.Policy)
	}
	return distinctNonEmpty(chipsField, p.Chips)
}

// ObservedTinfoil is the pins a verified report would match, for attest-watch to propose.
func ObservedTinfoil(r TinfoilReport) RouterPins {
	return RouterPins{
		Hosts:    []string{r.Host},
		Releases: []RouterRelease{{Measurement: r.Measurement}},
		Policy:   policyText(r.Policy),
		VMPL:     r.VMPL,
		MinTCB:   r.TCB,
		Chips:    []string{r.ChipID},
	}
}
