package attestation

import (
	_ "embed"
	"fmt"
	"sync"
	"sync/atomic"
)

//go:embed phala_pins.json
var phalaPinsJSON []byte

//go:embed near_pins.json
var nearPinsJSON []byte

//go:embed tinfoil_pins.json
var tinfoilPinsJSON []byte

// The Privacy Veil's filter runs in a Tinfoil enclave of its own, pinned as the router is. Its pins are not in a
// VendorSet: the pins repository does not carry them yet, so a signed release never swaps them, and a new filter
// release takes a code release.
//
//go:embed tinfoil_pii_pins.json
var tinfoilFilterPinsJSON []byte

var filterPins = sync.OnceValue(func() RouterPins {
	pins, err := ParseTinfoilPins(tinfoilFilterPinsJSON)
	if err != nil {
		panic("attestation: embedded tinfoil_pii_pins.json: " + err.Error())
	}
	return pins
})

// VendorSource says where a VendorSet came from: the files compiled into the binary, or a signed release of
// the pins repository, which StatementSHA256 names by the hash of its vendor statement.
type VendorSource struct {
	Sequence        uint64
	StatementSHA256 string
}

// Embedded is the source of the boot set.
func (s VendorSource) Embedded() bool { return s.StatementSHA256 == "" }

func (s VendorSource) String() string {
	if s.Embedded() {
		return "embedded"
	}
	return fmt.Sprintf("sequence %d, statement sha256 %s", s.Sequence, s.StatementSHA256)
}

// VendorSet is every vendor pin the enclave judges an upstream by. The three files travel together: a signed
// release replaces all of them, never one.
type VendorSet struct {
	Phala   IdentityPins
	Near    GatewayModelPins
	Tinfoil RouterPins
	Source  VendorSource
}

// VendorCounts is how many pins a set holds, so a log can say what a swap would add or drop.
type VendorCounts struct {
	PhalaReleases   int
	PhalaImages     int
	NearComposes    int
	NearImages      int
	TinfoilReleases int
}

func (s VendorSet) Counts() VendorCounts {
	return VendorCounts{
		PhalaReleases:   len(s.Phala.Releases),
		PhalaImages:     len(s.Phala.Images),
		NearComposes:    len(s.Near.Gateway.Composes) + len(s.Near.Model.Composes),
		NearImages:      len(s.Near.Gateway.Images) + len(s.Near.Model.Images),
		TinfoilReleases: len(s.Tinfoil.Releases),
	}
}

// ParseVendorSet parses the three files, which must be valid pins.
func ParseVendorSet(phala, near, tinfoil []byte, source VendorSource) (VendorSet, error) {
	set := VendorSet{Source: source}
	var err error
	if set.Phala, err = ParseIdentityPins(phala); err != nil {
		return VendorSet{}, fmt.Errorf("phala_pins.json: %w", err)
	}
	if set.Near, err = ParseNearPins(near); err != nil {
		return VendorSet{}, fmt.Errorf("near_pins.json: %w", err)
	}
	if set.Tinfoil, err = ParseTinfoilPins(tinfoil); err != nil {
		return VendorSet{}, fmt.Errorf("tinfoil_pins.json: %w", err)
	}
	return set, nil
}

var embedded = sync.OnceValue(func() *VendorSet {
	set, err := ParseVendorSet(phalaPinsJSON, nearPinsJSON, tinfoilPinsJSON, VendorSource{})
	if err != nil {
		panic("attestation: embedded pins: " + err.Error())
	}
	return &set
})

// active is the set callers judge by. It is nil until a swap, which leaves the embedded set in force.
var active atomic.Pointer[VendorSet]

// Vendors is the active set. Read it once per judgment, so the three files of one judgment come from one set.
func Vendors() VendorSet {
	if set := active.Load(); set != nil {
		return *set
	}
	return *embedded()
}

// SwapVendors makes set the active one, all three files at once, and returns the set it replaces.
func SwapVendors(set VendorSet) VendorSet {
	prev := Vendors()
	active.Store(&set)
	return prev
}

func PhalaPins() IdentityPins { return Vendors().Phala }

func NearPins() GatewayModelPins { return Vendors().Near }

func TinfoilPins() RouterPins { return Vendors().Tinfoil }

// TinfoilFilterPins are the pins of the Privacy Veil's filter.
func TinfoilFilterPins() RouterPins { return filterPins() }

func LoadPhalaPins(path string) (IdentityPins, error) {
	if path == "" {
		return PhalaPins(), nil
	}
	return readPins(path, ParseIdentityPins)
}

func LoadNearPins(path string) (GatewayModelPins, error) {
	if path == "" {
		return NearPins(), nil
	}
	return readPins(path, ParseNearPins)
}

func LoadTinfoilPins(path string) (RouterPins, error) {
	if path == "" {
		return TinfoilPins(), nil
	}
	return readPins(path, ParseTinfoilPins)
}
