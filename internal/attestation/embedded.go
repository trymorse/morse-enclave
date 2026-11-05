package attestation

import (
	_ "embed"
	"sync"
)

//go:embed phala_pins.json
var phalaPinsJSON []byte

//go:embed near_pins.json
var nearPinsJSON []byte

//go:embed tinfoil_pins.json
var tinfoilPinsJSON []byte

var (
	phalaPins   = sync.OnceValue(func() IdentityPins { return mustParse("phala_pins.json", phalaPinsJSON, ParseIdentityPins) })
	nearPins    = sync.OnceValue(func() GatewayModelPins { return mustParse("near_pins.json", nearPinsJSON, ParseNearPins) })
	tinfoilPins = sync.OnceValue(func() RouterPins { return mustParse("tinfoil_pins.json", tinfoilPinsJSON, ParseTinfoilPins) })
)

func PhalaPins() IdentityPins { return phalaPins() }

func NearPins() GatewayModelPins { return nearPins() }

func TinfoilPins() RouterPins { return tinfoilPins() }

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

func mustParse[P any](name string, raw []byte, parse func([]byte) (P, error)) P {
	p, err := parse(raw)
	if err != nil {
		panic("attestation: embedded " + name + ": " + err.Error())
	}
	return p
}
