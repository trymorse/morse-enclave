package attester

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"morse/backend/internal/baseurl"
)

type Upstream struct {
	BaseURL string
	Host    string
	Model   string
	APIKey  string
}

type Vendor struct {
	Name           string
	Gateway        string
	KeyEnv         string
	sealedChatOnly bool
	transcribes    bool
}

var Phala = &Vendor{Name: "phala", Gateway: "https://inference.phala.com", KeyEnv: "PHALA_API_KEY"}

var Near = &Vendor{Name: "near", Gateway: "https://cloud-api.near.ai", KeyEnv: "NEAR_API_KEY", sealedChatOnly: true, transcribes: true}

var vendors = []*Vendor{Phala, Near}

var ErrUnknown = errors.New("unknown attester")

func Vendors() []*Vendor { return slices.Clone(vendors) }

func Parse(name string) (*Vendor, error) {
	if i := slices.IndexFunc(vendors, func(v *Vendor) bool { return v.Name == name }); i >= 0 {
		return vendors[i], nil
	}
	return nil, fmt.Errorf("%w %q: must be one of %v", ErrUnknown, name, vendors)
}

func (v *Vendor) String() string { return v.Name }

// SealedChatOnly is whether the gateway serves only chats the client sealed to the model's key, so none at tee.
func (v *Vendor) SealedChatOnly() bool { return v.sealedChatOnly }

// Transcribes is whether the gateway serves an attested transcription model, which it reads in the clear.
func (v *Vendor) Transcribes() bool { return v.transcribes }

func (v *Vendor) At(gateway string) (Upstream, error) {
	gateway = cmp.Or(gateway, v.Gateway)
	u, err := baseurl.Parse("gateway", v.Gateway, gateway)
	if err != nil {
		return Upstream{}, err
	}
	return Upstream{BaseURL: strings.TrimRight(gateway, "/"), Host: u.Hostname()}, nil
}
