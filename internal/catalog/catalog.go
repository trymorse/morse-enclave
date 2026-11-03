package catalog

import (
	"encoding/json"
	"fmt"
	"strings"

	"morse/backend/internal/enum"
)

type ModelID string

type EndpointID string

type Tier uint8

const (
	Anon Tier = iota + 1
	Private
	TEE
	E2EE
)

var tierNames = enum.Names[Tier]{Anon: "anon", Private: "private", TEE: "tee", E2EE: "e2ee"}

func ParseTier(name string) (Tier, error) {
	t, ok := tierNames.Parse(name)
	if !ok {
		return 0, fmt.Errorf("tier %q must be one of %s", name, TierNames())
	}
	return t, nil
}

func (t Tier) Valid() bool { return tierNames.Valid(t) }

func (t Tier) String() string { return tierNames.String(t) }

func (t Tier) MarshalText() ([]byte, error) { return tierNames.MarshalText(t) }

type tierTerms struct {
	attested bool
	sealed   bool
}

var tierTable = [...]tierTerms{
	Anon:    {},
	Private: {},
	TEE:     {attested: true},
	E2EE:    {attested: true, sealed: true},
}

func Tiers() []Tier { return tierNames.Values() }

func TierNames() string { return tierNames.List() }

func (t Tier) Attested() bool { return t.Valid() && tierTable[t].attested }

func (t Tier) Sealed() bool { return t.Valid() && tierTable[t].sealed }

func (t Tier) Serves(k Kind) bool {
	return t.Valid() && (!t.Attested() || k.Attestable() && (!t.Sealed() || k.Sealable()))
}

// Relay is how a chat route's body reaches its vendor. A plaintext relay reads and rewrites it. A verbatim relay
// forwards the client's sealed body as sent, so only a sealed tier serves one.
type Relay uint8

const (
	Plaintext Relay = iota + 1
	Verbatim
)

func (r Relay) Validate(tier Tier) error {
	switch {
	case r == Plaintext && tier.Sealed():
		return fmt.Errorf("is tier %s and serves a plaintext provider, which cannot relay the client's sealed body", tier)
	case r == Verbatim && !tier.Sealed():
		return fmt.Errorf("is tier %s and relays verbatim, which only tier %s serves", tier, E2EE)
	}
	return nil
}

type Kind uint8

const (
	KindChat Kind = iota
	KindImage
	KindVideo
	KindSearch
	KindFetch
	KindResearch
	KindTranscription
)

var kindNames = enum.Names[Kind]{KindChat: "chat", KindImage: "image", KindVideo: "video", KindSearch: "search", KindFetch: "fetch", KindResearch: "research", KindTranscription: "transcription"}

type kindTerms struct {
	attestable bool
	sealable   bool
}

var kindTable = [...]kindTerms{
	KindChat:          {attestable: true, sealable: true},
	KindTranscription: {attestable: true},
}

func (k Kind) Attestable() bool { return int(k) < len(kindTable) && kindTable[k].attestable }

func (k Kind) Sealable() bool { return int(k) < len(kindTable) && kindTable[k].sealable }

func (k Kind) String() string { return kindNames.String(k) }

func Kinds() []Kind { return kindNames.Values() }

func (k Kind) MarshalText() ([]byte, error) { return kindNames.MarshalText(k) }

func (k *Kind) UnmarshalText(text []byte) error {
	kind, ok := kindNames.Parse(string(text))
	if !ok {
		return fmt.Errorf("kind %q must be one of %s", text, kindNames.List())
	}
	*k = kind
	return nil
}

type Retention uint8

const (
	RetentionVendor Retention = iota + 1
	RetentionZDR
)

var retentionNames = enum.Names[Retention]{RetentionVendor: "vendor", RetentionZDR: "zdr"}

func ParseRetention(name string) (Retention, error) {
	r, ok := retentionNames.Parse(name)
	if !ok {
		return 0, fmt.Errorf("retention %q must be %s or %s", name, RetentionVendor, RetentionZDR)
	}
	return r, nil
}

func (r Retention) String() string { return retentionNames.String(r) }

func (r Retention) MarshalText() ([]byte, error) { return retentionNames.MarshalText(r) }

type Modality uint8

const (
	ModalityText Modality = iota
	ModalityImage
)

var modalityNames = enum.Names[Modality]{ModalityText: "text", ModalityImage: "image"}

func (m Modality) String() string { return modalityNames.String(m) }

type ChatTerms struct {
	MaxOutputTokens        int
	DefaultMaxTokens       int
	DefaultReasoningEffort string
	ReasoningEfforts       []string
	Inputs                 Inputs
	ContextTokens          int
	CompactAtTokens        int
	HidesReasoning         bool
}

type Inputs uint8

func ParseInputs(names []string) (Inputs, error) {
	if names == nil {
		return 0, nil
	}
	var named Inputs
	for _, name := range names {
		m, ok := modalityNames.Parse(name)
		switch {
		case !ok:
			return 0, fmt.Errorf("input_modalities names %q, and each must be one of %s", name, modalityNames.List())
		case named&(1<<m) != 0:
			return 0, fmt.Errorf("input_modalities names %s twice", m)
		}
		named |= 1 << m
	}
	if named&(1<<ModalityText) == 0 {
		return 0, fmt.Errorf("input_modalities must include %s, which every chat model reads", ModalityText)
	}
	return named &^ (1 << ModalityText), nil
}

func (in Inputs) Reads(m Modality) bool {
	return m == ModalityText || modalityNames.Valid(m) && in&(1<<m) != 0
}

func (in Inputs) TextOnly() bool { return in == 0 }

func (in Inputs) Names() []string {
	var names []string
	for i, name := range modalityNames {
		if in.Reads(Modality(i)) {
			names = append(names, name)
		}
	}
	return names
}

func (in Inputs) String() string { return strings.Join(in.Names(), ", ") }

func (in Inputs) MarshalJSON() ([]byte, error) { return json.Marshal(in.Names()) }
