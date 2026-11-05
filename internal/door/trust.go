package door

import (
	"morse/backend/internal/pinsig"
	"morse/backend/internal/sigstore/rekorv2"
)

type Trust struct {
	Root      pinsig.TrustRoot
	Identity  pinsig.Identity
	Witnesses rekorv2.WitnessPolicy
}

const pinsWorkflow = "https://github.com/Watermark-Labs/pins/.github/workflows/sign.yml@refs/heads/main"

var pinsSigner = pinsig.Identity{
	Issuer:              "https://token.actions.githubusercontent.com",
	BuildSignerURI:      pinsWorkflow,
	BuildConfigURI:      pinsWorkflow,
	SourceRepositoryURI: "https://github.com/Watermark-Labs/pins",
	SourceRepositoryID:  "1405118053",
	SourceOwnerID:       "334112171",
	Ref:                 "refs/heads/main",
	Triggers:            []string{"push", "schedule"},
}

const witnessK = 3

// All four are staging or test tier. Sigstore's TUF repository carries no
// witness keys, so a change here needs a new image.
var witnesses = []struct{ vkey, operator string }{
	{"krabbel.ct.ipng.ch+4b10dbd8+BO4sLOtnhktlqMCejDx9C5LDd+/xZxbmBb6BP9ZD2Def", "IPng Networks"},
	{"staging.witness.transparency.goog/ring-any-bells+2e1a8dc9+BG5JTpLc3FJtwzgh1Uv+Qelz9qeOH2bfWjS1s0s+y4rL", "TrustFabric"},
	{"witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv", "Mullvad VPN"},
	{"witness.navigli.sunlight.geomys.org+a3e00fe2+BNy/co4C1Hn1p+INwJrfUlgz7W55dSZReusH/GhUhJ/G", "Geomys"},
}

func witnessPolicy() (rekorv2.WitnessPolicy, error) {
	var parsed []rekorv2.Witness
	for _, w := range witnesses {
		p, err := rekorv2.ParseWitness(w.vkey, w.operator)
		if err != nil {
			return rekorv2.WitnessPolicy{}, err
		}
		parsed = append(parsed, p)
	}
	return rekorv2.NewWitnessPolicy(witnessK, parsed...)
}

func Production() (Trust, error) {
	root, err := pinsig.PublicGood()
	if err != nil {
		return Trust{}, err
	}
	policy, err := witnessPolicy()
	if err != nil {
		return Trust{}, err
	}
	return Trust{Root: root, Identity: pinsSigner, Witnesses: policy}, nil
}
