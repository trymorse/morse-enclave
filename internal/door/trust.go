package door

import (
	"morse/backend/internal/pinsig"
	"morse/backend/internal/sigstore/rekorv2"
	"morse/backend/internal/sigstore/tuf"
)

type Trust struct {
	Root     pinsig.TrustRoot
	Identity pinsig.Identity
	// Witnesses count the cosignatures on the door's own record and on every
	// statement Identity signs, which pinsig takes from Rekor v2 only.
	Witnesses rekorv2.WitnessPolicy
	// TUFRoot is the Sigstore TUF root.json the door walks forward from.
	TUFRoot []byte
}

// pinsSigner is the public sign.yml of trymorse/morse-pins. It signs image
// statements and the vendor statement to Rekor v2 only, so the image never
// trusts the signer of Morse's private pins and never accepts a v1
// statement. The IDs are the repository's and its owner's, from gh api
// repos/trymorse/morse-pins on 2026-11-09, so a renamed or recreated
// repository fails.
var pinsSigner = pinsig.Identity{
	Issuer:              "https://token.actions.githubusercontent.com",
	SourceRepositoryURI: "https://github.com/trymorse/morse-pins",
	SourceRepositoryID:  "1437511167",
	SourceOwnerID:       "345029672",
	Workflow:            ".github/workflows/sign.yml",
	Ref:                 pinsig.ExactRef("refs/heads/main"),
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
	return Trust{Root: root, Identity: pinsSigner, Witnesses: policy, TUFRoot: tuf.SigstoreRoot()}, nil
}
