package routebounds

import (
	"reflect"
	"strings"
	"testing"

	"morse/backend/internal/catalog"
)

const (
	chat   = `{"id":"lab/chat","endpoints":[{"id":"a","provider":"a","base_url":"https://a.example","api_key_env":"A_API_KEY","tier":"private","upstream_model":"chat"}]}`
	open   = `{"id":"lab/open","endpoints":[{"id":"o","provider":"o","base_url":"https://o.example","api_key_env":"O_API_KEY","tier":"anon","upstream_model":"open"}]}`
	kept   = `{"id":"lab/kept","endpoints":[{"id":"z","provider":"z","base_url":"https://z.example","api_key_env":"Z_API_KEY","tier":"private","retention":"zdr","upstream_model":"kept"}]}`
	sealed = `{"id":"lab/sealed","endpoints":[{"id":"t","provider":"t","base_url":"https://t.example","api_key_env":"T_API_KEY","tier":"tee","attester":"t","upstream_model":"sealed"}]}`
	hosted = `{"id":"lab/hosted","endpoints":[{"id":"h","provider":"h","api_key_env":"H_API_KEY","tier":"tee","attester":"h","upstream_model":"hosted"}]}`
)

func file(models ...string) []byte {
	return []byte(`{"models":[` + strings.Join(models, ",") + `],"aliases":[]}` + "\n")
}

func edit(model string, pairs ...string) string {
	return strings.NewReplacer(pairs...).Replace(model)
}

func breaches(t *testing.T, boot, offered []byte) []Breach {
	t.Helper()
	image, err := Read(boot)
	if err != nil {
		t.Fatal(err)
	}
	next, err := Read(offered)
	if err != nil {
		t.Fatal(err)
	}
	return image.Breaches(next)
}

func TestARoutesFileStaysInsideItsBaseOnlyWhenNoRuleIsBroken(t *testing.T) {
	boot := file(chat, open, kept, sealed, hosted)
	for name, c := range map[string]struct {
		offered []byte
		want    []Breach
	}{
		"the base itself":              {boot, nil},
		"a new model on a served host": {file(chat, edit(chat, "lab/chat", "lab/chat-2", "chat", "chat-2"), open, kept, sealed, hosted), nil},
		"a removed model":              {file(chat, sealed), nil},
		"a removed attested endpoint":  {file(chat, open, kept), nil},
		"a new upstream model":         {file(edit(chat, `"upstream_model":"chat"`, `"upstream_model":"chat-v2"`), open, kept, sealed, hosted), nil},
		"a lower tier on a host":       {file(edit(chat, `"tier":"private"`, `"tier":"anon"`), open, kept, sealed, hosted), nil},
		"a dropped retention claim":    {file(chat, open, edit(kept, `"retention":"zdr",`, ``), sealed, hosted), nil},
		"an empty retention":           {file(edit(chat, `"tier":"private"`, `"tier":"private","retention":""`), open, kept, sealed, hosted), nil},
		"vendor retention spelled out": {file(edit(chat, `"tier":"private"`, `"tier":"private","retention":"vendor"`), open, kept, sealed, hosted), nil},
		"a plain endpoint beside an attested one of its host": {
			file(chat, open, kept, sealed, edit(sealed, "lab/sealed", "lab/plain", `"tier":"tee","attester":"t",`, `"tier":"private",`), hosted), nil},
		"a new key": {file(chat, edit(chat, "lab/chat", "lab/new", "A_API_KEY", "NEW_API_KEY"), open, kept, sealed, hosted),
			[]Breach{{NewValue, "api_key_env", []string{"NEW_API_KEY"}}, {NewPairing, "", []string{"lab/new a"}}}},
		"a new provider": {file(chat, edit(chat, "lab/chat", "lab/new", `"provider":"a"`, `"provider":"new"`), open, kept, sealed, hosted),
			[]Breach{{NewValue, "provider", []string{"new"}}, {NewPairing, "", []string{"lab/new a"}}}},
		"a new host": {file(chat, edit(chat, "lab/chat", "lab/new", "https://a.example", "https://new.example"), open, kept, sealed, hosted),
			[]Breach{{NewValue, "base_url", []string{"https://new.example"}}, {NewPairing, "", []string{"lab/new a"}}}},
		"a key, provider or host named outside any endpoint": {[]byte(`{"models":[` + chat + `,` + open + `,` + kept + `,` + sealed + `,` + hosted + `],"privacy_veil":{"base_url":"https://veil.example","nested":[{"api_key_env":"VEIL_API_KEY"}]}}`),
			[]Breach{{NewValue, "api_key_env", []string{"VEIL_API_KEY"}}, {NewValue, "base_url", []string{"https://veil.example"}}}},
		"a served key on another served host": {file(edit(chat, "https://a.example", "https://z.example"), open, kept, sealed, hosted),
			[]Breach{{NewPairing, "", []string{"lab/chat a"}}}},
		"a served key on a served host that claims less": {file(edit(chat, "https://a.example", "https://o.example"), open, kept, sealed, hosted),
			[]Breach{{NewPairing, "", []string{"lab/chat a"}}, {ClaimRaised, "", []string{"lab/chat a"}}}},
		"a served key with no host": {file(edit(chat, `"base_url":"https://a.example",`, ``), open, kept, sealed, hosted),
			[]Breach{{NewPairing, "", []string{"lab/chat a"}}}},
		"a new tee endpoint": {file(chat, open, kept, sealed, edit(sealed, "lab/sealed", "lab/sealed-2"), hosted),
			[]Breach{{AttestedChanged, "", []string{"lab/sealed-2 t"}}}},
		"a changed tee endpoint": {file(chat, open, kept, edit(sealed, `"upstream_model":"sealed"`, `"upstream_model":"sealed-v2"`), hosted),
			[]Breach{{AttestedChanged, "", []string{"lab/sealed t"}}}},
		"a tee endpoint with another attester": {file(chat, open, kept, edit(sealed, `"attester":"t"`, `"attester":"u"`), hosted),
			[]Breach{{AttestedChanged, "", []string{"lab/sealed t"}}}},
		"a tee endpoint with a field more": {file(chat, open, kept, edit(sealed, `"attester":"t"`, `"attester":"t","sealed_model":"s"`), hosted),
			[]Breach{{AttestedChanged, "", []string{"lab/sealed t"}}}},
		"a tee endpoint with a number respelled": {file(chat, open, kept, edit(sealed, `"attester":"t"`, `"attester":"t","context_tokens":1.0`), hosted),
			[]Breach{{AttestedChanged, "", []string{"lab/sealed t"}}}},
		"a tee endpoint made e2ee": {file(chat, open, kept, edit(sealed, `"tier":"tee"`, `"tier":"e2ee"`), hosted),
			[]Breach{{AttestedChanged, "", []string{"lab/sealed t"}}, {ClaimRaised, "", []string{"lab/sealed t"}}}},
		"a private endpoint made tee": {file(edit(chat, `"tier":"private"`, `"tier":"tee"`), open, kept, sealed, hosted),
			[]Breach{{AttestedChanged, "", []string{"lab/chat a"}}, {ClaimRaised, "", []string{"lab/chat a"}}}},
		"an anon host called private": {file(chat, edit(open, `"tier":"anon"`, `"tier":"private"`), kept, sealed, hosted),
			[]Breach{{ClaimRaised, "", []string{"lab/open o"}}}},
		"a new private model on an anon host": {file(chat, open, edit(open, "lab/open", "lab/open-2", `"tier":"anon"`, `"tier":"private"`), kept, sealed, hosted),
			[]Breach{{ClaimRaised, "", []string{"lab/open-2 o"}}}},
		"zdr claimed for a host that never had it": {file(edit(chat, `"tier":"private"`, `"tier":"private","retention":"zdr"`), open, kept, sealed, hosted),
			[]Breach{{ClaimRaised, "", []string{"lab/chat a"}}}},
		"a tier no release names": {file(edit(chat, `"tier":"private"`, `"tier":"secret"`), open, kept, sealed, hosted),
			[]Breach{{ClaimRaised, "", []string{"lab/chat a"}}}},
		"no tier": {file(edit(chat, `"tier":"private",`, ``), open, kept, sealed, hosted),
			[]Breach{{ClaimRaised, "", []string{"lab/chat a"}}}},
		"a retention no release names": {file(chat, open, edit(kept, `"retention":"zdr"`, `"retention":"never"`), sealed, hosted),
			[]Breach{{ClaimRaised, "", []string{"lab/kept z"}}}},
		"a retention that is not a string": {file(chat, open, edit(kept, `"retention":"zdr"`, `"retention":true`), sealed, hosted),
			[]Breach{{ClaimRaised, "", []string{"lab/kept z"}}}},
		"an e2ee endpoint with no host beside a tee one": {file(chat, open, kept, sealed, hosted, edit(hosted, "lab/hosted", "lab/hosted-2", `"tier":"tee"`, `"tier":"e2ee"`)),
			[]Breach{{AttestedChanged, "", []string{"lab/hosted-2 h"}}, {ClaimRaised, "", []string{"lab/hosted-2 h"}}}},
	} {
		if got := breaches(t, boot, c.offered); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
}

func TestAHostsCeilingIsTheMostAnyOfItsBaseEndpointsClaims(t *testing.T) {
	mixed := `{"id":"lab/mixed","endpoints":[` +
		`{"id":"m1","provider":"m","base_url":"https://m.example","api_key_env":"M_API_KEY","tier":"anon","upstream_model":"m"},` +
		`{"id":"m2","provider":"m","base_url":"https://m.example","api_key_env":"M_API_KEY","tier":"private","retention":"zdr","upstream_model":"m"}]}`
	boot := file(mixed)
	if got := breaches(t, boot, file(edit(mixed, `"tier":"anon"`, `"tier":"private","retention":"zdr"`))); got != nil {
		t.Errorf("an endpoint raised to what another of its host already claims: %v", got)
	}
	if got := breaches(t, boot, file(edit(mixed, `"tier":"anon"`, `"tier":"tee"`))); len(got) != 2 || got[1].Rule != ClaimRaised {
		t.Errorf("an endpoint raised above every claim of its host: %v", got)
	}
}

func TestEveryBreachSaysWhichRuleAndWhichNames(t *testing.T) {
	for _, b := range []Breach{{NewValue, "base_url", []string{"https://new.example"}}, {NewPairing, "", []string{"lab/chat a"}}, {AttestedChanged, "", []string{"lab/sealed t"}}, {ClaimRaised, "", []string{"lab/open o"}}, {Rule(99), "", []string{"lab/x y"}}} {
		if s := b.String(); !strings.Contains(s, b.Names[0]) || !strings.Contains(s, b.Key) {
			t.Errorf("rule %d describes itself as %q", b.Rule, s)
		}
	}
}

func TestARoutesFileThatIsNotOneObjectOfModelsWithEndpointObjectsIsNotRead(t *testing.T) {
	for name, raw := range map[string]string{
		"not JSON":                  `{`,
		"two values":                string(file(chat)) + `{}`,
		"a list":                    `[]`,
		"models not a list":         `{"models":{}}`,
		"a model not an object":     `{"models":["lab/chat"]}`,
		"an id not a string":        `{"models":[{"id":7,"endpoints":[]}]}`,
		"endpoints not a list":      `{"models":[{"id":"lab/chat","endpoints":{}}]}`,
		"an endpoint not an object": `{"models":[{"id":"lab/chat","endpoints":["a"]}]}`,
	} {
		if _, err := Read([]byte(raw)); err == nil {
			t.Errorf("%s: read without an error", name)
		}
	}
}

func TestTheRanksAreTheCatalogsTiersAndRetentionsLowestFirst(t *testing.T) {
	if got := catalog.Tiers(); !reflect.DeepEqual(got, []catalog.Tier{catalog.Anon, catalog.Private, catalog.TEE, catalog.E2EE}) {
		t.Errorf("the catalog's tiers are %v", got)
	}
	if !(catalog.Anon < catalog.Private && catalog.Private < catalog.TEE && catalog.TEE < catalog.E2EE && catalog.RetentionVendor < catalog.RetentionZDR) {
		t.Error("a claim is compared by its catalog value, which no longer rises with privacy")
	}
	for _, tier := range catalog.Tiers() {
		if want := tier == catalog.TEE || tier == catalog.E2EE; tier.Attested() != want {
			t.Errorf("tier %s attested %t, and the route rules and routes-guard.sh hold tee and e2ee alone to the attested rule", tier, tier.Attested())
		}
	}
}
