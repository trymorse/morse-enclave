package catalog

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestEveryTierAndRetentionKeepsItsWireName(t *testing.T) {
	for name, want := range map[string]Tier{"anon": Anon, "private": Private, "tee": TEE, "e2ee": E2EE} {
		got, err := ParseTier(name)
		if err != nil || got != want {
			t.Errorf("ParseTier(%q) = %v, %v", name, got, err)
		}
		if out, err := json.Marshal(want); err != nil || string(out) != `"`+name+`"` {
			t.Errorf("%s marshals as %s, %v", name, out, err)
		}
	}
	for name, want := range map[string]Retention{"vendor": RetentionVendor, "zdr": RetentionZDR} {
		got, err := ParseRetention(name)
		if err != nil || got != want {
			t.Errorf("ParseRetention(%q) = %v, %v", name, got, err)
		}
		if out, err := json.Marshal(want); err != nil || string(out) != `"`+name+`"` {
			t.Errorf("%s marshals as %s, %v", name, out, err)
		}
	}
}

func TestOnlyEnclaveTiersAreAttestedOnlyE2EEIsSealedAndAnAttestedTierServesOnlyChatAndTEETranscription(t *testing.T) {
	type terms struct {
		attested, sealed bool
		kinds            []Kind
	}
	every := Kinds()
	want := map[Tier]terms{
		Anon:    {false, false, every},
		Private: {false, false, every},
		TEE:     {true, false, []Kind{KindChat, KindTranscription}},
		E2EE:    {true, true, []Kind{KindChat}},
		Tier(0): {false, false, nil},
		Tier(9): {false, false, nil},
	}
	for tier, w := range want {
		var kinds []Kind
		for _, k := range every {
			if tier.Serves(k) {
				kinds = append(kinds, k)
			}
		}
		got := terms{tier.Attested(), tier.Sealed(), kinds}
		if got.attested != w.attested || got.sealed != w.sealed || !slices.Equal(got.kinds, w.kinds) {
			t.Errorf("tier %d is %+v, want %+v", tier, got, w)
		}
	}
	if got := Tiers(); !slices.Equal(got, []Tier{Anon, Private, TEE, E2EE}) {
		t.Errorf("Tiers() = %v", got)
	}
}

func TestInputModalitiesParseToTheSetAChatModelReadsAndMarshalInTableOrder(t *testing.T) {
	for name, c := range map[string]struct {
		names []string
		image bool
		list  string
	}{
		"absent":            {nil, false, `["text"]`},
		"text":              {[]string{"text"}, false, `["text"]`},
		"text and image":    {[]string{"text", "image"}, true, `["text","image"]`},
		"image named first": {[]string{"image", "text"}, true, `["text","image"]`},
	} {
		in, err := ParseInputs(c.names)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !in.Reads(ModalityText) || in.Reads(ModalityImage) != c.image || in.TextOnly() == c.image {
			t.Errorf("%s: reads text %t, image %t, text only %t", name, in.Reads(ModalityText), in.Reads(ModalityImage), in.TextOnly())
		}
		if out, err := json.Marshal(in); err != nil || string(out) != c.list {
			t.Errorf("%s marshals as %s, %v, want %s", name, out, err, c.list)
		}
	}
	var unset Inputs
	if out, _ := json.Marshal(struct {
		In Inputs `json:"in,omitempty"`
	}{unset}); string(out) != `{}` {
		t.Errorf("a text-only set under omitempty marshals as %s", out)
	}
	if unset.Reads(Modality(9)) {
		t.Error("a modality outside the table is read")
	}
}

func TestInputModalitiesRefuseAnUnknownNameARepeatAndAListWithoutText(t *testing.T) {
	for name, c := range map[string]struct {
		names []string
		want  string
	}{
		"unknown":      {[]string{"text", "audio"}, `input_modalities names "audio", and each must be one of text, image`},
		"wrong case":   {[]string{"Text"}, `input_modalities names "Text"`},
		"blank":        {[]string{"text", ""}, `input_modalities names ""`},
		"repeat":       {[]string{"text", "image", "image"}, `input_modalities names image twice`},
		"repeats text": {[]string{"text", "text"}, `input_modalities names text twice`},
		"no text":      {[]string{"image"}, `input_modalities must include text`},
		"empty":        {[]string{}, `input_modalities must include text`},
	} {
		if _, err := ParseInputs(c.names); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q", name, err, c.want)
		}
	}
}
