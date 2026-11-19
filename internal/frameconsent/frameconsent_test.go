package frameconsent

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
)

func TestADigestIsWrittenAndReadAsTheLowercaseHexOfItsSHA256(t *testing.T) {
	d := Of([]byte("frame"))
	if d != sha256.Sum256([]byte("frame")) {
		t.Fatal("Of is not SHA-256")
	}
	raw, err := json.Marshal(d)
	if err != nil || string(raw) != `"`+d.String()+`"` || strings.ToLower(d.String()) != d.String() || len(d.String()) != 64 {
		t.Fatalf("marshalled %s err %v", raw, err)
	}
	var back Digest
	if err := json.Unmarshal(raw, &back); err != nil || back != d {
		t.Errorf("read back %v err %v", back, err)
	}
	for _, bad := range []string{"", d.String()[:63], strings.ToUpper(d.String()), d.String() + "0", strings.Repeat("g", 64), " " + d.String()[1:]} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) took it", bad)
		}
	}
}

func TestTheFirstFrameWithoutConsentIsNamed(t *testing.T) {
	first, last := Of([]byte("first")), Of([]byte("last"))
	for name, c := range map[string]struct {
		frames, consented []Digest
		frame             int
		missing           bool
	}{
		"none asked":        {nil, nil, 0, false},
		"both consented":    {[]Digest{first, last}, []Digest{last, first}, 0, false},
		"first missing":     {[]Digest{first, last}, []Digest{last}, 0, true},
		"last missing":      {[]Digest{first, last}, []Digest{first}, 1, true},
		"identical frames":  {[]Digest{first, first}, []Digest{first}, 0, false},
		"nothing consented": {[]Digest{first}, nil, 0, true},
	} {
		if frame, missing := Missing(c.frames, c.consented); frame != c.frame || missing != c.missing {
			t.Errorf("%s: frame %d missing %v, want %d %v", name, frame, missing, c.frame, c.missing)
		}
	}
	if Required(0).Error() != ErrRequired.Error() || ErrRequired.Naming("image") != Required(0) || ErrRequired.Naming("last_image") != Required(1) {
		t.Errorf("Required names %v and %v, want image and last_image", Required(0), Required(1))
	}
}
