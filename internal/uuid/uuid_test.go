package uuid

import "testing"

func TestParseAcceptsEitherCase(t *testing.T) {
	for _, c := range []struct {
		s      string
		parses bool
	}{
		{"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", true},
		{"0190A1B2-C3D4-7E5F-8A9B-0C1D2E3F4A5B", true},
		{"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a-b", false},
		{"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f-a-b", false},
		{"0190a1b2c3d4-7e5f-8a9b-0c1d2e3f4a5b-", false},
		{"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5", false},
		{"0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5g", false},
		{"", false},
	} {
		id, ok := Parse(c.s)
		if ok != c.parses {
			t.Errorf("%q: parses %v, want %v", c.s, ok, c.parses)
		}
		if ok && Format(id) != "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b" {
			t.Errorf("%q formats as %s", c.s, Format(id))
		}
	}
}

func TestNewIsARandomVersion4UUID(t *testing.T) {
	a, b := New(), New()
	if a == b || a[6]>>4 != 4 || a[8]>>6 != 2 {
		t.Errorf("%s %s", Format(a), Format(b))
	}
}
