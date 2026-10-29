package e2ee

import (
	"bytes"
	"strings"
	"testing"
)

func TestPadCommentIsOneSSECommentLineAndStripRemovesOnlyExactPads(t *testing.T) {
	stream := "data: {\"id\":\"c1\",\"delta\":\": wm-pad ABCDEFGHIJKLMNOPQRST\"}\n\n: wm-pad short\n: keepalive\n\ndata: [DONE]\n\n"
	padded := string(PadComment("ABCDEFGHIJKLMNOP")) + "data: {\"id\":\"c1\",\"delta\":\": wm-pad ABCDEFGHIJKLMNOPQRST\"}\n" +
		string(PadComment(strings.Repeat("z", 64))) + "\n: wm-pad short\n: keepalive\n\n" + string(PadComment("0123456789abcdefGHIJ")) + "data: [DONE]\n\n" + string(PadComment(strings.Repeat("Q", 40)))
	if got := string(StripPadComments([]byte(padded))); got != stream {
		t.Errorf("stripped\n%q\nwant\n%q", got, stream)
	}
	if string(PadComment("ABCDEFGHIJKLMNOP")) != ": wm-pad ABCDEFGHIJKLMNOP\n" {
		t.Errorf("pad line %q", PadComment("ABCDEFGHIJKLMNOP"))
	}
	for _, kept := range []string{": wm-pad " + strings.Repeat("a", 15) + "\n", ": wm-pad " + strings.Repeat("a", 65) + "\n", ": wm-pad abc def ghi jkl mno\n", ":wm-pad abcdefghijklmnop\n", ": wm-pad abcdefghijklmnop"} {
		if got := StripPadComments([]byte(kept)); !bytes.Equal(got, []byte(kept)) {
			t.Errorf("StripPadComments(%q) = %q, want it kept", kept, got)
		}
	}
}
