package compaction

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"testing"
)

func TestThresholdIsEightyPercentOfTheWindowWhenTheReservesFit(t *testing.T) {
	if got := Threshold(1_000_000, 32768); got != 800_000 {
		t.Errorf("threshold %d, want 800000", got)
	}
}

func TestThresholdDropsSoTheOutputAndTheSummaryCallStillFit(t *testing.T) {
	cases := map[string]struct{ window, defaultMax, want int }{
		"a 128K window with a 32K default": {128_000, 32768, 128_000 - 32768 - SummaryReserve},
		"a default above the reserve cap":  {200_000, 128_000, 200_000 - MaxOutputReserve - SummaryReserve},
		"a window too small to compact":    {40_000, 32768, 40_000 - 32768 - SummaryReserve},
	}
	for name, c := range cases {
		got := Threshold(c.window, c.defaultMax)
		if got != c.want {
			t.Errorf("%s: threshold %d, want %d", name, got, c.want)
		}
		if got > 0 && got+min(c.defaultMax, MaxOutputReserve)+SummaryReserve > c.window {
			t.Errorf("%s: threshold %d leaves no room for the reply and the summary call", name, got)
		}
	}
}

func TestThePromptFitsTheOverheadTheReserveAllowsForItAtTwoBytesAToken(t *testing.T) {
	if n := len(Prompt()) + len(SummaryPrefix()); n > 2*PromptOverhead {
		t.Errorf("prompt and prefix are %d bytes, over the %d-byte overhead", n, 2*PromptOverhead)
	}
}

func TestThePromptAsksForTextInsideASummaryBlockAndForbidsTools(t *testing.T) {
	p := Prompt()
	for _, want := range []string{"<summary></summary>", "Do not call tools", "earlier checkpoint", "image or audio", "file attached", "name tools read it by"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt lacks %q", want)
		}
	}
}

func TestTheSummaryPrefixEndsWithABlankLineBeforeTheSummary(t *testing.T) {
	if p := SummaryPrefix(); !strings.HasSuffix(p, ".\n\n") || strings.TrimSpace(p) == "" {
		t.Errorf("prefix %q", p)
	}
}

func TestTheInstructionAsksForASummaryThatLeavesRoomForReasoningInsideTheClientsLimit(t *testing.T) {
	cases := map[int]string{
		5000:        "Use at most about 1,500 words.",
		4999:        "Use at most about 1,400 words.",
		3000:        "Use at most about 900 words.",
		2000:        "Use at most about 600 words.",
		200:         "Use at most about 100 words.",
		10000:       "Use at most about 3,000 words.",
		16384:       "Use at most about 3,000 words.",
		math.MaxInt: "Use at most about 3,000 words.",
		0:           "Use at most about 3,000 words.",
	}
	for maxTokens, want := range cases {
		got := PromptWithin(maxTokens)
		if !strings.HasSuffix(got, want) || strings.Contains(got, "{{") {
			t.Errorf("the instruction within %d tokens ends %q, want %q", maxTokens, got[strings.LastIndex(got, ". ")+2:], want)
		}
	}
	if p := Prompt(); !strings.HasSuffix(p, "Use at most about 3,000 words.") {
		t.Errorf("the published instruction ends %q, want the 3,000-word limit", p[strings.LastIndex(p, ". ")+2:])
	}
}

func TestThePublishedInstructionIsTheTextItsVersionNames(t *testing.T) {
	const pinned = "0b7be20da4b8387c835ba6a2fc7394b9392235c8458f648dce7652524d30d224"
	sum := sha256.Sum256([]byte(Prompt()))
	if got := hex.EncodeToString(sum[:]); got != pinned {
		t.Errorf("the published instruction hashes to %s, not the text Version %s names; when the instruction changes on purpose, bump Version and update the pin", got, Version)
	}
}
