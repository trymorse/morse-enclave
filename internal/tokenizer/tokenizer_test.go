package tokenizer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"
)

var pinned = map[string]string{
	"glm-5":       "19e773648cb4e65de8660ea6365e10acca112d42a854923df93db4a6f333a82d",
	"deepseek-v4": "c90dfa01249db1be4245780a052ede752e1361c612ac6d08e2bdada7d599476b",
	"kimi-k3":     "b6c497a7469b33ced9c38afb1ad6e47f03f5e5dc05f15930799210ec050c5103",
	"o200k":       "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d",
}

func TestEveryEmbeddedTokenizerIsThePinnedFile(t *testing.T) {
	for name, src := range sources {
		data, err := decompressed(src.file)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != pinned[name] {
			t.Errorf("%s decompresses to sha256 %s, want the pinned %s", name, got, pinned[name])
		}
	}
	if len(pinned) != len(sources) {
		t.Errorf("%d pins for %d tokenizers", len(pinned), len(sources))
	}
}

func TestTheLongestTokenOfEachVocabularyIsTheDocumentedOne(t *testing.T) {
	longest := map[string]int{"glm-5": 512, "deepseek-v4": 128, "kimi-k3": 256, "o200k": 128}
	for name := range sources {
		tk, err := Load(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := tk.LongestToken(); got != longest[name] {
			t.Errorf("%s: longest token is %d bytes, want the documented %d", name, got, longest[name])
		}
	}
}

var referenceTexts = []string{
	"Lighthouses have guided sailors safely to shore for centuries.",
	"def fib(n):\n    return n if n < 2 else fib(n-1) + fib(n-2)\n",
	"灯塔守护着航海者。The keeper's log—«nuit calme»—ends 🌊🌊 at 03:14.",
	"  multiple   spaces\n\n\ttabs and CAPS'LL don't'VE 12345678",
}

// From the Hugging Face tokenizers library (encode without special tokens) and tiktoken's
// encode_ordinary on the same files, 2026-10-04.
var reference = map[string]struct {
	counts   []int
	firstIDs []int
}{
	"glm-5":       {[]int{12, 24, 28, 21}, []int{127328, 105044, 98435, 117737, 98412, 1773}},
	"deepseek-v4": {[]int{12, 24, 29, 20}, []int{120077, 32993, 902, 89704, 1027, 320}},
	"kimi-k3":     {[]int{12, 24, 30, 19}, []int{89735, 142729, 72586, 785, 292, 1008}},
	"o200k":       {[]int{12, 24, 31, 18}, []int{90649, 70775, 55952, 29506, 17374, 21610}},
}

func TestEachTokenizerEncodesLikeItsReferenceLibrary(t *testing.T) {
	for name, want := range reference {
		tok, err := Load(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i, text := range referenceTexts {
			if n, _ := tok.Count(context.Background(), text); n != want.counts[i] {
				t.Errorf("%s counts %d tokens in text %d, the reference library %d", name, n, i, want.counts[i])
			}
		}
		if ids := tok.tokenIDs(referenceTexts[2]); !slices.Equal(ids[:min(6, len(ids))], want.firstIDs) {
			t.Errorf("%s encodes the mixed-script text as %v..., the reference library as %v...", name, ids[:min(6, len(ids))], want.firstIDs)
		}
	}
	if len(reference) != len(sources) {
		t.Errorf("%d references for %d tokenizers", len(reference), len(sources))
	}
}
