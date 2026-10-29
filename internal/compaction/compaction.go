package compaction

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"
)

//go:embed prompt.md
var prompt string

//go:embed summary_prefix.md
var summaryPrefix string

const (
	Version          = "2026-10-05"
	OutputLimit      = 16384
	PromptOverhead   = 2048
	SummaryReserve   = OutputLimit + PromptOverhead
	MaxOutputReserve = 32768
	ThresholdPercent = 80
)

const (
	publishedWords = 3000
	// The rest of the limit is room for the model's reasoning, which counts against max_tokens and took up to 55%
	// of a 3,000-token limit on ling at minimal effort.
	summaryShare          = 40
	wordsPerHundredTokens = 75
	fewestWords           = 100
)

func Prompt() string { return PromptWithin(0) }

func PromptWithin(maxTokens int) string {
	words := publishedWords
	if maxTokens > 0 {
		summaryTokens := min(maxTokens, OutputLimit) * summaryShare / 100
		words = summaryTokens * wordsPerHundredTokens / 100
		words = min(max(words/100*100, fewestWords), publishedWords)
	}
	return strings.TrimSpace(strings.Replace(prompt, "{{words}}", grouped(words), 1))
}

func grouped(n int) string {
	if n < 1000 {
		return strconv.Itoa(n)
	}
	return fmt.Sprintf("%d,%03d", n/1000, n%1000)
}

func SummaryPrefix() string { return summaryPrefix }

// CharacterThreshold is where a character chat compacts in a character window of contextTokens, which holds the
// prompt alone: early enough that the compaction request, the conversation and its instruction, fits the window.
func CharacterThreshold(contextTokens int) int {
	return min(contextTokens*ThresholdPercent/100, contextTokens-PromptOverhead)
}

func Threshold(contextTokens, defaultMaxTokens int) int {
	room := contextTokens - min(defaultMaxTokens, MaxOutputReserve) - SummaryReserve
	return min(contextTokens*ThresholdPercent/100, room)
}
