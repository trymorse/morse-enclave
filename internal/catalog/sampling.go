package catalog

import (
	"encoding/json"
	"fmt"

	"morse/backend/internal/enum"
)

type SamplingSetting uint8

const (
	FrequencyPenalty SamplingSetting = iota
	LogitBias
	MinP
	PresencePenalty
	RepetitionPenalty
	TopK
)

var samplingNames = enum.Names[SamplingSetting]{FrequencyPenalty: "frequency_penalty", LogitBias: "logit_bias", MinP: "min_p",
	PresencePenalty: "presence_penalty", RepetitionPenalty: "repetition_penalty", TopK: "top_k"}

func ParseSamplingSetting(name string) (SamplingSetting, bool) { return samplingNames.Parse(name) }

func SamplingSettings() []string {
	var names []string
	for _, s := range samplingNames.Values() {
		names = append(names, s.String())
	}
	return names
}

func (s SamplingSetting) String() string { return samplingNames.String(s) }

type Sampling uint8

func ParseSampling(names []string) (Sampling, error) {
	var taken Sampling
	last := -1
	for _, name := range names {
		s, ok := samplingNames.Parse(name)
		switch {
		case !ok:
			return 0, fmt.Errorf("sampling names %q, and each must be one of %s", name, samplingNames.List())
		case int(s) <= last:
			return 0, fmt.Errorf("sampling must name each of %s at most once, in that order", samplingNames.List())
		}
		last = int(s)
		taken |= 1 << s
	}
	return taken, nil
}

func (ss Sampling) Takes(s SamplingSetting) bool {
	return samplingNames.Valid(s) && ss&(1<<s) != 0
}

func (ss Sampling) Names() []string {
	var names []string
	for _, s := range samplingNames.Values() {
		if ss.Takes(s) {
			names = append(names, s.String())
		}
	}
	return names
}

func (ss Sampling) MarshalJSON() ([]byte, error) { return json.Marshal(ss.Names()) }
