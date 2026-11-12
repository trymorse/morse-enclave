package catalog

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"morse/backend/internal/enum"
)

// Quantization is the numeric precision a host publishes for the weights it serves a chat model at, in the names
// OpenRouter gives them (https://openrouter.ai/docs/guides/routing/provider-selection, "Quantization Levels").
// QuantizationUnknown is a host that publishes none, as no host of a closed model does. The order is OpenRouter's:
// integers, then floats, each fewest bits first, and unknown last, the order a list of them is shown in.
type Quantization uint8

const (
	QuantizationInt4 Quantization = iota + 1
	QuantizationInt8
	QuantizationFP4
	QuantizationMXFP4
	QuantizationNVFP4
	QuantizationFP6
	QuantizationFP8
	QuantizationMXFP8
	QuantizationFP16
	QuantizationBF16
	QuantizationFP32
	QuantizationUnknown
)

var quantizationNames = enum.Names[Quantization]{
	QuantizationInt4:    "int4",
	QuantizationInt8:    "int8",
	QuantizationFP4:     "fp4",
	QuantizationMXFP4:   "mxfp4",
	QuantizationNVFP4:   "nvfp4",
	QuantizationFP6:     "fp6",
	QuantizationFP8:     "fp8",
	QuantizationMXFP8:   "mxfp8",
	QuantizationFP16:    "fp16",
	QuantizationBF16:    "bf16",
	QuantizationFP32:    "fp32",
	QuantizationUnknown: "unknown",
}

// families are the precisions an asked name admits beyond itself: OpenRouter's fp4 takes the microscaling and NVIDIA
// 4-bit floats, and its fp8 the microscaling 8-bit float, as its provider routing guide lists them under
// "Quantization Levels": https://openrouter.ai/docs/guides/routing/provider-selection
var families = map[Quantization][]Quantization{
	QuantizationFP4: {QuantizationMXFP4, QuantizationNVFP4},
	QuantizationFP8: {QuantizationMXFP8},
}

func ParseQuantization(name string) (Quantization, error) {
	q, ok := quantizationNames.Parse(name)
	if !ok {
		return 0, fmt.Errorf("quantization %q must be one of %s", name, QuantizationNames())
	}
	return q, nil
}

func QuantizationNames() string { return quantizationNames.List() }

func (q Quantization) String() string { return quantizationNames.String(q) }

func (q Quantization) MarshalText() ([]byte, error) { return quantizationNames.MarshalText(q) }

// Quantizations is a set of precisions: the ones a request's provider.quantizations admits, or the ones a tier's hosts
// serve. The zero set is a request that names none, which admits every host.
type Quantizations uint16

// With is s with q added. A precision no route loads, the zero one, adds nothing.
func (s Quantizations) With(q Quantization) Quantizations {
	if !quantizationNames.Valid(q) {
		return s
	}
	return s | 1<<q
}

func (s Quantizations) Has(q Quantization) bool { return s&(1<<q) != 0 }

func (s Quantizations) Set() bool { return s != 0 }

// Admits is whether a host serving at q may serve a request whose provider.quantizations is s. A host whose precision
// is unknown qualifies only when s names unknown, as on OpenRouter.
func (s Quantizations) Admits(q Quantization) bool {
	if !s.Set() || s.Has(q) {
		return true
	}
	for asked, members := range families {
		if s.Has(asked) && slices.Contains(members, q) {
			return true
		}
	}
	return false
}

// Values lists the set's precisions in Quantization order.
func (s Quantizations) Values() []Quantization {
	return slices.DeleteFunc(quantizationNames.Values(), func(q Quantization) bool { return !s.Has(q) })
}

// MarshalJSON lists the set as an array of names, in Values order.
func (s Quantizations) MarshalJSON() ([]byte, error) { return json.Marshal(s.Values()) }

func (s Quantizations) String() string {
	var names []string
	for _, q := range s.Values() {
		names = append(names, q.String())
	}
	return strings.Join(names, ", ")
}
