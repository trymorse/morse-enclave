package completions

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"

	"morse/backend/internal/jsonx"
)

const stateVersion = 1

type ReasoningState struct {
	Layout string
	Items  []json.RawMessage
	Texts  []int
}

type stateWire struct {
	Version int               `json:"v"`
	Binding string            `json:"for"`
	Layout  string            `json:"layout"`
	Items   []json.RawMessage `json:"items"`
	Texts   []int             `json:"texts,omitempty"`
}

func stateBinding(endpoint, model string) string {
	sum := sha256.Sum256([]byte(endpoint + "\x00" + model))
	return hex.EncodeToString(sum[:8])
}

func encodeState(endpoint, model string, s ReasoningState) string {
	wire := stateWire{Version: stateVersion, Binding: stateBinding(endpoint, model), Layout: s.Layout, Items: s.Items, Texts: s.Texts}
	return base64.RawURLEncoding.EncodeToString(jsonx.Encode(wire))
}

func (c Conversation) StateOf(t Turn, model string) (ReasoningState, bool) {
	if !c.CarryReasoning || t.Role != Assistant || t.ReasoningState == "" {
		return ReasoningState{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(t.ReasoningState)
	if err != nil {
		return ReasoningState{}, false
	}
	var wire stateWire
	if json.Unmarshal(raw, &wire) != nil || wire.Version != stateVersion || wire.Binding != stateBinding(c.Endpoint, model) || len(wire.Items) == 0 {
		return ReasoningState{}, false
	}
	return ReasoningState{Layout: wire.Layout, Items: wire.Items, Texts: wire.Texts}, true
}

func (c Conversation) withoutReasoningStates() Conversation {
	c.Turns = slices.Clone(c.Turns)
	for i := range c.Turns {
		c.Turns[i].ReasoningState = ""
	}
	return c
}
