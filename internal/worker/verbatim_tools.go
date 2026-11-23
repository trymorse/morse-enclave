package worker

import (
	"encoding/json"

	"morse/backend/internal/chat"
	"morse/backend/internal/e2ee/near"
)

func verbatimField(field string, params chat.E2EE) (verbatimValue, bool) {
	if params.SealsTools() {
		switch field {
		case "tools":
			return func(raw json.RawMessage) bool { return near.Tools(raw, ciphertextOf(params)) }, true
		case "tool_choice":
			return near.IsToolChoice, true
		}
	}
	check, ok := verbatimFields[field]
	return check, ok
}

func ciphertextOf(params chat.E2EE) near.Value {
	return func(_ string, raw json.RawMessage) bool { return params.IsCiphertext(raw) }
}

func admitMessage(m chat.Message, params chat.E2EE) error {
	allowed, tools := verbatimMessageKeys, params.SealsTools()
	switch {
	case tools && m.Role == "tool":
		allowed = near.ToolTurnKeys
	case tools && m.Role == "assistant":
		allowed = near.CallingKeys
	}
	for _, key := range m.Keys() {
		if !allowed[key] {
			return fieldRefused("messages." + key)
		}
	}
	if !verbatimRoles[m.Role] && !(tools && m.Role == "tool") {
		return fieldRefused("messages.role")
	}
	if m.Role == "tool" && !near.IsCallID(m.Raw("tool_call_id")) {
		return fieldRefused("messages.tool_call_id")
	}
	calls := m.Raw("tool_calls")
	if calls != nil && !near.Calls(calls, ciphertextOf(params)) {
		return fieldRefused("messages.tool_calls")
	}
	content := m.Raw("content")
	if calls != nil && (content == nil || string(content) == "null") {
		return nil
	}
	if !params.IsCiphertext(content) {
		return errE2EEContentNotEncrypted
	}
	return nil
}
