package gemini

import (
	"cmp"
	"crypto/rand"
	"encoding/json"
	"net/http"

	"morse/backend/internal/apierr"
	"morse/backend/internal/completions"
)

const (
	// Gemini 3 refuses a replayed function call that lacks the thought signature it was sent with. The client
	// keeps no signature, so each replayed call carries the value Google documents for history it did not write.
	skipSignature   = "skip_thought_signature_validator"
	unnamedFunction = "function"
)

var callingModes = map[string]string{
	completions.ChoiceAuto:     "AUTO",
	completions.ChoiceNone:     "NONE",
	completions.ChoiceRequired: "ANY",
	completions.ChoiceFunction: "ANY",
}

type thinkingConfig struct {
	ThinkingLevel string `json:"thinkingLevel"`
}

type functionResponse struct {
	Name     string     `json:"name"`
	Response toolOutput `json:"response"`
}

type toolOutput struct {
	Result string `json:"result"`
}

type toolSet struct {
	FunctionDeclarations []functionDeclaration `json:"functionDeclarations"`
}

type functionDeclaration struct {
	Name                 string          `json:"name"`
	Description          string          `json:"description,omitempty"`
	ParametersJSONSchema json.RawMessage `json:"parametersJsonSchema"`
}

type toolConfig struct {
	FunctionCallingConfig callingConfig `json:"functionCallingConfig"`
}

type callingConfig struct {
	Mode                 string   `json:"mode"`
	AllowedFunctionNames []string `json:"allowedFunctionNames,omitempty"`
}

func NewChat(baseURL, apiKey, model string, client *http.Client) *completions.Provider {
	return &completions.Provider{Endpoint: endpoint(baseURL, apiKey, client), Translator: translator{model: model}, ReadsToEnd: true}
}

type translator struct {
	model string
}

func (t translator) Request(conv completions.Conversation) (string, string, any) {
	return streamPath(t.model), streamAccept, t.request(conv)
}

func (translator) Events(w *completions.Writer) func([]byte) (bool, error) {
	return completions.On((&translation{w: w}).chunk)
}

type translation struct{ w *completions.Writer }

func (s *translation) chunk(e streamChunk) (bool, error) {
	if e.UsageMetadata != nil {
		s.w.Count(e.UsageMetadata.usage(), true)
	}
	switch {
	case s.w.Finished():
		return false, nil
	case e.Error != nil:
		return true, s.w.Fail("", e.Error.refusal())
	}
	for _, p := range e.parts() {
		if err := s.part(p); err != nil {
			return false, err
		}
	}
	finish, ended := e.end()
	switch {
	case !ended:
		return false, nil
	case finish == "":
		return true, s.w.Fail("", apierr.ErrUpstream)
	case finish == completions.FinishStop && s.w.Calls() > 0:
		finish = completions.FinishToolCalls
	}
	return false, s.w.Finish(finish)
}

func (s *translation) part(p replyPart) error {
	switch {
	case p.Thought:
		return nil
	case p.FunctionCall != nil:
		key := s.w.Calls()
		if err := s.w.ToolStart(key, "call_"+rand.Text(), p.FunctionCall.Name); err != nil {
			return err
		}
		return s.w.ToolEnd(key, string(objectArgs(p.FunctionCall.Args)))
	case p.Text != nil && *p.Text != "":
		return s.w.Text(*p.Text)
	}
	return nil
}

func (t translator) request(conv completions.Conversation) request {
	out := request{GenerationConfig: generationConfig{MaxOutputTokens: conv.OutputLimit}}
	if conv.ForwardedEffort != "" {
		out.GenerationConfig.ThinkingConfig = &thinkingConfig{ThinkingLevel: conv.ForwardedEffort}
	}
	if len(conv.Tools) > 0 {
		out.Tools = []toolSet{{FunctionDeclarations: declarations(conv.Tools)}}
		out.ToolConfig = calling(conv.Choice)
	}
	system, exchanges := conv.Alternating()
	if len(system) > 0 {
		out.SystemInstruction = &content{}
		for _, text := range system {
			out.SystemInstruction.Parts = append(out.SystemInstruction.Parts, part{Text: text})
		}
	}
	names := map[string]string{}
	for _, x := range exchanges {
		c := content{Role: roles[x.FromModel]}
		for _, turn := range x.Turns {
			c.Parts = append(c.Parts, parts(turn, names)...)
		}
		out.Contents = append(out.Contents, c)
	}
	return out
}

func parts(t completions.Turn, names map[string]string) []part {
	switch t.Role {
	case completions.Assistant:
		return modelParts(t, names)
	case completions.ToolResult:
		response := functionResponse{Name: cmp.Or(names[t.CallID], unnamedFunction), Response: toolOutput{Result: t.Text}}
		return []part{{FunctionResponse: &response}}
	}
	return userParts(t.Parts)
}

func userParts(parts []completions.Part) []part {
	var out []part
	for _, p := range parts {
		if p.Image == nil {
			out = append(out, part{Text: p.Text})
			continue
		}
		out = append(out, part{InlineData: &blob{MIMEType: p.Image.MediaType, Data: p.Image.Base64}})
	}
	return out
}

func modelParts(t completions.Turn, names map[string]string) []part {
	var out []part
	if t.Text != "" {
		out = append(out, part{Text: t.Text})
	}
	for i, call := range t.Calls {
		names[call.ID] = call.Function.Name
		p := part{FunctionCall: &functionCall{Name: call.Function.Name, Args: objectArgs(json.RawMessage(call.Function.Arguments))}}
		if i == 0 {
			p.ThoughtSignature = skipSignature
		}
		out = append(out, p)
	}
	return out
}

func objectArgs(args json.RawMessage) json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(args, &fields) != nil || fields == nil {
		return json.RawMessage(completions.EmptyArguments)
	}
	return args
}

func declarations(tools []completions.Tool) []functionDeclaration {
	var out []functionDeclaration
	for _, tool := range tools {
		out = append(out, functionDeclaration{Name: tool.Name, Description: tool.Description, ParametersJSONSchema: tool.Schema()})
	}
	return out
}

func calling(c *completions.Choice) *toolConfig {
	if c == nil {
		return nil
	}
	config := &toolConfig{FunctionCallingConfig: callingConfig{Mode: callingModes[c.Mode]}}
	if c.Mode == completions.ChoiceFunction {
		config.FunctionCallingConfig.AllowedFunctionNames = []string{c.Name}
	}
	return config
}
