package gemini

import (
	"encoding/json"
	"net/http"

	"morse/backend/internal/apierr"
	"morse/backend/internal/chat"
	"morse/backend/internal/completions"
	"morse/backend/internal/upstream"
)

const (
	roleUser     = "user"
	roleModel    = "model"
	streamAccept = "text/event-stream"
)

var roles = map[bool]string{false: roleUser, true: roleModel}

var finishReasons = map[string]completions.Finish{
	"STOP":                     completions.FinishStop,
	"MAX_TOKENS":               completions.FinishLength,
	"SAFETY":                   completions.FinishContentFilter,
	"RECITATION":               completions.FinishContentFilter,
	"LANGUAGE":                 completions.FinishContentFilter,
	"BLOCKLIST":                completions.FinishContentFilter,
	"PROHIBITED_CONTENT":       completions.FinishContentFilter,
	"SPII":                     completions.FinishContentFilter,
	"IMAGE_SAFETY":             completions.FinishContentFilter,
	"IMAGE_PROHIBITED_CONTENT": completions.FinishContentFilter,
	"IMAGE_RECITATION":         completions.FinishContentFilter,
}

func endpoint(baseURL, apiKey string, client *http.Client) upstream.Endpoint {
	return upstream.Endpoint{BaseURL: baseURL, Auth: http.Header{"X-Goog-Api-Key": {apiKey}}, HTTP: client}
}

func streamPath(model string) string {
	return "/v1beta/models/" + model + ":streamGenerateContent?alt=sse"
}

type request struct {
	SystemInstruction *content         `json:"systemInstruction,omitempty"`
	Contents          []content        `json:"contents"`
	Tools             []toolSet        `json:"tools,omitempty"`
	ToolConfig        *toolConfig      `json:"toolConfig,omitempty"`
	GenerationConfig  generationConfig `json:"generationConfig"`
}

type generationConfig struct {
	MaxOutputTokens    int             `json:"maxOutputTokens,omitempty"`
	ThinkingConfig     *thinkingConfig `json:"thinkingConfig,omitempty"`
	ResponseModalities []string        `json:"responseModalities,omitempty"`
	ImageConfig        *imageConfig    `json:"imageConfig,omitempty"`
}

type content struct {
	Role  string `json:"role,omitempty"`
	Parts []part `json:"parts"`
}

type part struct {
	Text             string            `json:"text,omitempty"`
	InlineData       *blob             `json:"inlineData,omitempty"`
	FunctionCall     *functionCall     `json:"functionCall,omitempty"`
	FunctionResponse *functionResponse `json:"functionResponse,omitempty"`
	ThoughtSignature string            `json:"thoughtSignature,omitempty"`
}

type blob struct {
	MIMEType string `json:"mimeType"`
	Data     string `json:"data"`
}

// Google's error object carries the HTTP status it would have answered with, as a number.
type vendorError struct {
	Code int `json:"code"`
}

func (e vendorError) refusal() apierr.Error { return apierr.SanitizedUpstreamError(e.Code, nil) }

type functionCall struct {
	Name string          `json:"name"`
	Args json.RawMessage `json:"args,omitempty"`
}

type replyPart struct {
	Text         *string       `json:"text"`
	Thought      bool          `json:"thought"`
	FunctionCall *functionCall `json:"functionCall"`
	InlineData   *blob         `json:"inlineData"`
}

// The stream has no closing event, so its readers read it to its end: usage may follow the chunk that finishes.
type streamChunk struct {
	Candidates []struct {
		Content struct {
			Parts []replyPart `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	PromptFeedback *struct {
		BlockReason string `json:"blockReason"`
	} `json:"promptFeedback"`
	UsageMetadata *usageWire   `json:"usageMetadata"`
	Error         *vendorError `json:"error"`
}

func (e streamChunk) parts() []replyPart {
	if len(e.Candidates) == 0 {
		return nil
	}
	return e.Candidates[0].Content.Parts
}

func (e streamChunk) end() (finish completions.Finish, ended bool) {
	switch {
	case e.PromptFeedback != nil && e.PromptFeedback.BlockReason != "":
		return completions.FinishContentFilter, true
	case len(e.Candidates) == 0 || e.Candidates[0].FinishReason == "":
		return "", false
	}
	return finishReasons[e.Candidates[0].FinishReason], true
}

type modalityCount struct {
	Modality   string `json:"modality"`
	TokenCount int    `json:"tokenCount"`
}

type usageWire struct {
	PromptTokenCount        int             `json:"promptTokenCount"`
	CachedContentTokenCount int             `json:"cachedContentTokenCount"`
	CandidatesTokenCount    int             `json:"candidatesTokenCount"`
	ToolUsePromptTokenCount int             `json:"toolUsePromptTokenCount"`
	ThoughtsTokenCount      int             `json:"thoughtsTokenCount"`
	CandidatesTokensDetails []modalityCount `json:"candidatesTokensDetails"`
}

// Gemini counts thinking apart from the candidates and bills it at the output rate, so the completion is both.
func (u usageWire) usage() chat.Usage {
	return chat.Usage{
		PromptTokens:       u.PromptTokenCount + u.ToolUsePromptTokenCount,
		CachedPromptTokens: u.CachedContentTokenCount,
		CompletionTokens:   u.CandidatesTokenCount + u.ThoughtsTokenCount,
		ReasoningTokens:    u.ThoughtsTokenCount,
	}
}
