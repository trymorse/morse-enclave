package worker

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"morse/backend/internal/catalog"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/schedule"
)

// What a run tells the model, beyond the device's system text: the worker's own words, which the device can't change,
// saying it runs on a schedule with no one to answer follow-ups, the date and time where the task lives, and, for a
// task that speaks only when something changed, its last result and how to say nothing did. The model's provider reads
// all of it, so it never names the task's time zone, which would say roughly where the user lives; an Anonymous task
// gives the date alone, as the app's own Anonymous chats do.

const (
	taskScheduledNote = "This is a scheduled task: the user set this prompt to run on a schedule, and Morse AI runs it while they are away. No one is present to answer questions or follow-ups, so don't ask any. Make reasonable assumptions and give a complete answer now; the user reads it later, in the task's chat."
	taskClockNote     = "It is now %s, the task's local time."
	taskDateNote      = "Today is %s."
	taskWebNote       = "Use the web tools for anything that depends on today, such as news, prices, weather, schedules, and releases."
	taskChangesNote   = "The user wants to hear from this task only when something important has changed. Its last result, from %s, is below.\n<last_result>\n%s\n</last_result>\nIf nothing important has changed since that result, answer with " + TaskNoChange + " alone on the first line; you may add a short note on the lines after it. Otherwise answer as usual, and don't begin with " + TaskNoChange + "."
	taskReplayNote    = "# Tool calls\n\nEarlier turns show tool calls in <unbound_call> blocks, which ran for this task, and their results in <unbound_result> blocks. No tools are available now: don't write tool calls, and answer with what you have."
	taskFinalNote     = "No more tool calls are available in this run. Answer now."
	wallLayout        = "Monday, January 2, 2006, 3:04 PM"
	dayLayout         = "Monday, January 2, 2006"
)

// taskSystem is the run's system text: the device's, then the worker's notes.
func taskSystem(b TaskBundle, now time.Time, web bool) string {
	loc, err := schedule.Zone(b.Schedule.TZ)
	if err != nil {
		loc = time.UTC
	}
	clock := fmt.Sprintf(taskClockNote, now.In(loc).Format(wallLayout))
	if b.Mode == TaskAnon {
		clock = fmt.Sprintf(taskDateNote, now.In(loc).Format(dayLayout))
	}
	notes := []string{taskScheduledNote, clock}
	if web {
		notes = append(notes, taskWebNote)
	}
	if asksForChange(b) {
		at := time.Unix(b.Last.At, 0).In(loc)
		when := at.Format(wallLayout)
		if b.Mode == TaskAnon {
			when = at.Format(dayLayout)
		}
		notes = append(notes, fmt.Sprintf(taskChangesNote, when, defang(b.Last.Text)))
	}
	note := strings.Join(notes, "\n")
	if b.System == "" {
		return note
	}
	return b.System + "\n\n" + note
}

// asksForChange reports whether a run asks for NO_CHANGE: only with notify "changes" and a last result to compare.
func asksForChange(b TaskBundle) bool { return b.Notify == TaskChanges && b.Last != nil }

// A turn after the prompt: the model's, with the calls it made, or one call's result.
type taskTurn struct {
	assistant bool
	content   string
	calls     []*taskCall
	call      *taskCall
}

// taskCall is a tool call as the run replays it: an id unique in the run, a name and arguments vendors take back,
// the arguments as the model wrote them, and, once known, what the model reads of its result.
type taskCall struct {
	id, name, args, raw string
	result              string
	answered            bool
}

type passMessage struct {
	Role       string         `json:"role"`
	Content    *string        `json:"content"`
	ToolCalls  []passToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type passToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function passFunction `json:"function"`
}

type passFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type passRequest struct {
	Model         string            `json:"model"`
	Provider      *passProvider     `json:"provider,omitempty"`
	Stream        bool              `json:"stream"`
	StreamOptions json.RawMessage   `json:"stream_options"`
	Messages      []passMessage     `json:"messages"`
	Tools         []json.RawMessage `json:"tools,omitempty"`
	ToolChoice    string            `json:"tool_choice,omitempty"`
}

// passProvider is a pass's floor: a run in Private mode is served at private or above, never by an anon host a
// breaker or a failover could otherwise reach on a model the route shares with other tiers.
type passProvider struct {
	MinPrivacy string `json:"min_privacy"`
}

// passShape is what a chat pass sends of the run's tools: their definitions, and whether the model may call them.
// A pass that sends none replays earlier calls as text, since some vendors refuse tool turns without definitions.
type passShape struct {
	tools    []json.RawMessage
	callable bool
}

// passBody is a chat pass's request: the system text, the prompt, then the run's turns, natively when the pass sends
// the tools' definitions and as text when it sends none.
func passBody(route string, floor catalog.Tier, system, prompt string, turns []taskTurn, shape passShape) []byte {
	req := passRequest{Model: route, Stream: true, StreamOptions: json.RawMessage(`{"include_usage":true}`)}
	if floor > catalog.Anon {
		req.Provider = &passProvider{MinPrivacy: floor.String()}
	}
	native := len(shape.tools) > 0
	switch {
	case !native && len(turns) > 0:
		system += "\n\n" + taskReplayNote
	case native && !shape.callable:
		system += "\n\n" + taskFinalNote
	}
	req.Messages = append(req.Messages, textMessage("system", system), textMessage("user", prompt))
	if native {
		req.Tools = shape.tools
		if !shape.callable {
			req.ToolChoice = "none"
		}
		req.Messages = append(req.Messages, nativeTurns(turns)...)
	} else {
		req.Messages = append(req.Messages, textTurns(turns)...)
	}
	return jsonx.Encode(req)
}

func textMessage(role, content string) passMessage { return passMessage{Role: role, Content: &content} }

func nativeTurns(turns []taskTurn) []passMessage {
	var out []passMessage
	for _, t := range turns {
		if !t.assistant {
			out = append(out, passMessage{Role: "tool", Content: &t.call.result, ToolCallID: t.call.id})
			continue
		}
		m := passMessage{Role: "assistant"}
		if t.content != "" {
			m.Content = &t.content
		}
		for _, c := range t.calls {
			m.ToolCalls = append(m.ToolCalls, passToolCall{ID: c.id, Type: "function", Function: passFunction{Name: c.name, Arguments: c.args}})
		}
		out = append(out, m)
	}
	return out
}

var ownTags = regexp.MustCompile(`(?i)<(/?unbound_)`)

// textTurns writes each assistant turn's calls after its text as <unbound_call> blocks, and the results that follow
// it as one user turn of <unbound_result> blocks, as the app replays a history's calls to a request that offers no
// tools.
func textTurns(turns []taskTurn) []passMessage {
	var out []passMessage
	for i := 0; i < len(turns); i++ {
		t := turns[i]
		if !t.assistant {
			continue
		}
		blocks := make([]string, len(t.calls))
		for j, c := range t.calls {
			args := json.RawMessage(c.args)
			if !json.Valid(args) {
				args = jsonx.Encode(c.args)
			}
			call := fmt.Sprintf(`{"name": %s, "arguments": %s}`, jsonx.Encode(c.name), args)
			blocks[j] = "<unbound_call>\n" + ownTags.ReplaceAllString(call, `<$1`) + "\n</unbound_call>"
		}
		text := strings.Join(blocks, "\n")
		if strings.TrimSpace(t.content) != "" {
			text = strings.TrimRight(t.content, " \t\r\n") + "\n\n" + text
		}
		out = append(out, textMessage("assistant", text))
		var results []string
		for n := 1; i+1 < len(turns) && !turns[i+1].assistant; n++ {
			i++
			c := turns[i].call
			errorMark := ""
			if strings.HasPrefix(c.result, "Error:") {
				errorMark = ` error="true"`
			}
			results = append(results, fmt.Sprintf("<unbound_result call=\"%d\" name=\"%s\"%s>\n%s\n</unbound_result>", n, c.name, errorMark, c.result))
		}
		if len(results) > 0 {
			out = append(out, textMessage("user", strings.Join(results, "\n\n")))
		}
	}
	return out
}

var wireUnsafe = regexp.MustCompile(`[^\w-]`)

// wireName is a name or id as every vendor's tool API takes it back, [A-Za-z0-9_-]{1,64}, or fallback when nothing of
// it survives.
func wireName(raw, fallback string) string {
	name := wireUnsafe.ReplaceAllString(raw, "_")
	if name == "" {
		name = fallback
	}
	return name[:min(len(name), 64)]
}

// jsonObject reports whether args is one JSON object, the only arguments vendors take back.
func jsonObject(args string) bool {
	var fields map[string]json.RawMessage
	return json.Unmarshal([]byte(args), &fields) == nil && fields != nil
}
