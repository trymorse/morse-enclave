package worker

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"morse/backend/internal/billing/measure"
	"morse/backend/internal/catalog"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/seal"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/taskseal"
	"morse/backend/internal/uuid"
)

// A bundle route's body, read by contracts.md section B.1: strict JSON, then the fields in the contract's order, each
// refusal the first that applies.

// The keys each object of a bundle may hold. Every field decodes with into, which refuses one that is absent, but
// recalled, last, cron, and once_local. So a schedule without kind or tz is not of the contract's shape: the relay
// never sees a kind it can't name, and schedule.CodeKind stays unreachable from the routes, as E.5 row 1 says.
var (
	bundleFields = []string{"v", "id", "chat", "name", "prompt", "system", "recalled", "route", "mode", "notify", "schedule", "keys", "last"}
	specFields   = []string{"kind", "cron", "once_local", "tz"}
	lastFields   = []string{"run", "at", "text"}
)

// recalledTiers are the names recalled takes: the tier of the most private memory system carries.
var recalledTiers = map[string]catalog.Tier{"anon": catalog.Anon, "private": catalog.Private}

// bundleRoute is which bundle route a body came to: POST /v1/tasks creates a task, POST /v1/tasks/{id}/bundle
// replaces the bundle of the task its path names.
type bundleRoute struct {
	replaces bool
	pathID   string
}

func (r bundleRoute) status() int {
	if r.replaces {
		return http.StatusOK
	}
	return http.StatusCreated
}

func readBundle(body io.Reader, route bundleRoute) (TaskBundle, error) {
	if body == nil {
		body = http.NoBody
	}
	raw, err := io.ReadAll(io.LimitReader(body, MaxTaskBody+1))
	switch {
	case err != nil:
		return TaskBundle{}, ErrInvalidTask
	case len(raw) > MaxTaskBody:
		return TaskBundle{}, ErrTaskTooLarge
	}
	b, ok := decodeBundle(raw)
	if !ok {
		return TaskBundle{}, ErrInvalidTask
	}
	return b, checkBundle(b, route)
}

// decodeBundle reads raw as one strict JSON object of the bundle's shape: every key exactly as B.1 names it, once,
// with no null at any depth and the fields of their types, which is all strict decoding asks; checkBundle checks the
// values.
func decodeBundle(raw []byte) (TaskBundle, bool) {
	var b TaskBundle
	if !strictJSON(raw) {
		return b, false
	}
	fields, ok := objectOf(raw, bundleFields)
	if !ok {
		return b, false
	}
	spec, ok := objectOf(fields["schedule"], specFields)
	if !ok {
		return b, false
	}
	ok = into(fields["v"], &b.V) && into(fields["id"], &b.ID) && into(fields["chat"], &b.Chat) &&
		into(fields["name"], &b.Name) && into(fields["prompt"], &b.Prompt) && into(fields["system"], &b.System) &&
		optionalInto(fields, "recalled", &b.Recalled) && into(fields["route"], &b.Route) &&
		into(fields["mode"], &b.Mode) && into(fields["notify"], &b.Notify) && into(fields["keys"], &b.Keys) &&
		into(spec["kind"], &b.Schedule.Kind) && into(spec["tz"], &b.Schedule.TZ) &&
		optionalInto(spec, "cron", &b.Schedule.Cron) && optionalInto(spec, "once_local", &b.Schedule.OnceLocal)
	if !ok {
		return b, false
	}
	if raw, sent := fields["last"]; sent {
		last, ok := objectOf(raw, lastFields)
		b.Last = &TaskLast{}
		if !ok || !into(last["run"], &b.Last.Run) || !into(last["at"], &b.Last.At) || !into(last["text"], &b.Last.Text) {
			return b, false
		}
	}
	return b, true
}

func objectOf(raw json.RawMessage, allowed []string) (map[string]json.RawMessage, bool) {
	fields, err := strictjson.Object(bytes.NewReader(raw), allowed...)
	return fields, err == nil
}

// into decodes a field into v, refusing one that is absent, whose raw value is nil.
func into(raw json.RawMessage, v any) bool { return raw != nil && json.Unmarshal(raw, v) == nil }

func optionalInto(fields map[string]json.RawMessage, key string, v any) bool {
	raw, sent := fields[key]
	return !sent || into(raw, v)
}

// strictJSON reports whether raw is valid UTF-8 holding exactly one JSON object with no null at any depth and no key
// an object repeats. strictjson.Object checks only the top level.
func strictJSON(raw []byte) bool {
	if !utf8.Valid(raw) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		keys        map[string]bool
		awaitingKey bool
	}
	var stack []*frame
	values := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return values == 1 && len(stack) == 0
		}
		if err != nil {
			return false
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			stack = stack[:len(stack)-1]
			continue
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if top != nil && top.keys != nil && top.awaitingKey {
			key, _ := tok.(string)
			if top.keys[key] {
				return false
			}
			top.keys[key], top.awaitingKey = true, false
			continue
		}
		switch {
		case tok == nil:
			return false
		case top == nil:
			if values++; values > 1 || tok != json.Delim('{') {
				return false
			}
		case top.keys != nil:
			top.awaitingKey = true
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &frame{keys: map[string]bool{}, awaitingKey: true})
		case json.Delim('['):
			stack = append(stack, &frame{})
		}
	}
}

// checkBundle checks what decoding leaves, in the contract's order: every invalid_task rule, then the keys, then the
// schedule's fields.
func checkBundle(b TaskBundle, route bundleRoute) error {
	recalled, known := recalledTiers[b.Recalled]
	switch {
	case b.V != TaskBundleVersion,
		!isTaskID(b.ID), !isTaskID(b.Chat),
		route.replaces && b.ID != route.pathID,
		runes(b.Name) < 1, runes(b.Name) > MaxTaskNameRunes, strings.ContainsFunc(b.Name, unicode.IsControl),
		runes(b.Prompt) < 1, runes(b.Prompt) > MaxTaskPromptRunes,
		len(b.System) > MaxTaskSystemBytes,
		b.Recalled != "" && (!known || recalled > b.Mode.Tier()),
		len(b.Route) < 1, len(b.Route) > MaxTaskRouteBytes, strings.ContainsFunc(b.Route, isSpaceOrControl),
		b.Last != nil && (!isTaskID(b.Last.Run) || b.Last.At <= 0 || runes(b.Last.Text) > MaxTaskLastRunes):
		return ErrInvalidTask
	case !keysUsable(b.Keys):
		return ErrTaskKeysInvalid
	case b.Schedule.CheckFields() != nil:
		return ErrTaskScheduleInvalid
	}
	return nil
}

func runes(s string) int { return utf8.RuneCountInString(s) }

func isSpaceOrControl(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }

// isTaskID reports whether s is a UUID in its one spelling the task contract takes: canonical, lowercase.
func isTaskID(s string) bool {
	id, ok := uuid.Parse(s)
	return ok && uuid.Format(id) == s
}

// probeKey is any X25519 scalar: X25519 clears the cofactor, so a low-order point gives the zero shared secret, which
// crypto/ecdh refuses, whichever scalar meets it.
var probeKey = func() *ecdh.PrivateKey {
	sum := sha256.Sum256([]byte("morse task key probe"))
	k, err := ecdh.X25519().NewPrivateKey(sum[:])
	if err != nil {
		panic(err)
	}
	return k
}()

// keysUsable reports whether keys are 1 to MaxTaskKeys distinct device keys a result can be sealed to.
func keysUsable(keys []TaskPublicKey) bool {
	if len(keys) < 1 || len(keys) > MaxTaskKeys {
		return false
	}
	for i, k := range keys {
		if slices.Contains(keys[:i], k) {
			return false
		}
		pub, err := ecdh.X25519().NewPublicKey(k[:])
		if err != nil {
			return false
		}
		if _, err := probeKey.ECDH(pub); err != nil {
			return false
		}
	}
	return true
}

func keyIDsOf(keys []TaskPublicKey) []seal.KeyID {
	ids := make([]seal.KeyID, len(keys))
	for i, k := range keys {
		ids[i] = seal.KeyIDOf(k[:])
	}
	return ids
}

// atRest is the bundle's JSON as the worker keeps it under its task key: its own compact encoding, with last.text
// cut until it fits a bundle at rest. A bundle that can't fit with no last text left is too large.
func atRest(b TaskBundle) ([]byte, error) {
	if b.Last == nil {
		if data := jsonx.Encode(b); len(data) <= taskseal.MaxBundleJSON {
			return data, nil
		}
		return nil, ErrTaskTooLarge
	}
	last := *b.Last
	data, _, ok := fitting(last.Text, taskseal.MaxBundleJSON, func(text string) []byte {
		last.Text = text
		b.Last = &last
		return jsonx.Encode(b)
	})
	if !ok {
		return nil, ErrTaskTooLarge
	}
	return data, nil
}

// fitting is what encode makes of the longest prefix of text, cut at a rune boundary, whose encoding is at most
// limit bytes, and false when not even the empty prefix fits. Escaping makes the encoding grow by as much as six
// bytes a byte, so the prefix is searched for rather than cut by the overflow.
func fitting(text string, limit int, encode func(string) []byte) ([]byte, string, bool) {
	if data := encode(text); len(data) <= limit {
		return data, text, true
	}
	if len(encode("")) > limit {
		return nil, "", false
	}
	lo, hi := 0, len(text)
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		if len(encode(cutBytes(text, mid))) <= limit {
			lo = mid
		} else {
			hi = mid
		}
	}
	kept := cutBytes(text, lo)
	return encode(kept), kept, true
}

// cutBytes is s cut to at most n bytes at a rune boundary.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:max(n, 0)]
}

// cutRunes is s cut to at most n runes.
func cutRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	i := 0
	for at := range s {
		if i == n {
			return s[:at]
		}
		i++
	}
	return s
}

// openedTask is a bundle route's request, opened and checked, waiting for the relay to adopt it or cut it.
type openedTask struct {
	task   [16]byte
	bundle []byte
	reply  []byte
	status int
}

func (*openedTask) cut(measure.Cut) {}

// openTask opens a bundle route. The admission tells the relay what it checks and keeps: the bundle's id, route,
// mode, notify, schedule, and its keys' ids, never its name, prompt, system, chat, or last.
func (w *InProcess) openTask(o Opening, route bundleRoute) (Admission, error) {
	b, err := readBundle(o.Body, route)
	if err != nil {
		return nil, err
	}
	data, err := atRest(b)
	if err != nil {
		return nil, err
	}
	task, _ := uuid.Parse(b.ID)
	keys := keyIDsOf(b.Keys)
	t := &openedTask{task: task, bundle: data, reply: jsonx.Encode(TaskReply{Object: TaskObject, ID: b.ID, Keys: keys}), status: route.status()}
	return TaskAdmission{admitted: admitted{w.keep(o, t)}, ID: b.ID, Route: b.Route, Mode: b.Mode, Notify: b.Notify, Schedule: b.Schedule, Keys: keys}, nil
}
