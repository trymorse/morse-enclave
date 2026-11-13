package taskrun

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

	"morse/backend/internal/catalog"
	"morse/backend/internal/jsonx"
	"morse/backend/internal/seal"
	"morse/backend/internal/strictjson"
	"morse/backend/internal/taskseal"
)

var (
	bundleFields = []string{"v", "id", "chat", "name", "prompt", "system", "recalled", "route", "mode", "notify", "schedule", "keys", "last"}
	specFields   = []string{"kind", "cron", "once_local", "tz"}
	lastFields   = []string{"run", "at", "text"}
)

var recalledTiers = map[string]catalog.Tier{"anon": catalog.Anon, "private": catalog.Private}

type BundleRoute struct {
	Replaces bool
	PathID   string
}

func (r BundleRoute) Status() int {
	if r.Replaces {
		return http.StatusOK
	}
	return http.StatusCreated
}

func Read(body io.Reader, route BundleRoute) (Bundle, error) {
	if body == nil {
		body = http.NoBody
	}
	raw, err := io.ReadAll(io.LimitReader(body, MaxBody+1))
	switch {
	case err != nil:
		return Bundle{}, ErrInvalid
	case len(raw) > MaxBody:
		return Bundle{}, ErrTooLarge
	}
	b, ok := Decode(raw)
	if !ok {
		return Bundle{}, ErrInvalid
	}
	return b, check(b, route)
}

func Decode(raw []byte) (Bundle, bool) {
	var b Bundle
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
		b.Last = &Last{}
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

func into(raw json.RawMessage, v any) bool { return raw != nil && json.Unmarshal(raw, v) == nil }

func optionalInto(fields map[string]json.RawMessage, key string, v any) bool {
	raw, sent := fields[key]
	return !sent || into(raw, v)
}

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

func check(b Bundle, route BundleRoute) error {
	recalled, known := recalledTiers[b.Recalled]
	switch {
	case b.V != BundleVersion,
		!IsID(b.ID), !IsID(b.Chat),
		route.Replaces && b.ID != route.PathID,
		runes(b.Name) < 1, runes(b.Name) > MaxNameRunes, strings.ContainsFunc(b.Name, unicode.IsControl),
		runes(b.Prompt) < 1, runes(b.Prompt) > MaxPromptRunes,
		len(b.System) > MaxSystemBytes,
		b.Recalled != "" && (!known || recalled > b.Mode.Tier()),
		len(b.Route) < 1, len(b.Route) > MaxRouteBytes, strings.ContainsFunc(b.Route, isSpaceOrControl),
		b.Last != nil && (!IsID(b.Last.Run) || b.Last.At <= 0 || runes(b.Last.Text) > MaxLastRunes):
		return ErrInvalid
	case !keysUsable(b.Keys):
		return ErrKeysInvalid
	case b.Schedule.CheckFields() != nil:
		return ErrScheduleInvalid
	}
	return nil
}

func runes(s string) int { return utf8.RuneCountInString(s) }

func isSpaceOrControl(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }

var probeKey = func() *ecdh.PrivateKey {
	sum := sha256.Sum256([]byte("morse task key probe"))
	k, err := ecdh.X25519().NewPrivateKey(sum[:])
	if err != nil {
		panic(err)
	}
	return k
}()

func keysUsable(keys []PublicKey) bool {
	if len(keys) < 1 || len(keys) > MaxKeys {
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

func KeyIDs(keys []PublicKey) []seal.KeyID {
	ids := make([]seal.KeyID, len(keys))
	for i, k := range keys {
		ids[i] = seal.KeyIDOf(k[:])
	}
	return ids
}

func AtRest(b Bundle) ([]byte, error) {
	if b.Last == nil {
		if data := jsonx.Encode(b); len(data) <= taskseal.MaxBundleJSON {
			return data, nil
		}
		return nil, ErrTooLarge
	}
	last := *b.Last
	data, _, ok := fitting(last.Text, taskseal.MaxBundleJSON, func(text string) []byte {
		last.Text = text
		b.Last = &last
		return jsonx.Encode(b)
	})
	if !ok {
		return nil, ErrTooLarge
	}
	return data, nil
}

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

func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:max(n, 0)]
}

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

func OpenBundle(key *taskseal.Key, task string, rev int64, sealed []byte) (Bundle, ID, error) {
	id, ok := ParseID(task)
	if !ok {
		return Bundle{}, id, ErrBundleInvalid
	}
	plain, err := taskseal.OpenBundle(key, id, uint64(rev), sealed)
	if err != nil {
		return Bundle{}, id, ErrBundleInvalid
	}
	b, ok := Decode(plain)
	if !ok || check(b, BundleRoute{}) != nil || b.ID != task {
		return Bundle{}, id, ErrBundleInvalid
	}
	return b, id, nil
}
