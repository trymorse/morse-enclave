package attestation

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

const (
	runtimeIMR                    = 3
	dstackRuntimeEventType uint32 = 0x08000001
	runtimeFieldSeparator         = ":"
	eventComposeHash              = "compose-hash"
	eventAppID                    = "app-id"
	eventInstanceID               = "instance-id"
	eventOSImageHash              = "os-image-hash"
	eventKeyProvider              = "key-provider"
	eventSystemReady              = "system-ready"
	eventLogV1                    = 1
	eventLogV2                    = 2
)

type event struct {
	IMR     int
	Type    uint32
	Version uint32
	Digest  [sha512.Size384]byte
	Name    string
	Payload []byte
}

// dstack sends its event log, and NEAR its gateway's tcb_info, as JSON inside a JSON string.
func unquoted(raw json.RawMessage) json.RawMessage {
	var quoted string
	if json.Unmarshal(raw, &quoted) == nil {
		return json.RawMessage(quoted)
	}
	return raw
}

func parseEventLog(raw json.RawMessage) ([]event, error) {
	raw = unquoted(raw)
	var wire []struct {
		IMR      int     `json:"imr"`
		Type     uint32  `json:"event_type"`
		Version  *uint32 `json:"version"`
		Digest   string  `json:"digest"`
		Name     string  `json:"event"`
		Payload  string  `json:"event_payload"`
		Preimage *string `json:"preimage"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEventLog, err)
	}
	events := make([]event, len(wire))
	for i, w := range wire {
		e := event{IMR: w.IMR, Type: w.Type, Version: eventLogV1, Name: w.Name}
		if w.Version != nil {
			e.Version = *w.Version
		}
		if e.Version != eventLogV1 && (e.IMR != runtimeIMR || e.Version != eventLogV2) {
			return nil, fmt.Errorf("%w: %w: event %d in IMR %d has version %d", ErrEventLog, ErrUnreadable, i, e.IMR, e.Version)
		}
		payload, err := hex.DecodeString(w.Payload)
		if err != nil {
			return nil, fmt.Errorf("%w: event %d payload: %w", ErrEventLog, i, err)
		}
		e.Payload = payload
		switch {
		// Newer dstack leaves a runtime event's digest out: it is the hash of the event itself, and
		// the replay against the quote's RTMR3 binds what we compute here all the same.
		case w.Digest == "" && e.IMR == runtimeIMR:
			e.Digest = runtimeDigest(e)
		case len(w.Digest) != hex.EncodedLen(len(e.Digest)):
			return nil, fmt.Errorf("%w: event %d digest %q is not %d hex bytes", ErrEventLog, i, w.Digest, len(e.Digest))
		default:
			if _, err := hex.Decode(e.Digest[:], []byte(w.Digest)); err != nil {
				return nil, fmt.Errorf("%w: event %d digest: %w", ErrEventLog, i, err)
			}
		}
		if e.IMR == runtimeIMR {
			if w.Preimage != nil && *w.Preimage != hex.EncodeToString(runtimePreimage(e)) {
				return nil, fmt.Errorf("%w: runtime event %d %q has a preimage that is not its version %d preimage", ErrEventLog, i, e.Name, e.Version)
			}
			if err := checkRuntimeEvent(e); err != nil {
				return nil, fmt.Errorf("%w: runtime event %d %q %w", ErrEventLog, i, e.Name, err)
			}
		}
		events[i] = e
	}
	return events, nil
}

func checkRuntimeEvent(e event) error {
	switch {
	case e.Type != dstackRuntimeEventType:
		return fmt.Errorf("has event_type %#x, not %#x", e.Type, dstackRuntimeEventType)
	case e.Version == eventLogV1 && strings.Contains(e.Name, runtimeFieldSeparator):
		return fmt.Errorf("contains %q in its name, which makes its digest preimage ambiguous", runtimeFieldSeparator)
	case e.Digest != runtimeDigest(e):
		return fmt.Errorf("digest %x is not the hash of its payload", e.Digest)
	}
	return nil
}

func runtimeDigest(e event) [sha512.Size384]byte {
	return sha512.Sum384(runtimePreimage(e))
}

// why: dstack's cc-eventlog runtime_events.rs hashes a version 1 event as event_type_le || ":" || name ||
// ":" || payload, and a version 2 event as the RFC 8785 JSON {"name":...,"payload":"<hex>","type":...}.
func runtimePreimage(e event) []byte {
	if e.Version == eventLogV2 {
		var b bytes.Buffer
		b.WriteString(`{"name":`)
		jcsString(&b, e.Name)
		b.WriteString(`,"payload":"` + hex.EncodeToString(e.Payload) + `","type":` + strconv.FormatUint(uint64(e.Type), 10) + `}`)
		return b.Bytes()
	}
	b := binary.LittleEndian.AppendUint32(nil, e.Type)
	b = append(b, runtimeFieldSeparator+e.Name+runtimeFieldSeparator...)
	return append(b, e.Payload...)
}

// why: RFC 8785 section 3.2.2.2 escapes only '"', '\\' and the controls below U+0020, the five with a short
// escape by it and the rest as lowercase \u00xx, and writes every other character as UTF-8.
func jcsString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

func replayRuntime(events []event) [sha512.Size384]byte {
	var mr [sha512.Size384]byte
	for _, e := range events {
		if e.IMR == runtimeIMR {
			mr = sha512.Sum384(append(mr[:], e.Digest[:]...))
		}
	}
	return mr
}

type measurements struct {
	composeHash []byte
	appID       []byte
	instanceID  []byte
	osImageHash []byte
	keyProvider []byte
}

func runtimeMeasurements(events []event) (measurements, error) {
	var m measurements
	required := []struct {
		name     string
		payload  *[]byte
		sentinel error
	}{
		{eventComposeHash, &m.composeHash, ErrComposeHash},
		{eventAppID, &m.appID, ErrEventLog},
		{eventInstanceID, &m.instanceID, ErrEventLog},
		{eventOSImageHash, &m.osImageHash, ErrEventLog},
		{eventKeyProvider, &m.keyProvider, ErrEventLog},
	}
	seen := map[string]bool{}
	ready := false
	for _, e := range events {
		if e.IMR != runtimeIMR {
			continue
		}
		if e.Name == eventSystemReady {
			ready = true
			break
		}
		for _, r := range required {
			if r.name != e.Name {
				continue
			}
			if seen[e.Name] {
				return measurements{}, fmt.Errorf("%w: %q is measured twice before %s", r.sentinel, e.Name, eventSystemReady)
			}
			seen[e.Name] = true
			*r.payload = e.Payload
		}
	}
	if !ready {
		return measurements{}, fmt.Errorf("%w: no %s event is measured", ErrEventLog, eventSystemReady)
	}
	for _, r := range required {
		if len(*r.payload) == 0 {
			return measurements{}, fmt.Errorf("%w: no %s is measured before %s", r.sentinel, r.name, eventSystemReady)
		}
	}
	return m, nil
}

func keyProviderID(payload []byte) (string, error) {
	var provider struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(payload, &provider); err != nil {
		return "", fmt.Errorf("%w: %s payload %q: %w", ErrEventLog, eventKeyProvider, payload, err)
	}
	if provider.ID == "" {
		return "", fmt.Errorf("%w: %s payload %q has no id", ErrEventLog, eventKeyProvider, payload)
	}
	return provider.ID, nil
}
