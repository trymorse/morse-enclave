package attestation

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
)

type event struct {
	IMR     int
	Type    uint32
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
		IMR     int    `json:"imr"`
		Type    uint32 `json:"event_type"`
		Digest  string `json:"digest"`
		Name    string `json:"event"`
		Payload string `json:"event_payload"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEventLog, err)
	}
	events := make([]event, len(wire))
	for i, w := range wire {
		e := event{IMR: w.IMR, Type: w.Type, Name: w.Name}
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
	case strings.Contains(e.Name, runtimeFieldSeparator):
		return fmt.Errorf("contains %q in its name, which makes its digest preimage ambiguous", runtimeFieldSeparator)
	case e.Digest != runtimeDigest(e):
		return fmt.Errorf("digest %x is not the hash of its payload", e.Digest)
	}
	return nil
}

func runtimeDigest(e event) [sha512.Size384]byte {
	h := sha512.New384()
	h.Write(binary.LittleEndian.AppendUint32(nil, e.Type))
	h.Write([]byte(runtimeFieldSeparator + e.Name + runtimeFieldSeparator))
	h.Write(e.Payload)
	var sum [sha512.Size384]byte
	h.Sum(sum[:0])
	return sum
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
