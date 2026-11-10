package seal

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newIdentity(t *testing.T) *Identity {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

var chatHead = Head{Method: "POST", Path: "/v1/chat/completions?x=1", Headers: map[string]string{"Content-Type": "application/json", "X-E2EE-Version": "2"}, TS: 1792216730}

func TestARequestSealedToSeveralKeysOpensUnderEachAndUnderNoOther(t *testing.T) {
	a, b, c := newIdentity(t), newIdentity(t), newIdentity(t)
	body := []byte(`{"model":"m","messages":[]}`)
	sealed, cek, err := Seal([][]byte{a.PublicKey(), b.PublicKey()}, chatHead, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != prefixSize+2*entrySize+Pad {
		t.Errorf("sealed %d bytes, want 2 entries and one 1 KiB ciphertext", len(sealed))
	}
	for _, id := range []*Identity{a, b} {
		r, err := id.Open(sealed)
		if err != nil {
			t.Fatal(err)
		}
		if r.Method != chatHead.Method || r.Path != chatHead.Path || r.TS != chatHead.TS || r.Headers["X-E2EE-Version"] != "2" || len(r.Headers) != 2 {
			t.Errorf("opened head %+v, want %+v", r.Head, chatHead)
		}
		if !bytes.Equal(r.Body, body) || r.CEK != cek {
			t.Errorf("opened body %q under cek %x, want %q under %x", r.Body, r.CEK, body, cek)
		}
	}
	if _, err := c.Open(sealed); !errors.Is(err, ErrKeyUnknown) {
		t.Errorf("a third key opened it: %v", err)
	}
}

func TestTheCiphertextIsPaddedToAWholeKiBIncludingItsTag(t *testing.T) {
	id := newIdentity(t)
	for _, n := range []int{0, 1, Pad - tagSize - 4 - 100, 5000} {
		body := bytes.Repeat([]byte("x"), n)
		sealed, _, err := Seal([][]byte{id.PublicKey()}, chatHead, body)
		if err != nil {
			t.Fatal(err)
		}
		ct := len(sealed) - prefixSize - entrySize
		if ct%Pad != 0 || ct < Pad {
			t.Errorf("body of %d: ciphertext of %d bytes", n, ct)
		}
		r, err := id.Open(sealed)
		if err != nil || len(r.Body) != n {
			t.Errorf("body of %d: opened %d bytes, %v", n, len(r.Body), err)
		}
	}
}

func TestEveryMalformedRequestIsInvalidAndNoneIsAnUnknownKey(t *testing.T) {
	id := newIdentity(t)
	sealed, _, err := Seal([][]byte{id.PublicKey()}, chatHead, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	flip := func(at int) []byte {
		b := bytes.Clone(sealed)
		b[at] ^= 1
		return b
	}
	cases := map[string][]byte{
		"empty":            {},
		"version 2":        flip(0),
		"count 0":          flip(1),
		"count 5":          append([]byte{Version, 5}, sealed[2:]...),
		"short entries":    sealed[:prefixSize+entrySize-1],
		"tampered enc":     flip(prefixSize + keyIDSize),
		"tampered wrapped": flip(prefixSize + keyIDSize + encSize),
		"tampered content": flip(len(sealed) - 1),
		"extra byte":       append(bytes.Clone(sealed), 0),
		"no ciphertext":    sealed[:prefixSize+entrySize],
		"short ciphertext": sealed[:len(sealed)-1],
	}
	for name, b := range cases {
		if _, err := id.Open(b); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestTheInnerPlaintextIsHeldToItsHeadBodyLengthAndZeroPadding(t *testing.T) {
	head := []byte(`{"method":"GET","path":"/v1/account","headers":{},"ts":1,"body_len":2}`)
	inner := func(h, body, pad []byte) []byte {
		b := binary.BigEndian.AppendUint32(nil, uint32(len(h)))
		return append(append(append(b, h...), body...), pad...)
	}
	if h, body, err := parseInner(inner(head, []byte("hi"), make([]byte, 7))); err != nil || h.Path != "/v1/account" || string(body) != "hi" {
		t.Errorf("well formed: %+v %q %v", h, body, err)
	}
	bad := map[string][]byte{
		"short":            {0, 0},
		"head past end":    inner(head, nil, nil)[:len(head)],
		"body past end":    inner(head, []byte("h"), nil),
		"nonzero padding":  inner(head, []byte("hi"), []byte{0, 1}),
		"unknown field":    inner([]byte(`{"method":"GET","path":"/","headers":{},"ts":1,"body_len":0,"x":1}`), nil, nil),
		"two documents":    inner([]byte(`{"method":"GET","path":"/","headers":{},"ts":1,"body_len":0}{}`), nil, nil),
		"negative length":  inner([]byte(`{"method":"GET","path":"/","headers":{},"ts":1,"body_len":-1}`), nil, nil),
		"headers not text": inner([]byte(`{"method":"GET","path":"/","headers":{"A":1},"ts":1,"body_len":0}`), nil, nil),
	}
	for name, b := range bad {
		if _, _, err := parseInner(b); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}

func TestAHeadPastMaxHeadIsInvalidAndOverheadBoundsTheSealedBytes(t *testing.T) {
	id := newIdentity(t)
	long := chatHead
	long.Path = "/v1/lookup/x/" + strings.Repeat("a", MaxHead)
	if sealed, _, err := Seal([][]byte{id.PublicKey()}, long, nil); !errors.Is(err, ErrHeadTooLarge) {
		t.Errorf("a head past MaxHead sealed to %d bytes with %v, want ErrHeadTooLarge", len(sealed), err)
	}
	oversized := plaintextOf([]byte(`{"method":"GET","path":"/`+strings.Repeat("a", MaxHead)+`","headers":{},"ts":1,"body_len":0}`), nil)
	if _, _, err := parseInner(oversized); !errors.Is(err, ErrInvalid) {
		t.Errorf("a head past MaxHead parsed: %v", err)
	}
	most := chatHead
	most.Path = "/v1/lookup/x/" + strings.Repeat("a", MaxHead-200)
	keys := [][]byte{id.PublicKey(), newIdentity(t).PublicKey(), newIdentity(t).PublicKey(), newIdentity(t).PublicKey()}
	body := bytes.Repeat([]byte("x"), 3*Pad+1)
	sealed, _, err := Seal(keys, most, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := id.Open(sealed); err != nil || len(sealed) > len(body)+Overhead {
		t.Errorf("a %d-byte body sealed to %d bytes (%v), past its Overhead of %d", len(body), len(sealed), err, Overhead)
	}
}

func TestSealTakesOneToFourKeys(t *testing.T) {
	id := newIdentity(t)
	var keys [][]byte
	for range MaxKeys + 1 {
		keys = append(keys, id.PublicKey())
	}
	if _, _, err := Seal(nil, chatHead, nil); err == nil || !strings.Contains(err.Error(), "0 keys") {
		t.Errorf("no keys: %v", err)
	}
	if _, _, err := Seal(keys, chatHead, nil); err == nil || !strings.Contains(err.Error(), "5 keys") {
		t.Errorf("five keys: %v", err)
	}
	if _, _, err := Seal(keys[:MaxKeys], chatHead, nil); err != nil {
		t.Errorf("four keys: %v", err)
	}
}

func TestAnIdentityFromAKnownKeyIsThatKeyAndItsIDIsTheHashPrefix(t *testing.T) {
	priv := make([]byte, 32)
	rand.Read(priv)
	a, err := IdentityFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := IdentityFromKey(priv)
	if !bytes.Equal(a.PublicKey(), b.PublicKey()) || a.KeyID() != KeyIDOf(a.PublicKey()) || a.KeyID() != b.KeyID() {
		t.Errorf("two identities from one key differ: %x %x", a.PublicKey(), b.PublicKey())
	}
	if _, err := IdentityFromKey(priv[:31]); err == nil {
		t.Error("a 31-byte key was accepted")
	}
}

func TestFreshnessIsWithinTheSkewAndNotBeforeTheStart(t *testing.T) {
	now := time.Unix(1_000_000, 500_000_000)
	long, lately := time.Unix(990_000, 0), time.Unix(999_940, 0)
	cases := []struct {
		ts      int64
		started time.Time
		want    bool
	}{
		{1_000_000, long, true},
		{1_000_000 - 120, long, true},
		{1_000_000 + 120, long, true},
		{1_000_000 - 121, long, false},
		{1_000_000 + 121, long, false},
		{999_940, lately, true},
		{999_939, lately, false},
	}
	for _, c := range cases {
		r := Request{Head: Head{TS: c.ts}}
		if got := r.Fresh(now, c.started); got != c.want {
			t.Errorf("ts %d started %d: fresh %t, want %t", c.ts, c.started.Unix(), got, c.want)
		}
	}
}

func TestARequestIsStaleBeforeItsEncLeavesTheReplayCache(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	for _, ts := range []int64{now.Add(-ReplayWindow).Unix(), now.Add(ReplayWindow).Unix()} {
		if (Request{Head: Head{TS: ts}}).Fresh(now, time.Unix(0, 0)) {
			t.Errorf("ts %d is fresh at %d, so a repeat could outlive the replay cache", ts, now.Unix())
		}
	}
}

func TestAReplayIsRefusedForTheWindowAndForgottenAfterIt(t *testing.T) {
	var replays Replays
	var enc, other [encSize]byte
	enc[0], other[0] = 1, 2
	at := time.Unix(1_000_000, 0)
	if !replays.Admit(enc, at) {
		t.Fatal("the first request was a replay")
	}
	if replays.Admit(enc, at.Add(ReplayWindow-time.Second)) {
		t.Error("a repeat inside the window was admitted")
	}
	if !replays.Admit(other, at) {
		t.Error("another enc was refused")
	}
	if !replays.Admit(enc, at.Add(ReplayWindow)) {
		t.Error("a repeat past the window was refused")
	}
	var third [encSize]byte
	third[0] = 3
	replays.Admit(third, at.Add(ReplayWindow+pruneReplaysEvery))
	if _, kept := replays.seen[other]; kept || len(replays.seen) != 2 {
		t.Errorf("the cache holds %d entries after pruning, and the oldest kept %t", len(replays.seen), kept)
	}
}

func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestABodyIsSealedWhereItLiesAndSealCopiesItOnce(t *testing.T) {
	id := newIdentity(t)
	keys := [][]byte{id.PublicKey()}
	body := bytes.Repeat([]byte("y"), 4<<20)
	var sealed []byte
	copied := allocatedBy(func() { sealed, _, _ = Seal(keys, chatHead, body) })
	if opened, err := id.Open(sealed); err != nil || !bytes.Equal(opened.Body, body) {
		t.Fatalf("Seal's output does not open to the body: %v", err)
	}
	if copied > uint64(len(body))*3/2 {
		t.Errorf("Seal allocated %d MiB for a %d MiB body, want one copy: the body is sealed in the storage it lands in", copied>>20, len(body)>>20)
	}
	var inner Inner
	inner.Grow(1 << 20)
	if err := inner.Fill(bytes.NewReader(body)); err != nil {
		t.Fatalf("a 4 MiB body into 1 MiB of room: %v, want nil with the room full", err)
	}
	inner.Grow(len(body))
	if err := inner.Fill(io.MultiReader(bytes.NewReader(body[inner.Len():len(body)-1]), bytes.NewReader(body[len(body)-1:]))); err != nil || inner.Len() != len(body) {
		t.Fatalf("the rest of the body: %v with %d bytes, want nil with the room full at %d", err, inner.Len(), len(body))
	}
	inner.Grow(len(body) + 1)
	if err := inner.Fill(bytes.NewReader(nil)); !errors.Is(err, io.EOF) || inner.Len() != len(body) {
		t.Fatalf("filling from an ended reader: %v, want io.EOF with the body kept", err)
	}
	inPlace := allocatedBy(func() { sealed, _, _ = inner.Seal(keys, chatHead) })
	if opened, err := id.Open(sealed); err != nil || !bytes.Equal(opened.Body, body) {
		t.Fatalf("an Inner's seal does not open to the body: %v", err)
	}
	if storage := inner.buf[:cap(inner.buf)]; inPlace > 64<<10 || &storage[len(storage)-cap(sealed)] != &sealed[0] {
		t.Errorf("sealing an Inner allocated %d KiB and the sealed request lies elsewhere; want it encrypted in the Inner's own storage", inPlace>>10)
	}
	empty, _, err := (Inner{}).Seal(keys, chatHead)
	if opened, err2 := id.Open(empty); err != nil || err2 != nil || len(opened.Body) != 0 {
		t.Errorf("a zero Inner seals a request without a body: %v %v %q", err, err2, opened.Body)
	}
}
