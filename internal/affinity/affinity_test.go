package affinity_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"regexp"
	"strings"
	"testing"

	"morse/backend/internal/affinity"
	"morse/backend/internal/catalog"
)

const keyBytes = "0123456789abcdef0123456789abcdef"

func key(t *testing.T, raw string) affinity.Key {
	t.Helper()
	k, err := affinity.ParseKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func scope() affinity.Scope {
	return affinity.Scope{Owner: affinity.CredentialOwner(sha256.Sum256([]byte("sk_one"))), Model: "z-ai/glm-5.3-flash", Tier: catalog.Private}
}

func conversations(t *testing.T, n int) []affinity.Conversation {
	t.Helper()
	k := key(t, keyBytes)
	out := make([]affinity.Conversation, n)
	for i := range out {
		out[i] = k.Conversation(scope(), affinity.DigestOfSum(sha256.Sum256(binary.BigEndian.AppendUint64(nil, uint64(i)))))
	}
	return out
}

func TestTwoRelaysWithOneKeyNameOneConversationAndAnyChangeOfScopeOrDigestNamesAnother(t *testing.T) {
	digest := affinity.DigestOfSum(sha256.Sum256([]byte("opening")))
	base := key(t, keyBytes).Conversation(scope(), digest)
	if again := key(t, keyBytes).Conversation(scope(), digest); again != base {
		t.Error("two keys built from the same bytes name the same conversation differently")
	}
	otherOwner, otherModel, otherTier := scope(), scope(), scope()
	otherOwner.Owner = affinity.AccountOwner([16]byte{1})
	otherModel.Model = "z-ai/glm-5.3"
	otherTier.Tier = catalog.Anon
	for name, got := range map[string]affinity.Conversation{
		"owner":  key(t, keyBytes).Conversation(otherOwner, digest),
		"model":  key(t, keyBytes).Conversation(otherModel, digest),
		"tier":   key(t, keyBytes).Conversation(otherTier, digest),
		"digest": key(t, keyBytes).Conversation(scope(), affinity.DigestOfSum(sha256.Sum256([]byte("another opening")))),
		"key":    key(t, strings.Repeat("k", 32)).Conversation(scope(), digest),
	} {
		if got == base {
			t.Errorf("changing the %s left the conversation unchanged", name)
		}
	}
	if key(t, keyBytes).Conversation(scope(), affinity.Digest{}) == key(t, keyBytes).Conversation(scope(), affinity.DigestOfSum([32]byte{})) {
		t.Error("no digest and a digest of all zero bytes name one conversation")
	}
}

func TestAKeyNeedsThirtyTwoBytes(t *testing.T) {
	if _, err := affinity.ParseKey(keyBytes[:31]); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("31 bytes parsed with %v, want an error naming 32 bytes", err)
	}
	if k := key(t, keyBytes); !k.Set() {
		t.Error("32 bytes parsed as an unset key")
	}
	if k := key(t, ""); k.Set() {
		t.Error("the empty string parsed as a set key")
	}
}

var draws = map[string]func(affinity.Conversation, affinity.Share) bool{
	"Ramped": affinity.Conversation.Ramped,
	"Spread": affinity.Conversation.Spread,
	"Canary": affinity.Conversation.Canary,
}

func TestEachDrawIsAllOrNothingAtItsEndsAndOnlyEverGrows(t *testing.T) {
	convs := conversations(t, 10_000)
	shares := []affinity.Share{0, 500, 1_000, 5_000, 10_000}
	for name, draw := range draws {
		for _, c := range convs[:1_000] {
			if !draw(c, affinity.WholeShare) || draw(c, 0) {
				t.Fatalf("%s %s: whole %t zero %t", name, c.Short(), draw(c, affinity.WholeShare), draw(c, 0))
			}
		}
		for _, c := range convs {
			was := false
			for _, share := range shares {
				now := draw(c, share)
				if was && !now {
					t.Fatalf("%s %s left the share when it rose to %d", name, c.Short(), share)
				}
				was = now
			}
		}
	}
}

func straddle(j int) (lo, hi uint64, share affinity.Share) {
	step := uint64(1) << (8 * (7 - j))
	for m := uint64(1); ; m++ {
		q, r := bits.Div64(m, 0, uint64(affinity.WholeShare))
		if r != 0 {
			q++
		}
		hi = (q + step - 1) / step * step
		if byte(hi>>(8*(7-j))) != 0 {
			return hi - step, hi, affinity.Share(m)
		}
	}
}

const shortStart = len(affinity.Conversation{}) - 8

func readsByte(draw func(affinity.Conversation, affinity.Share) bool, q int) bool {
	for start := max(0, q-7); start <= min(q, shortStart); start++ {
		lo, hi, share := straddle(q - start)
		var a, b affinity.Conversation
		binary.BigEndian.PutUint64(a[start:], lo)
		binary.BigEndian.PutUint64(b[start:], hi)
		if draw(a, share) != draw(b, share) {
			return true
		}
	}
	return false
}

func TestEachDrawReadsItsOwnBits(t *testing.T) {
	readBy := map[int]string{}
	for name, draw := range draws {
		read := 0
		for q := range len(affinity.Conversation{}) {
			if !readsByte(draw, q) {
				continue
			}
			read++
			if other, taken := readBy[q]; taken {
				t.Errorf("%s and %s both read byte %d, so one draw's outcome predicts the other's", other, name, q)
			}
			if q >= shortStart {
				t.Errorf("%s reads byte %d, which Short logs", name, q)
			}
			readBy[q] = name
		}
		if read != 8 {
			t.Errorf("%s reads %d bytes, want 8", name, read)
		}
	}
}

func TestRendezvousPicksAMemberStaysWhenALoserLeavesAndSharesEvenly(t *testing.T) {
	ids := []catalog.EndpointID{"a", "b", "c"}
	wins := map[catalog.EndpointID]int{}
	convs := conversations(t, 100_000)
	for _, c := range convs {
		home := c.Rendezvous(ids)
		if home != "a" && home != "b" && home != "c" {
			t.Fatalf("%s drew %q", c.Short(), home)
		}
		wins[home]++
		var rest []catalog.EndpointID
		for _, id := range ids {
			if id != home {
				rest = append(rest, id)
			}
		}
		if moved := c.Rendezvous(append(rest[:1:1], home)); moved != home {
			t.Fatalf("%s moved from %q to %q when %q left", c.Short(), home, moved, rest[1])
		}
	}
	for _, id := range ids {
		if share := float64(wins[id]) / float64(len(convs)); share < 0.30 || share > 0.37 {
			t.Errorf("%q is home to %.1f%% of conversations", id, 100*share)
		}
	}
	if convs[0].Rendezvous(nil) != "" {
		t.Error("no ids drew an endpoint")
	}
}

func TestShortNamesTheConversationFromBytesNoDrawReads(t *testing.T) {
	hexes := regexp.MustCompile(`^[0-9a-f]{16}$`)
	for _, c := range conversations(t, 1_000) {
		short := c.Short()
		if !hexes.MatchString(short) {
			t.Fatalf("Short is %q", short)
		}
		if strings.Contains(hex.EncodeToString(c[:24]), short) {
			t.Fatalf("Short %q appears in the bytes the draws read", short)
		}
	}
}

func TestADigestCrossesAsSixtyFourHexCharactersAndNothingElse(t *testing.T) {
	sum := sha256.Sum256([]byte("opening"))
	text, err := affinity.DigestOfSum(sum).MarshalText()
	if err != nil || len(text) != 64 {
		t.Fatalf("marshalled %q, %v", text, err)
	}
	var back affinity.Digest
	if err := back.UnmarshalText(text); err != nil || back != affinity.DigestOfSum(sum) || back.IsZero() {
		t.Errorf("round trip gave %#v, %v", back, err)
	}
	for name, bad := range map[string]string{"63 hex": string(text[:63]), "non-hex": strings.Repeat("g", 64), "empty": ""} {
		var d affinity.Digest
		if err := d.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("%s unmarshalled", name)
		}
	}
}

func TestNoFormattingLeaksAKeyADigestOrAConversation(t *testing.T) {
	k := key(t, keyBytes)
	sum := sha256.Sum256([]byte("opening"))
	d := affinity.DigestOfSum(sum)
	c := k.Conversation(scope(), d)
	for name, s := range map[string]string{
		"key %s": fmt.Sprintf("%s", k), "key %v": fmt.Sprintf("%v", k), "key %#v": fmt.Sprintf("%#v", k), "key %+v": fmt.Sprintf("%+v", k),
		"digest %s": fmt.Sprintf("%s", d), "digest %v": fmt.Sprintf("%v", d), "digest %#v": fmt.Sprintf("%#v", d),
		"conversation %s": fmt.Sprintf("%s", c), "conversation %v": fmt.Sprintf("%v", c), "conversation %#v": fmt.Sprintf("%#v", c),
	} {
		for _, secret := range []string{keyBytes, hex.EncodeToString(sum[:8]), hex.EncodeToString(c[:8]), c.Short()} {
			if strings.Contains(s, secret) {
				t.Errorf("%s prints %q, which carries %q", name, s, secret)
			}
		}
	}
}
