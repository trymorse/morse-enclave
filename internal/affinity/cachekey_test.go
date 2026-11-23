package affinity_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/affinity"
	"morse/backend/internal/catalog"
)

var noon = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

const deepinfra catalog.EndpointID = "deepinfra"

var cacheKeyVendors = []catalog.EndpointID{deepinfra, "morph", "xai", "novita"}

func openingDigest(s string) affinity.Digest { return affinity.DigestOfSum(sha256.Sum256([]byte(s))) }

func TestACacheKeyIsThirtyTwoHexCharactersBothRelaysAgreeOnAllOneUTCDay(t *testing.T) {
	got := key(t, keyBytes).CacheKey(noon, deepinfra, scope(), openingDigest("opening"))
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(got) {
		t.Fatalf("CacheKey is %q, want 32 lowercase hex characters", got)
	}
	pacific := time.FixedZone("PST", -8*3600)
	for name, at := range map[string]time.Time{
		"the other relay":          noon,
		"the day's first second":   time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC),
		"the day's last second":    time.Date(2026, 11, 17, 23, 59, 59, 0, time.UTC),
		"the same instant in PST":  noon.In(pacific),
		"16:00 PST the day before": time.Date(2026, 11, 16, 16, 0, 0, 0, pacific),
	} {
		if again := key(t, keyBytes).CacheKey(at, deepinfra, scope(), openingDigest("opening")); again != got {
			t.Errorf("%s gave %q, want %q", name, again, got)
		}
	}
}

func TestTheSameConversationGetsANewCacheKeyEachUTCDay(t *testing.T) {
	k := key(t, keyBytes)
	seen := map[string]time.Time{}
	for day := range 400 {
		at := noon.AddDate(0, 0, day)
		got := k.CacheKey(at, deepinfra, scope(), openingDigest("opening"))
		if earlier, ok := seen[got]; ok {
			t.Fatalf("%s and %s share the cache key %q", earlier.Format(time.DateOnly), at.Format(time.DateOnly), got)
		}
		seen[got] = at
	}
	midnight := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	if k.CacheKey(midnight.Add(-time.Nanosecond), deepinfra, scope(), openingDigest("opening")) == k.CacheKey(midnight, deepinfra, scope(), openingDigest("opening")) {
		t.Error("the key did not change at UTC midnight")
	}
}

func TestTwoConversationsNeverShareACacheKey(t *testing.T) {
	k := key(t, keyBytes)
	base := k.CacheKey(noon, deepinfra, scope(), openingDigest("opening"))
	otherAccount, otherKey, otherModel, otherTier := scope(), scope(), scope(), scope()
	otherAccount.Owner = affinity.AccountOwner([16]byte{1})
	otherKey.Owner = affinity.CredentialOwner(sha256.Sum256([]byte("sk_two")))
	otherModel.Model = "z-ai/glm-5.3"
	otherTier.Tier = catalog.Anon
	for name, got := range map[string]string{
		"another account": k.CacheKey(noon, deepinfra, otherAccount, openingDigest("opening")),
		"another API key": k.CacheKey(noon, deepinfra, otherKey, openingDigest("opening")),
		"another model":   k.CacheKey(noon, deepinfra, otherModel, openingDigest("opening")),
		"another tier":    k.CacheKey(noon, deepinfra, otherTier, openingDigest("opening")),
		"another opening": k.CacheKey(noon, deepinfra, scope(), openingDigest("another opening")),
		"another secret":  key(t, strings.Repeat("k", 32)).CacheKey(noon, deepinfra, scope(), openingDigest("opening")),
	} {
		if got == base {
			t.Errorf("%s shares the cache key %q", name, got)
		}
	}
	seen := map[string]int{}
	for i := range 20_000 {
		got := k.CacheKey(noon, deepinfra, scope(), affinity.DigestOfSum(sha256.Sum256(binary.BigEndian.AppendUint64(nil, uint64(i)))))
		if j, ok := seen[got]; ok {
			t.Fatalf("conversations %d and %d share the cache key %q", j, i, got)
		}
		seen[got] = i
	}
}

func TestNoDigestOrNoSecretGivesNoCacheKey(t *testing.T) {
	if got := key(t, keyBytes).CacheKey(noon, deepinfra, scope(), affinity.Digest{}); got != "" {
		t.Errorf("no digest gave %q", got)
	}
	if got := (affinity.Key{}).CacheKey(noon, deepinfra, scope(), openingDigest("opening")); got != "" {
		t.Errorf("no secret gave %q", got)
	}
	if got := key(t, keyBytes).CacheKey(noon, "", scope(), openingDigest("opening")); got != "" {
		t.Errorf("no vendor gave %q", got)
	}
}

func TestACacheKeyCarriesNoneOfWhatItIsMadeOfAndNeedsTheSecret(t *testing.T) {
	k := key(t, keyBytes)
	account := [16]byte{0x9a, 0x59, 0xe6, 0x4b, 0xc7, 0x7d, 0x4a, 0xdc, 0x94, 0xc9, 0xec, 0xd6, 0x02, 0xff, 0xde, 0x48}
	s := affinity.Scope{Owner: affinity.AccountOwner(account), Model: "deepseek/deepseek-v4.1-flash-1017", Tier: catalog.Private}
	opening := sha256.Sum256([]byte("opening"))
	d := affinity.DigestOfSum(opening)
	conv := k.Conversation(s, d)
	got := k.CacheKey(noon, deepinfra, s, d)
	day := noon.Format(time.DateOnly)
	for name, part := range map[string][]byte{"account id": account[:], "digest": opening[:], "conversation": conv[:]} {
		for i := 0; i+4 <= len(part); i++ {
			if strings.Contains(got, hex.EncodeToString(part[i:i+4])) {
				t.Errorf("the key %q carries 4 bytes of the %s", got, name)
			}
		}
		for _, unkeyed := range [][]byte{part, append([]byte(day), part...), append(append([]byte{}, part...), day...)} {
			sum := sha256.Sum256(unkeyed)
			if strings.Contains(hex.EncodeToString(sum[:]), got) {
				t.Errorf("the key is an unkeyed hash of the %s", name)
			}
		}
	}
	if strings.Contains(got, conv.Short()) {
		t.Error("the key carries the Short the relay logs")
	}
}

func TestEachVendorGetsItsOwnCacheKeyForTheSameConversationAndDay(t *testing.T) {
	k := key(t, keyBytes)
	for i := range 2_000 {
		d := affinity.DigestOfSum(sha256.Sum256(binary.BigEndian.AppendUint64(nil, uint64(i))))
		seen := map[string]catalog.EndpointID{}
		for _, vendor := range cacheKeyVendors {
			got := k.CacheKey(noon, vendor, scope(), d)
			if other, ok := seen[got]; ok {
				t.Fatalf("conversation %d: %s and %s share the cache key %q", i, other, vendor, got)
			}
			seen[got] = vendor
		}
	}
	if k.CacheKey(noon, "morph", scope(), openingDigest("opening")) != k.CacheKey(noon, "morph", scope(), openingDigest("opening")) {
		t.Error("one vendor was given two keys for one conversation on one day")
	}
}

func TestNoVendorCanComputeAnotherVendorsCacheKeyFromItsOwn(t *testing.T) {
	k := key(t, keyBytes)
	d := openingDigest("opening")
	day := noon.Format(time.DateOnly)
	keys := map[catalog.EndpointID]string{}
	for _, vendor := range cacheKeyVendors {
		keys[vendor] = k.CacheKey(noon, vendor, scope(), d)
	}
	for _, from := range cacheKeyVendors {
		own, _ := hex.DecodeString(keys[from])
		for _, to := range cacheKeyVendors {
			if to == from {
				continue
			}
			for i := 0; i+4 <= len(own); i++ {
				if strings.Contains(keys[to], hex.EncodeToString(own[i:i+4])) {
					t.Errorf("%s's key %q carries 4 bytes of %s's %q", to, keys[to], from, keys[from])
				}
			}
			for name, guess := range map[string][]byte{
				"its key":                own,
				"its key and the vendor": append(slices.Clone(own), to...),
				"the vendor and its key": append([]byte(to), own...),
				"its key, day, vendor":   append(append(slices.Clone(own), day...), to...),
			} {
				sum := sha256.Sum256(guess)
				mac := hmac.New(sha256.New, own)
				mac.Write([]byte(to))
				for _, derived := range [][]byte{sum[:], mac.Sum(nil)} {
					if strings.Contains(hex.EncodeToString(derived), keys[to]) {
						t.Errorf("%s's key is a hash of %s from %s", to, name, from)
					}
				}
			}
		}
	}
}
