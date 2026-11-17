package affinity_test

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"morse/backend/internal/affinity"
)

var workerSecret = [32]byte{0x5e, 0xc2, 0xe7}

var partition = []byte("chat-0123456789a")

func TestAWorkersCacheKeyIsThirtyTwoHexCharactersAllOneUTCDayAndNewTheNext(t *testing.T) {
	k := affinity.NewWorkerKey(workerSecret)
	got := k.CacheKey(noon, deepinfra, "z-ai/glm-5.3", partition, openingDigest("opening"))
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(got) {
		t.Fatalf("CacheKey is %q, want 32 lowercase hex characters", got)
	}
	for name, at := range map[string]time.Time{
		"the day's first second":   time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC),
		"the day's last second":    time.Date(2026, 11, 17, 23, 59, 59, 0, time.UTC),
		"16:00 PST the day before": time.Date(2026, 11, 16, 16, 0, 0, 0, time.FixedZone("PST", -8*3600)),
	} {
		if again := k.CacheKey(at, deepinfra, "z-ai/glm-5.3", partition, openingDigest("opening")); again != got {
			t.Errorf("%s gave %q, want %q", name, again, got)
		}
	}
	seen := map[string]int{}
	for day := range 400 {
		key := k.CacheKey(noon.AddDate(0, 0, day), deepinfra, "z-ai/glm-5.3", partition, openingDigest("opening"))
		if earlier, ok := seen[key]; ok {
			t.Fatalf("days %d and %d share the cache key %q", earlier, day, key)
		}
		seen[key] = day
	}
}

func TestAWorkersCacheKeyIsApartForEachVendorModelPartitionOpeningAndSecretAndFromTheRelays(t *testing.T) {
	k := affinity.NewWorkerKey(workerSecret)
	base := k.CacheKey(noon, deepinfra, "z-ai/glm-5.3", partition, openingDigest("opening"))
	for name, got := range map[string]string{
		"another vendor":     k.CacheKey(noon, "morph", "z-ai/glm-5.3", partition, openingDigest("opening")),
		"another model":      k.CacheKey(noon, deepinfra, "z-ai/glm-5.3-flash", partition, openingDigest("opening")),
		"another opening":    k.CacheKey(noon, deepinfra, "z-ai/glm-5.3", partition, openingDigest("another opening")),
		"another partition":  k.CacheKey(noon, deepinfra, "z-ai/glm-5.3", []byte("chat-0123456789b"), openingDigest("opening")),
		"another secret":     affinity.NewWorkerKey([32]byte{1}).CacheKey(noon, deepinfra, "z-ai/glm-5.3", partition, openingDigest("opening")),
		"the relay's secret": key(t, string(workerSecret[:])).CacheKey(noon, deepinfra, affinity.Scope{Model: "z-ai/glm-5.3"}, openingDigest("opening")),
	} {
		if got == base {
			t.Errorf("%s shares the cache key %q", name, got)
		}
	}
	seen := map[string]string{}
	for i := range 2_000 {
		d := affinity.DigestOfSum(sha256.Sum256(binary.BigEndian.AppendUint64(nil, uint64(i))))
		for _, vendor := range cacheKeyVendors {
			got := k.CacheKey(noon, vendor, "z-ai/glm-5.3", partition, d)
			if earlier, ok := seen[got]; ok {
				t.Fatalf("conversation %d at %s shares the cache key %q with %s", i, vendor, got, earlier)
			}
			seen[got] = fmt.Sprintf("conversation %d at %s", i, vendor)
		}
	}
}

func TestAWorkersCacheKeyNeedsADigestASecretAVendorAndAPartitionAndCarriesNoneOfTheOpening(t *testing.T) {
	k := affinity.NewWorkerKey(workerSecret)
	for name, got := range map[string]string{
		"no digest":           k.CacheKey(noon, deepinfra, "z-ai/glm-5.3", partition, affinity.Digest{}),
		"no secret":           (affinity.WorkerKey{}).CacheKey(noon, deepinfra, "z-ai/glm-5.3", partition, openingDigest("opening")),
		"no vendor":           k.CacheKey(noon, "", "z-ai/glm-5.3", partition, openingDigest("opening")),
		"no partition":        k.CacheKey(noon, deepinfra, "z-ai/glm-5.3", nil, openingDigest("opening")),
		"a 15-byte partition": k.CacheKey(noon, deepinfra, "z-ai/glm-5.3", partition[:15], openingDigest("opening")),
	} {
		if got != "" {
			t.Errorf("%s gave %q", name, got)
		}
	}
	opening := sha256.Sum256([]byte("opening"))
	got := k.CacheKey(noon, deepinfra, "z-ai/glm-5.3", partition, affinity.DigestOfSum(opening))
	for name, part := range map[string][]byte{"digest": opening[:], "secret": workerSecret[:3], "partition": partition} {
		for i := 0; i+3 <= len(part); i++ {
			if strings.Contains(got, hex.EncodeToString(part[i:i+3])) {
				t.Errorf("the key %q carries 3 bytes of the %s", got, name)
			}
		}
	}
	for _, unkeyed := range [][]byte{opening[:], append([]byte(noon.Format(time.DateOnly)), opening[:]...), append([]byte(deepinfra), opening[:]...)} {
		sum := sha256.Sum256(unkeyed)
		if strings.Contains(hex.EncodeToString(sum[:]), got) {
			t.Error("the key is an unkeyed hash of the opening")
		}
	}
	for _, printed := range []string{fmt.Sprint(k), fmt.Sprintf("%#v", k), fmt.Sprintf("%+v", k)} {
		if printed != "affinity.WorkerKey(redacted)" {
			t.Errorf("a WorkerKey prints as %s", printed)
		}
	}
}
