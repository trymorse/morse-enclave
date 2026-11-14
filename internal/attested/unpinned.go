package attested

import (
	"cmp"
	"slices"
	"sync"
	"time"

	"morse/backend/internal/attestation"
)

type UnpinnedRelease struct {
	Vendor    string    `json:"vendor"`
	Field     string    `json:"field"`
	Release   string    `json:"release"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Listed    bool      `json:"listed,omitempty"`
}

const (
	maxKeptReleases = 256
	maxReleaseBytes = 512
)

type UnpinnedReleases struct {
	now  func() time.Time
	mu   sync.Mutex
	seen map[unpinnedKey]UnpinnedRelease
}

type unpinnedKey struct{ vendor, field, release string }

func NewUnpinnedReleases(now func() time.Time) *UnpinnedReleases {
	return &UnpinnedReleases{now: now, seen: map[unpinnedKey]UnpinnedRelease{}}
}

func (u *UnpinnedReleases) Observe(vendor string, ev Event) {
	if ev.Kind != Anchored && ev.Kind != Verified {
		return
	}
	now := u.now()
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, d := range ev.Drift {
		if d.Kind != attestation.DriftRelease || len(d.Observed) > maxReleaseBytes {
			continue
		}
		k := unpinnedKey{vendor, d.Field, d.Observed}
		r, ok := u.seen[k]
		switch {
		case ok:
			r.LastSeen = now
		case len(u.seen) >= maxKeptReleases:
			continue
		default:
			r = UnpinnedRelease{Vendor: vendor, Field: d.Field, Release: d.Observed, FirstSeen: now, LastSeen: now}
		}
		u.seen[k] = r
	}
}

func (u *UnpinnedReleases) Seen() []UnpinnedRelease {
	u.mu.Lock()
	out := make([]UnpinnedRelease, 0, len(u.seen))
	for _, r := range u.seen {
		out = append(out, r)
	}
	u.mu.Unlock()
	slices.SortFunc(out, func(a, b UnpinnedRelease) int {
		return cmp.Or(cmp.Compare(a.Vendor, b.Vendor), cmp.Compare(a.Field, b.Field), cmp.Compare(a.Release, b.Release))
	})
	return out
}
