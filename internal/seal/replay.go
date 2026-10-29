package seal

import (
	"sync"
	"time"
)

const ReplayWindow = 2 * MaxSkew

const pruneReplaysEvery = 10 * time.Second

type Replays struct {
	mu     sync.Mutex
	seen   map[[encSize]byte]time.Time
	pruned time.Time
}

func (r *Replays) Admit(enc [encSize]byte, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[[encSize]byte]time.Time{}
	}
	if now.Sub(r.pruned) >= pruneReplaysEvery {
		r.pruned = now
		for e, at := range r.seen {
			if now.Sub(at) >= ReplayWindow {
				delete(r.seen, e)
			}
		}
	}
	if at, ok := r.seen[enc]; ok && now.Sub(at) < ReplayWindow {
		return false
	}
	r.seen[enc] = now
	return true
}
