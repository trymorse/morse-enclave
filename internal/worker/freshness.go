package worker

import (
	"sync"
	"time"

	"morse/backend/internal/e2ee"
)

// why: the browser stamps the request, so a browser clock a few minutes off must still pass.
const sealedSkew = 10 * time.Minute

const pruneNoncesEvery = 30 * time.Second

const SealedNonceLife = 2 * sealedSkew

// why: the set is this instance's own and refuses a replay sent here; the proxy claims the nonce the admission
// carries (ChatAdmission.SealedNonce) in a store every instance shares, which refuses one sent to another instance.
type sealedNonces struct {
	mu     sync.Mutex
	seen   map[string]time.Time
	pruned time.Time
}

func (n *sealedNonces) admit(p e2ee.Params, now time.Time) error {
	at := time.Unix(p.Timestamp(), 0)
	if at.Before(now.Add(-sealedSkew)) || at.After(now.Add(sealedSkew)) {
		return e2ee.ErrStaleTimestamp
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.seen == nil {
		n.seen = map[string]time.Time{}
	}
	if now.Sub(n.pruned) >= pruneNoncesEvery {
		n.pruned = now
		for nonce, kept := range n.seen {
			if now.Sub(kept) >= SealedNonceLife {
				delete(n.seen, nonce)
			}
		}
	}
	if kept, ok := n.seen[p.Nonce()]; ok && now.Sub(kept) < SealedNonceLife {
		return e2ee.ErrNonceReused
	}
	n.seen[p.Nonce()] = now
	return nil
}
