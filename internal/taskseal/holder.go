package taskseal

import (
	"errors"
	"sync"
	"time"
)

// ErrSettled refuses a key handed to a worker that already settled on one: the key it settled on seals its bundles.
var ErrSettled = errors.New("taskseal: this worker already settled on a task key")

// SettleReason is why a worker settled on a key of its own instead of taking a peer's.
type SettleReason string

const (
	// NoPeer is a worker with no peer it could take a key from, or with handoffs off.
	NoPeer SettleReason = "no_peer"
	// KeyExpired is a worker whose peer's key is past its age limit: the key is replaced, and its tasks sealed again.
	KeyExpired SettleReason = "key_expired"
	// NoHandoff is a worker whose peers handed it nothing in time, though it had some to ask.
	NoHandoff SettleReason = "no_handoff"
)

func (r SettleReason) Valid() bool { return r == NoPeer || r == KeyExpired || r == NoHandoff }

// Standing is a holder's key as its host reports it: the epoch once it settled, whether it took that key from a peer,
// and why it made do with its own when it did not.
type Standing struct {
	Epoch   Epoch
	Settled bool
	Taken   bool
	Why     SettleReason
}

// Holder is a worker's task key. A worker that may take its key from a peer enclave starts pending: it holds a key of
// its own, under which it seals and opens nothing, until it takes the peer's or settles on its own, so no bundle is
// sealed under a key about to be replaced. It settles once.
type Holder struct {
	mu      sync.Mutex
	key     *Key
	born    time.Time
	settled bool
	taken   bool
	why     SettleReason
}

// Settled holds key, made at born, from the start.
func Settled(key *Key, born time.Time) *Holder {
	return &Holder{key: key, born: born, settled: true, why: NoPeer}
}

// Pending holds key, made at born, until it takes another or settles on it.
func Pending(key *Key, born time.Time) *Holder { return &Holder{key: key, born: born} }

// Key is the key bundles are sealed and opened under, and false while the holder is pending.
func (h *Holder) Key() (*Key, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.settled {
		return nil, false
	}
	return h.key, true
}

// State is the epoch of the key the holder settled on, and false while it is pending.
func (h *Holder) State() (Epoch, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.settled {
		return Epoch{}, false
	}
	return h.key.epoch, true
}

func (h *Holder) Standing() Standing {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.settled {
		return Standing{}
	}
	return Standing{Epoch: h.key.epoch, Settled: true, Taken: h.taken, Why: h.why}
}

// Held is the settled key's secret and when it was first made, which a handoff carries, and false while pending.
func (h *Holder) Held() ([secretSize]byte, time.Time, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.settled {
		return [secretSize]byte{}, time.Time{}, false
	}
	return h.key.secret, h.born, true
}

// Take settles on the key a peer handed over, first made at born. ErrSettled once the holder settled.
func (h *Holder) Take(secret [secretSize]byte, born time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.settled {
		return ErrSettled
	}
	h.key, h.born, h.settled, h.taken = KeyFromSecret(secret), born, true, true
	return nil
}

// Settle settles on the holder's own key for why, and does nothing once it settled.
func (h *Holder) Settle(why SettleReason) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.settled {
		h.settled, h.why = true, why
	}
}

// SettleAfter settles on the holder's own key d from now, unless it settled first.
func (h *Holder) SettleAfter(d time.Duration) {
	time.AfterFunc(d, func() { h.Settle(NoHandoff) })
}
