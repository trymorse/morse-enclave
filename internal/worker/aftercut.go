package worker

import (
	"context"
	"sync"
	"time"
)

// cutGrace is how long a reply sealed whole goes on being read once its caller left. Its router writes the
// usage it counted only in a trailer after the last frame, so a relay that stopped reading at the cut would
// bill an estimate even for a reply that had all but ended; one still generating after the grace is cut then,
// so a Stop costs at most this much more generation.
var cutGrace = 2 * time.Second

// afterCut keeps a sealed-body run reading after its caller left: writes are dropped from then on, and its
// context ends cutGrace after the caller's, with the caller's cause.
type afterCut struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	unhook func() bool

	mu    sync.Mutex
	left  error
	timer *time.Timer
}

func newAfterCut(run, caller context.Context) *afterCut {
	d := &afterCut{}
	d.ctx, d.cancel = context.WithCancelCause(run)
	d.unhook = context.AfterFunc(caller, func() { d.leave(context.Cause(caller)) })
	return d
}

// leave marks the caller gone, by its context or by a write that failed, and starts the grace once.
func (d *afterCut) leave(cause error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.left != nil {
		return
	}
	d.left = cause
	d.timer = time.AfterFunc(cutGrace, func() { d.cancel(cause) })
}

// gone is why the caller left, or nil while it is there.
func (d *afterCut) gone() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.left
}

func (d *afterCut) stop() {
	d.unhook()
	d.mu.Lock()
	if d.timer != nil {
		d.timer.Stop()
	}
	d.mu.Unlock()
	d.cancel(context.Canceled)
}
