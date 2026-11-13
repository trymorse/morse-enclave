package taskrun

import (
	"math"
	"sync"

	"morse/backend/internal/uuid"
)

type ID [16]byte

func ParseID(s string) (ID, bool) {
	if !IsID(s) {
		return ID{}, false
	}
	return uuid.Parse(s)
}

func (id ID) String() string { return uuid.Format(id) }

func IsID(s string) bool {
	id, ok := uuid.Parse(s)
	return ok && uuid.Format(id) == s
}

type Floors struct {
	mu sync.Mutex
	of map[ID]revs
}

type revs struct{ floor, issued int64 }

func (f *Floors) Reserve(task ID, rev int64) (int64, bool) { return f.reserve(task, rev, false) }

func (f *Floors) reserve(task ID, rev int64, finish bool) (int64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.of[task]
	if rev < 0 || finish && r.floor != rev {
		return 0, false
	}
	top := max(rev, r.floor, r.issued)
	if top == math.MaxInt64 {
		return 0, false
	}
	if f.of == nil {
		f.of = map[ID]revs{}
	}
	r.issued = top + 1
	if !finish {
		r.floor = r.issued
	}
	f.of[task] = r
	return r.issued, true
}

func (f *Floors) Admit(task ID, rev int64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.of[task]
	if rev < r.floor {
		return false
	}
	if f.of == nil {
		f.of = map[ID]revs{}
	}
	r.floor = rev
	f.of[task] = r
	return true
}
