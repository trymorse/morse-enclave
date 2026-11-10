package privacyveil

import (
	"container/list"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

// Namespace keeps the partitions a sealed client chooses apart from those the relay chooses, so neither can name
// the other's.
type Namespace uint8

const (
	SealedPartition Namespace = iota + 1
	RelayPartition
)

// MinSealedPartition is the fewest random bytes a sealed client's partition needs to be cached at all.
const MinSealedPartition = 16

// A Cache keeps, for a while, where in a segment's text the filter found details: spans only, never the text, keyed
// by an HMAC under a key drawn at boot, which dies with the process. A segment a client sends again in its partition
// is not scanned again.
type Cache struct {
	mu       sync.Mutex
	secret   [32]byte
	ttl      time.Duration
	maxBytes int
	bytes    int
	now      func() time.Time
	entries  map[[32]byte]*list.Element
	order    *list.List
}

type cacheEntry struct {
	key   [32]byte
	spans []Span
	at    time.Time
	size  int
}

const cacheEntryOverhead = 96

func NewCache(maxBytes int, ttl time.Duration, now func() time.Time) *Cache {
	c := &Cache{ttl: ttl, maxBytes: maxBytes, now: now, entries: map[[32]byte]*list.Element{}, order: list.New()}
	rand.Read(c.secret[:])
	return c
}

func (c *Cache) id(ns Namespace, partition []byte, text string) ([32]byte, bool) {
	if c == nil || len(partition) == 0 || ns == SealedPartition && len(partition) < MinSealedPartition {
		return [32]byte{}, false
	}
	mac := hmac.New(sha256.New, c.secret[:])
	mac.Write([]byte{byte(ns)})
	mac.Write(binary.AppendUvarint(nil, uint64(len(partition))))
	mac.Write(partition)
	mac.Write([]byte(text))
	var id [32]byte
	copy(id[:], mac.Sum(nil))
	return id, true
}

// Get is the spans cached for text in the partition, and false when none are, or they are older than the TTL.
func (c *Cache) Get(ns Namespace, partition []byte, text string) ([]Span, bool) {
	id, ok := c.id(ns, partition, text)
	if !ok {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[id]
	if !ok {
		return nil, false
	}
	e := el.Value.(*cacheEntry)
	if c.now().Sub(e.at) > c.ttl {
		c.remove(el)
		return nil, false
	}
	c.order.MoveToFront(el)
	return append([]Span(nil), e.spans...), true
}

// Put keeps the spans found in text, evicting the least recently used entries past the byte cap.
func (c *Cache) Put(ns Namespace, partition []byte, text string, spans []Span) {
	id, ok := c.id(ns, partition, text)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[id]; ok {
		c.remove(el)
	}
	e := &cacheEntry{key: id, spans: append([]Span(nil), spans...), at: c.now(), size: cacheEntryOverhead + 24*len(spans)}
	if e.size > c.maxBytes {
		return
	}
	c.entries[id] = c.order.PushFront(e)
	c.bytes += e.size
	for c.bytes > c.maxBytes {
		c.remove(c.order.Back())
	}
}

func (c *Cache) remove(el *list.Element) {
	e := el.Value.(*cacheEntry)
	c.order.Remove(el)
	delete(c.entries, e.key)
	c.bytes -= e.size
}
