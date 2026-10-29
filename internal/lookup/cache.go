package lookup

import (
	"container/list"
	"sync"
	"time"
)

type cache struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int
	bytes      int
	order      *list.List
	byKey      map[string]*list.Element
}

type entry struct {
	key     string
	body    []byte
	expires time.Time
}

func newCache(maxEntries, maxBytes int) *cache {
	return &cache{maxEntries: maxEntries, maxBytes: maxBytes, order: list.New(), byKey: map[string]*list.Element{}}
}

func (c *cache) get(key string, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byKey[key]
	if !ok {
		return nil, false
	}
	e := el.Value.(*entry)
	if !now.Before(e.expires) {
		c.remove(el)
		return nil, false
	}
	c.order.MoveToFront(el)
	return e.body, true
}

func (c *cache) put(key string, body []byte, expires time.Time) {
	if len(body) > c.maxBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byKey[key]; ok {
		c.remove(el)
	}
	c.byKey[key] = c.order.PushFront(&entry{key: key, body: body, expires: expires})
	c.bytes += len(body)
	for c.order.Len() > c.maxEntries || c.bytes > c.maxBytes {
		c.remove(c.order.Back())
	}
}

func (c *cache) remove(el *list.Element) {
	e := c.order.Remove(el).(*entry)
	delete(c.byKey, e.key)
	c.bytes -= len(e.body)
}
