package phala

import (
	"encoding/json"
	"expvar"
	"sync"
	"time"
)

const (
	keptReceiptBytes = 16 << 20
	keepReceiptFor   = 10 * time.Minute
)

var receiptsKept = expvar.NewMap("receipts_kept")

// kept answers the receipts the billing proof fetched again, since the gateway runs several replicas and one
// can answer 404 for a receipt another issued.
var kept = receiptCache{byID: map[string]keptReceipt{}, limit: keptReceiptBytes, now: time.Now}

type keptReceipt struct {
	raw   json.RawMessage
	until time.Time
}

type receiptCache struct {
	mu       sync.Mutex
	byID     map[string]keptReceipt
	byExpiry []string
	bytes    int
	limit    int
	now      func() time.Time
}

func (c *receiptCache) put(id string, raw json.RawMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.byID[id]; ok {
		return
	}
	c.byID[id] = keptReceipt{raw: raw, until: c.now().Add(keepReceiptFor)}
	c.byExpiry = append(c.byExpiry, id)
	c.bytes += len(raw)
	for len(c.byExpiry) > 0 && (c.bytes > c.limit || !c.now().Before(c.byID[c.byExpiry[0]].until)) {
		c.bytes -= len(c.byID[c.byExpiry[0]].raw)
		delete(c.byID, c.byExpiry[0])
		c.byExpiry = c.byExpiry[1:]
	}
}

func (c *receiptCache) get(id string) (json.RawMessage, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.byID[id]
	return r.raw, ok && c.now().Before(r.until)
}
