package door

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

var (
	errClientFull = errors.New("door: the client already holds its share of the door's connections")
	errDoorFull   = errors.New("door: every connection belongs to a client holding too few to give one up")
)

type entrance struct {
	proxyV2   bool
	peers     []netip.Prefix
	timeout   time.Duration
	handshake time.Duration
	report    func(ConnectionRefusal)
	most      int
	line      int
	share     int

	mu      sync.Mutex
	pending []*doorConn
	open    map[*doorConn]struct{}
	clients map[netip.Prefix]int
}

type gate struct {
	net.Listener
	e *entrance
}

func (g gate) Accept() (net.Conn, error) {
	for {
		raw, err := g.Listener.Accept()
		if err != nil {
			return nil, err
		}
		peer, _ := netip.ParseAddrPort(raw.RemoteAddr().String())
		if g.e.proxyV2 && !g.e.trusts(peer.Addr()) {
			raw.Close()
			g.e.report(UntrustedPeer)
			continue
		}
		c := &doorConn{Conn: raw, e: g.e, peer: peer, accepted: time.Now()}
		g.e.arrive(c)
		return c, nil
	}
}

func (e *entrance) trusts(peer netip.Addr) bool {
	for _, p := range e.peers {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

func (e *entrance) arrive(c *doorConn) {
	e.mu.Lock()
	if e.open == nil {
		e.open, e.clients = map[*doorConn]struct{}{}, map[netip.Prefix]int{}
	}
	var evicted *doorConn
	if len(e.pending) >= e.line {
		evicted = e.pending[rand.IntN(len(e.pending))]
		e.unqueue(evicted)
	}
	c.slot = len(e.pending)
	e.pending = append(e.pending, c)
	e.mu.Unlock()
	if evicted != nil {
		evicted.Conn.Close()
	}
}

func (e *entrance) queued(c *doorConn) bool {
	return c.slot < len(e.pending) && e.pending[c.slot] == c
}

func (e *entrance) unqueue(c *doorConn) {
	if !e.queued(c) {
		return
	}
	last := e.pending[len(e.pending)-1]
	e.pending[c.slot], last.slot = last, c.slot
	e.pending[len(e.pending)-1] = nil
	e.pending = e.pending[:len(e.pending)-1]
}

func (e *entrance) join(c *doorConn, client netip.Prefix) error {
	e.mu.Lock()
	if !e.queued(c) {
		e.mu.Unlock()
		return net.ErrClosed
	}
	e.unqueue(c)
	held := e.clients[client]
	var evicted *doorConn
	switch {
	case held >= e.share:
		if evicted = e.oldestWaitingOf(client); evicted == nil {
			e.mu.Unlock()
			return errClientFull
		}
	case len(e.open) >= e.most:
		if evicted = cmp.Or(e.yielding(held), e.oldestWaitingOf(client)); evicted == nil {
			e.mu.Unlock()
			return errDoorFull
		}
	}
	if evicted != nil {
		e.dropLocked(evicted)
	}
	c.client, c.since = client, time.Now()
	e.open[c] = struct{}{}
	e.clients[client]++
	e.mu.Unlock()
	if evicted != nil {
		evicted.Conn.Close()
	}
	return nil
}

func (e *entrance) yielding(newcomer int) *doorConn {
	var pick *doorConn
	for c := range e.open {
		if held := e.clients[c.client]; held <= newcomer || c.busy && held <= newcomer+1 {
			continue
		}
		if pick == nil || e.yieldsBefore(c, pick) {
			pick = c
		}
	}
	return pick
}

func (e *entrance) yieldsBefore(a, b *doorConn) bool {
	if ha, hb := e.clients[a.client], e.clients[b.client]; ha != hb {
		return ha > hb
	}
	if a.busy != b.busy {
		return !a.busy
	}
	if a.busy {
		return a.since.After(b.since)
	}
	return a.since.Before(b.since)
}

func (e *entrance) oldestWaitingOf(client netip.Prefix) *doorConn {
	var oldest *doorConn
	for c := range e.open {
		if c.served && !c.busy && c.client == client && (oldest == nil || c.since.Before(oldest.since)) {
			oldest = c
		}
	}
	return oldest
}

func (e *entrance) dropLocked(c *doorConn) {
	e.unqueue(c)
	if _, open := e.open[c]; !open {
		return
	}
	delete(e.open, c)
	if e.clients[c.client]--; e.clients[c.client] == 0 {
		delete(e.clients, c.client)
	}
}

func (e *entrance) leave(c *doorConn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dropLocked(c)
}

func doorConnOf(conn net.Conn) *doorConn {
	if tc, ok := conn.(*tls.Conn); ok {
		conn = tc.NetConn()
	}
	c, _ := conn.(*doorConn)
	return c
}

type connKey struct{}

func withConn(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, doorConnOf(conn))
}

func (e *entrance) markBusy(ctx context.Context) {
	if c, _ := ctx.Value(connKey{}).(*doorConn); c != nil {
		e.mu.Lock()
		c.busy = true
		e.mu.Unlock()
	}
}

func (e *entrance) track(conn net.Conn, state http.ConnState) {
	c := doorConnOf(conn)
	if c == nil {
		return
	}
	switch state {
	case http.StateIdle:
		e.mu.Lock()
		c.busy, c.served, c.since = false, true, time.Now()
		e.mu.Unlock()
	case http.StateHijacked, http.StateClosed:
		e.leave(c)
	}
}

type doorConn struct {
	net.Conn
	e        *entrance
	peer     netip.AddrPort
	accepted time.Time
	slot     int
	once     sync.Once
	source   netip.AddrPort
	err      error

	client netip.Prefix
	busy   bool
	served bool
	since  time.Time
}

func (c *doorConn) identify() {
	c.once.Do(func() {
		if c.e.proxyV2 {
			c.Conn.SetReadDeadline(time.Now().Add(c.e.timeout))
			c.source, c.err = readHeader(c.Conn)
			c.Conn.SetReadDeadline(c.accepted.Add(c.e.handshake))
			if c.err != nil {
				c.e.report(refusalOf(c.err))
				return
			}
		}
		client := c.peer
		if c.source.IsValid() {
			client = c.source
		}
		switch c.err = c.e.join(c, clientOf(client.Addr())); {
		case errors.Is(c.err, errClientFull):
			c.e.report(ClientFull)
		case errors.Is(c.err, errDoorFull):
			c.e.report(DoorFull)
		}
	})
}

func (c *doorConn) Read(p []byte) (int, error) {
	c.identify()
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}

func (c *doorConn) RemoteAddr() net.Addr {
	c.identify()
	if !c.source.IsValid() {
		return c.Conn.RemoteAddr()
	}
	return net.TCPAddrFromAddrPort(c.source)
}
