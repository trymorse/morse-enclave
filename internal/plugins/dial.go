package plugins

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"morse/backend/internal/web"
)

var errNotPublic = errors.New("plugins: a server's name resolved to an address that isn't public")

// NewClient is the client the worker calls plugins with. It connects only to public addresses, whatever a
// server's name resolves to, so no record can point a call at the host, its network, or the enclave's own, and
// it takes no proxy from the environment.
func NewClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: publicOnly}
	return &http.Client{Transport: &http.Transport{
		DialContext:         dialer.DialContext,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		// As long as a call may take: a vendor can hold a slow call's headers until it answers, and one cut early may
		// have acted, which leaves a write that can't be retried.
		ResponseHeaderTimeout:  callTimeout,
		MaxResponseHeaderBytes: 64 << 10,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        90 * time.Second,
	}}
}

func publicOnly(_, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	if !web.PublicAddr(addrPort.Addr().WithZone("").Unmap()) {
		return errNotPublic
	}
	return nil
}
