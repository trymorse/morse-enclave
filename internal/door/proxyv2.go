package door

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"

	"morse/backend/internal/enum"
)

type ConnectionRefusal uint8

const (
	NoProxyHeader ConnectionRefusal = iota + 1
	BadProxyHeader
	SlowProxyHeader
	UntrustedPeer
	DoorFull
	ClientFull
)

var refusalNames = enum.Names[ConnectionRefusal]{NoProxyHeader: "no_proxy_header", BadProxyHeader: "bad_proxy_header", SlowProxyHeader: "slow_proxy_header", UntrustedPeer: "untrusted_peer", DoorFull: "door_full", ClientFull: "client_full"}

func (r ConnectionRefusal) String() string { return refusalNames.String(r) }

var proxyV2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

const (
	proxyV2Fixed  = 16
	proxyV2Local  = 0x20
	proxyV2Proxy  = 0x21
	proxyV2Unspec = 0x00
	proxyV2TCP4   = 0x11
	proxyV2TCP6   = 0x21
	maxHeaderTail = 512
)

var (
	errNoProxyHeader  = errors.New("door: the connection opened without a PROXY v2 header")
	errBadProxyHeader = errors.New("door: the PROXY v2 header is malformed")
)

func readHeader(r io.Reader) (netip.AddrPort, error) {
	var fixed [proxyV2Fixed]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %w", errNoProxyHeader, err)
	}
	if !bytes.Equal(fixed[:len(proxyV2Signature)], proxyV2Signature) {
		return netip.AddrPort{}, errNoProxyHeader
	}
	command, family, length := fixed[12], fixed[13], int(binary.BigEndian.Uint16(fixed[14:]))
	if length > maxHeaderTail {
		return netip.AddrPort{}, errBadProxyHeader
	}
	tail := make([]byte, length)
	if _, err := io.ReadFull(r, tail); err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: %w", errBadProxyHeader, err)
	}
	switch {
	case command == proxyV2Local, command == proxyV2Proxy && family == proxyV2Unspec:
		return netip.AddrPort{}, nil
	case command != proxyV2Proxy:
		return netip.AddrPort{}, errBadProxyHeader
	case family == proxyV2TCP4 && len(tail) >= 12:
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(tail[0:4])), binary.BigEndian.Uint16(tail[8:10])), nil
	case family == proxyV2TCP6 && len(tail) >= 36:
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(tail[0:16])), binary.BigEndian.Uint16(tail[32:34])), nil
	}
	return netip.AddrPort{}, errBadProxyHeader
}

func refusalOf(err error) ConnectionRefusal {
	var timeout net.Error
	switch {
	case errors.As(err, &timeout) && timeout.Timeout():
		return SlowProxyHeader
	case errors.Is(err, errNoProxyHeader):
		return NoProxyHeader
	}
	return BadProxyHeader
}
