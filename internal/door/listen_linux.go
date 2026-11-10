package door

import (
	"net"
	"syscall"
)

func holdUntilData(ln net.Listener, seconds int) error {
	tl, ok := ln.(*net.TCPListener)
	if !ok {
		return nil
	}
	raw, err := tl.SyscallConn()
	if err != nil {
		return err
	}
	var set error
	if err := raw.Control(func(fd uintptr) {
		set = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_DEFER_ACCEPT, seconds)
	}); err != nil {
		return err
	}
	return set
}
