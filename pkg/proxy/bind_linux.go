//go:build linux

package proxy

import (
	"syscall"
)

// bindToInterface returns a dialer control function that binds the socket to
// iface (SO_BINDTODEVICE), so the connection leaves through that interface
// whatever the routing table prefers.
func bindToInterface(iface string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var bindErr error

		if err := c.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}

		return bindErr
	}
}
