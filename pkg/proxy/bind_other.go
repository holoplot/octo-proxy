//go:build !linux

package proxy

import (
	"fmt"
	"syscall"
)

func bindToInterface(iface string) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, _ syscall.RawConn) error {
		return fmt.Errorf("binding to interface %s is only supported on Linux", iface)
	}
}
