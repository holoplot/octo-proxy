//go:build !linux

package mdns

import (
	"fmt"
	"net"
	"time"
)

func TrackService(name string, v4, v6 bool) error {
	return nil
}

func UntrackServices() {
}

func ResolveService(name string, v4, v6 bool, timeout time.Duration) ([]net.TCPAddr, error) {
	return []net.TCPAddr{}, fmt.Errorf("not implemented")
}
