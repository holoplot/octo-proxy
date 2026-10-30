//go:build linux

package proxy

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/nothinux/octo-proxy/pkg/config"
)

func TestDialTargetBindsToInterface(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	host, port, _ := net.SplitHostPort(l.Addr().String())

	hc := config.HostConfig{Host: host, Port: port}
	hc.Interface = "lo"

	c, err := dialTarget(context.Background(), hc)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("binding to an interface needs CAP_NET_RAW")
	}
	if err != nil {
		t.Fatalf("dial bound to lo: %v", err)
	}
	c.Close()

	hc.Interface = "no-such-if0"

	if c, err := dialTarget(context.Background(), hc); err == nil {
		c.Close()
		t.Fatal("dial bound to a missing interface succeeded")
	}
}
