package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/nothinux/octo-proxy/pkg/config"
)

func TestShutdownBeforeRunDoesNotDeadlock(t *testing.T) {
	listener := "127.0.0.1:" + freePort(t)

	cfg, err := config.GenerateConfig(listener, []string{"127.0.0.1:1"}, "")
	if err != nil {
		t.Fatal(err)
	}

	// The runner adds to Wg before starting Run in a goroutine, so Shutdown
	// can run before Run has started.
	p := New("shutdown-test")
	p.Wg.Add(1)

	done := make(chan struct{})
	go func() {
		p.Shutdown()
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)

	go func() {
		p.Run(cfg.ServerConfigs[0])
		p.Wg.Done()
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown did not return")
	}

	if c, err := net.DialTimeout("tcp", listener, 200*time.Millisecond); err == nil {
		c.Close()
		t.Error("proxy is listening after Shutdown")
	}
}
