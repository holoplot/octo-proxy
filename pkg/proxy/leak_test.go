package proxy

import (
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/nothinux/octo-proxy/pkg/config"
)

func TestZeroTimeoutConnectionsDontLeakGoroutines(t *testing.T) {
	backend := echoBackend(t, "127.0.0.1:0")
	listener := "127.0.0.1:" + freePort(t)

	cfg, err := config.GenerateConfig(listener, []string{backend.Addr().String()}, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerConfigs[0].Targets[0].TimeoutDuration = 0

	p := New("leak-test")
	p.Wg.Add(1)
	go func() {
		p.Run(cfg.ServerConfigs[0])
		p.Wg.Done()
	}()
	defer p.Shutdown()

	time.Sleep(200 * time.Millisecond)

	before := runtime.NumGoroutine()

	const conns = 50
	for i := 0; i < conns; i++ {
		c, err := net.Dial("tcp", listener)
		if err != nil {
			t.Fatal(err)
		}
		roundTrip(t, c)
		c.Close()
	}

	// Give the proxy time to notice the closed connections.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+5 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	if after := runtime.NumGoroutine(); after > before+5 {
		t.Errorf("goroutines grew from %d to %d after %d closed connections", before, after, conns)
	}
}
