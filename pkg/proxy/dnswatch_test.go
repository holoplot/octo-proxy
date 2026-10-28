package proxy

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nothinux/octo-proxy/pkg/config"
	"github.com/nothinux/octo-proxy/pkg/dnswatch"
)

// switchableAnswer is the DNS answer for controller.test, shared by the
// dialer and the watcher.
type switchableAnswer struct {
	mu  sync.Mutex
	ips []string
}

func (a *switchableAnswer) set(ips ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ips = ips
}

func (a *switchableAnswer) get() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.ips...)
}

func (a *switchableAnswer) lookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return ipAddrs(a.get()...), nil
}

func (a *switchableAnswer) lookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	var ips []net.IP
	for _, s := range a.get() {
		ip := net.ParseIP(s)
		if (ip.To4() != nil) == (network == "ip4") {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return ips, nil
}

// echoBackend echoes on every accepted connection and keeps it open.
func echoBackend(t *testing.T, addr string) net.Listener {
	t.Helper()

	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("can't listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	return l
}

func freePort(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

// roundTrip sends a message through c and waits for the backend's echo.
func roundTrip(t *testing.T, c net.Conn) {
	t.Helper()

	c.SetDeadline(time.Now().Add(2 * time.Second))
	defer c.SetDeadline(time.Time{})

	if _, err := c.Write(messageByte); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, len(messageByte))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
}

func waitClosed(c net.Conn, timeout time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(timeout))
	defer c.SetReadDeadline(time.Time{})

	_, err := c.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return err != nil
}

type dnsWatchSetup struct {
	answer   *switchableAnswer
	proxy    *Proxy
	listener string
	group    *dnswatch.Group
}

// startDNSWatchProxy starts an echo backend on each of ips, all on one port,
// and a proxy to controller.test, which first resolves to ips[0].
func startDNSWatchProxy(t *testing.T, watch bool, ips ...string) *dnsWatchSetup {
	t.Helper()

	old := echoBackend(t, net.JoinHostPort(ips[0], "0"))
	_, port, _ := net.SplitHostPort(old.Addr().String())
	for _, ip := range ips[1:] {
		echoBackend(t, net.JoinHostPort(ip, port))
	}

	answer := &switchableAnswer{}
	answer.set(ips[0])
	withLookup(t, answer.lookupIPAddr)

	listenPort := freePort(t)
	cfg, err := config.GenerateConfig("127.0.0.1:"+listenPort, []string{"controller.test:" + port}, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerConfigs[0].Targets[0].DNSWatch = watch
	cfg.ServerConfigs[0].Targets[0].TimeoutDuration = 0

	g := dnswatch.New(20*time.Millisecond, []string{"controller.test"}, answer.lookupIP)
	g.Start()

	p := New("dnswatch-test")
	p.DNSWatch = g
	p.Wg.Add(1)
	go func() {
		p.Run(cfg.ServerConfigs[0])
		p.Wg.Done()
	}()

	t.Cleanup(func() {
		p.Shutdown()
		g.Stop()
	})

	time.Sleep(200 * time.Millisecond)

	return &dnsWatchSetup{
		answer:   answer,
		proxy:    p,
		listener: "127.0.0.1:" + listenPort,
		group:    g,
	}
}

func TestDNSWatchMovesConnectionToNewAnswer(t *testing.T) {
	s := startDNSWatchProxy(t, true, "127.0.0.1", "127.0.0.2")

	c, err := net.Dial("tcp", s.listener)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	roundTrip(t, c)

	if waitClosed(c, 100*time.Millisecond) {
		t.Fatal("connection closed while its address was still in the answer")
	}

	s.answer.set("127.0.0.2")

	if !waitClosed(c, time.Second) {
		t.Fatal("connection not closed after its address left the answer")
	}

	// The client reconnects and lands on the new address.
	c2, err := net.Dial("tcp", s.listener)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	roundTrip(t, c2)

	if waitClosed(c2, 200*time.Millisecond) {
		t.Error("reconnected connection was closed, want it on the new address")
	}
}

func TestDNSWatchIgnoresTargetsWithoutFlag(t *testing.T) {
	s := startDNSWatchProxy(t, false, "127.0.0.1", "127.0.0.2")

	c, err := net.Dial("tcp", s.listener)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	roundTrip(t, c)

	s.answer.set("127.0.0.2")

	if waitClosed(c, 300*time.Millisecond) {
		t.Error("closed a connection to a target without dnsWatch")
	}
}

func TestDNSWatchMovesIPv6ConnectionWhenAAAAGoes(t *testing.T) {
	s := startDNSWatchProxy(t, true, "::1", "127.0.0.1")

	c, err := net.Dial("tcp", s.listener)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	roundTrip(t, c)

	if waitClosed(c, 100*time.Millisecond) {
		t.Fatal("connection closed while its address was still in the answer")
	}

	// Switched to IPv4-only backends.
	s.answer.set("127.0.0.1")

	if !waitClosed(c, time.Second) {
		t.Fatal("IPv6 connection not closed after the name lost its AAAA records")
	}

	c2, err := net.Dial("tcp", s.listener)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	roundTrip(t, c2)

	if waitClosed(c2, 200*time.Millisecond) {
		t.Error("reconnected connection was closed, want it on the IPv4 address")
	}
}
