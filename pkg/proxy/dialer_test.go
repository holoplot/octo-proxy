package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nothinux/octo-proxy/pkg/config"
)

func ipAddrs(ips ...string) []net.IPAddr {
	addrs := make([]net.IPAddr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, net.IPAddr{IP: net.ParseIP(ip)})
	}
	return addrs
}

func TestShuffleAddrsKeepsFamilyOrder(t *testing.T) {
	addrs := ipAddrs("10.0.0.1", "fd00::1", "10.0.0.2", "fd00::2", "10.0.0.3")

	for i := 0; i < 100; i++ {
		got := shuffleAddrs(addrs)

		if len(got) != len(addrs) {
			t.Fatalf("got %d addresses, want %d", len(got), len(addrs))
		}

		for j, a := range got {
			isV4 := a.IP.To4() != nil
			if j < 3 && !isV4 {
				t.Fatalf("got %v, want the three IPv4 addresses first", got)
			}
			if j >= 3 && isV4 {
				t.Fatalf("got %v, want the IPv6 addresses last", got)
			}
		}
	}
}

func TestShuffleAddrsSpreadsFirstAddress(t *testing.T) {
	addrs := ipAddrs("10.0.0.1", "10.0.0.2", "10.0.0.3")
	first := map[string]int{}

	const runs = 3000
	for i := 0; i < runs; i++ {
		first[shuffleAddrs(addrs)[0].IP.String()]++
	}

	for _, a := range addrs {
		n := first[a.IP.String()]
		if n < runs/3*8/10 || n > runs/3*12/10 {
			t.Errorf("%v came first %d times out of %d, want about %d", a.IP, n, runs, runs/3)
		}
	}
}

type fakeConn struct {
	net.Conn
	addr   string
	closed atomic.Bool
}

func (c *fakeConn) Close() error {
	c.closed.Store(true)
	return nil
}

// fakeDialer answers per address: "ok" connects at once, "refused" fails at
// once, "blackhole" blocks until the attempt is cancelled.
type fakeDialer struct {
	mu       sync.Mutex
	behavior map[string]string
	delay    map[string]time.Duration
	attempts []string
	conns    []*fakeConn
}

func (f *fakeDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.attempts = append(f.attempts, addr)
	behavior := f.behavior[addr]
	delay := f.delay[addr]
	f.mu.Unlock()

	switch behavior {
	case "refused":
		return nil, syscall.ECONNREFUSED
	case "blackhole":
		<-ctx.Done()
		return nil, ctx.Err()
	case "ignores-cancel":
		time.Sleep(delay)
	}

	c := &fakeConn{addr: addr}
	f.mu.Lock()
	f.conns = append(f.conns, c)
	f.mu.Unlock()

	return c, nil
}

func TestDialStaggeredHealthyDialsOnce(t *testing.T) {
	f := &fakeDialer{behavior: map[string]string{"a:1": "ok", "b:1": "ok"}}

	c, err := dialStaggered(context.Background(), []string{"a:1", "b:1"}, 250*time.Millisecond, f.dial)
	if err != nil {
		t.Fatal(err)
	}

	if got := c.(*fakeConn).addr; got != "a:1" {
		t.Errorf("connected to %s, want a:1", got)
	}

	time.Sleep(300 * time.Millisecond)

	if len(f.attempts) != 1 {
		t.Errorf("got attempts %v, want only a:1", f.attempts)
	}
}

func TestDialStaggeredBlackholeCostsOneStagger(t *testing.T) {
	f := &fakeDialer{behavior: map[string]string{"a:1": "blackhole", "b:1": "ok"}}
	stagger := 100 * time.Millisecond

	start := time.Now()
	c, err := dialStaggered(context.Background(), []string{"a:1", "b:1"}, stagger, f.dial)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}

	if got := c.(*fakeConn).addr; got != "b:1" {
		t.Errorf("connected to %s, want b:1", got)
	}

	if elapsed < stagger || elapsed > 3*stagger {
		t.Errorf("took %v, want about %v", elapsed, stagger)
	}
}

func TestDialStaggeredFailureStartsNextAtOnce(t *testing.T) {
	f := &fakeDialer{behavior: map[string]string{"a:1": "refused", "b:1": "ok"}}

	start := time.Now()
	c, err := dialStaggered(context.Background(), []string{"a:1", "b:1"}, time.Second, f.dial)
	if err != nil {
		t.Fatal(err)
	}

	if got := c.(*fakeConn).addr; got != "b:1" {
		t.Errorf("connected to %s, want b:1", got)
	}

	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("took %v, want the next attempt to start at once", elapsed)
	}
}

func TestDialStaggeredAllFail(t *testing.T) {
	f := &fakeDialer{behavior: map[string]string{"a:1": "refused", "b:1": "refused"}}

	_, err := dialStaggered(context.Background(), []string{"a:1", "b:1"}, 10*time.Millisecond, f.dial)
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("got %v, want connection refused", err)
	}
}

func TestDialStaggeredClosesLateWinners(t *testing.T) {
	f := &fakeDialer{
		behavior: map[string]string{"a:1": "ignores-cancel", "b:1": "ok"},
		delay:    map[string]time.Duration{"a:1": 100 * time.Millisecond},
	}

	c, err := dialStaggered(context.Background(), []string{"a:1", "b:1"}, 20*time.Millisecond, f.dial)
	if err != nil {
		t.Fatal(err)
	}

	if got := c.(*fakeConn).addr; got != "b:1" {
		t.Fatalf("connected to %s, want b:1", got)
	}

	time.Sleep(200 * time.Millisecond)

	f.mu.Lock()
	defer f.mu.Unlock()

	for _, fc := range f.conns {
		if fc.addr == "a:1" && !fc.closed.Load() {
			t.Error("late connection to a:1 was not closed")
		}
		if fc.addr == "b:1" && fc.closed.Load() {
			t.Error("winning connection to b:1 was closed")
		}
	}
}

func TestDialStaggeredCancelled(t *testing.T) {
	f := &fakeDialer{behavior: map[string]string{"a:1": "blackhole"}}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := dialStaggered(ctx, []string{"a:1"}, 10*time.Millisecond, f.dial); err == nil {
		t.Error("expected an error")
	}
}

// withLookup replaces the resolver used for hostname targets.
func withLookup(t *testing.T, fn func(ctx context.Context, host string) ([]net.IPAddr, error)) {
	t.Helper()

	orig := lookupIPAddr
	lookupIPAddr = fn
	t.Cleanup(func() { lookupIPAddr = orig })
}

func listenOn(t *testing.T, addr string) net.Listener {
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
			c.Close()
		}
	}()

	return l
}

func TestDialTargetHostnameSpreadsOverAddresses(t *testing.T) {
	l := listenOn(t, "127.0.0.1:0")
	_, port, _ := net.SplitHostPort(l.Addr().String())

	ips := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}
	for _, ip := range ips[1:] {
		listenOn(t, net.JoinHostPort(ip, port))
	}

	withLookup(t, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host != "controller.test" {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		// A resolver that never rotates: always the same order.
		return ipAddrs(ips...), nil
	})

	hc := config.HostConfig{
		Host: "controller.test",
		Port: port,
		ConnectionConfig: config.ConnectionConfig{
			ConnectTimeoutDuration: time.Second,
			DialStaggerDuration:    250 * time.Millisecond,
		},
	}

	counts := map[string]int{}
	const dials = 300
	for i := 0; i < dials; i++ {
		c, err := dialTarget(context.Background(), hc)
		if err != nil {
			t.Fatal(err)
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		counts[host]++
		c.Close()
	}

	for _, ip := range ips {
		if n := counts[ip]; n < dials/3/2 {
			t.Errorf("%s got %d of %d dials, want about %d", ip, n, dials, dials/3)
		}
	}
}

func TestDialTargetHostnameLookupError(t *testing.T) {
	withLookup(t, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})

	hc := config.HostConfig{
		Host: "controller.test",
		Port: "4222",
		ConnectionConfig: config.ConnectionConfig{
			ConnectTimeoutDuration: time.Second,
		},
	}

	if _, err := dialTarget(context.Background(), hc); err == nil {
		t.Error("expected an error")
	}
}

// writeTestCerts writes a CA and a server certificate for dnsName into dir.
func writeTestCerts(t *testing.T, dir, dnsName string) (caFile, certFile, keyFile string) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	write := func(name, typ string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	return write("ca.pem", "CERTIFICATE", caDER), write("cert.pem", "CERTIFICATE", der), write("key.pem", "EC PRIVATE KEY", keyDER)
}

func TestDialTargetHostnameTLS(t *testing.T) {
	caFile, certFile, keyFile := writeTestCerts(t, t.TempDir(), "controller.test")

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
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
			go func() {
				defer c.Close()
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()

	_, port, _ := net.SplitHostPort(l.Addr().String())

	withLookup(t, func(ctx context.Context, host string) ([]net.IPAddr, error) {
		return ipAddrs("127.0.0.1"), nil
	})

	hc := config.HostConfig{
		Host: "controller.test",
		Port: port,
		ConnectionConfig: config.ConnectionConfig{
			ConnectTimeoutDuration: time.Second,
		},
		TLSConfig: config.TLSConfig{
			Mode:   "simple",
			CaCert: caFile,
		},
	}

	c, err := dialTarget(context.Background(), hc)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	tc, ok := c.(*tls.Conn)
	if !ok {
		t.Fatalf("got %T, want *tls.Conn", c)
	}

	if got := tc.ConnectionState().ServerName; got != "controller.test" {
		t.Errorf("server name: got %q, want controller.test", got)
	}
}
