package dnswatch

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

const host = "controller.test"

// fakeResolver serves a settable answer for host.
type fakeResolver struct {
	mu      sync.Mutex
	ips     []net.IP
	err     error
	lookups atomic.Int32
}

func (r *fakeResolver) set(ips ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.err = nil
	r.ips = nil
	for _, ip := range ips {
		r.ips = append(r.ips, net.ParseIP(ip))
	}
}

func (r *fakeResolver) fail(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.err = err
}

func (r *fakeResolver) lookup(ctx context.Context, h string) ([]net.IP, error) {
	r.lookups.Add(1)

	r.mu.Lock()
	defer r.mu.Unlock()

	if h != host {
		return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
	}

	return r.ips, r.err
}

// testConn counts how often its close function runs.
type testConn struct {
	closes     atomic.Int32
	unregister func()
}

func (c *testConn) closed() bool {
	return c.closes.Load() > 0
}

func register(g *Group, ip string) *testConn {
	c := &testConn{}
	c.unregister = g.Register(host, net.ParseIP(ip), func() { c.closes.Add(1) })
	return c
}

func newTestGroup(r *fakeResolver) *Group {
	return newGroup(time.Hour, []string{host}, r.lookup)
}

func TestAddressLeavingAnswerClosesOnlyItsConnections(t *testing.T) {
	r := &fakeResolver{}
	r.set("10.0.0.1", "10.0.0.2")
	g := newTestGroup(r)

	a := register(g, "10.0.0.1")
	b := register(g, "10.0.0.2")

	g.pollAll(context.Background())

	if a.closed() || b.closed() {
		t.Fatal("closed a connection whose address is still in the answer")
	}

	r.set("10.0.0.2", "10.0.0.3")
	g.pollAll(context.Background())

	if !a.closed() {
		t.Error("connection to 10.0.0.1 not closed after it left the answer")
	}

	if b.closed() {
		t.Error("connection to 10.0.0.2 closed, but it is still in the answer")
	}
}

func TestOrderDoesNotMatter(t *testing.T) {
	r := &fakeResolver{}
	r.set("10.0.0.1", "10.0.0.2")
	g := newTestGroup(r)

	a := register(g, "10.0.0.1")

	r.set("10.0.0.2", "10.0.0.1")
	g.pollAll(context.Background())

	if a.closed() {
		t.Error("closed a connection because the answer was reordered")
	}
}

func TestFailedLookupsCloseNothing(t *testing.T) {
	tests := []struct {
		name  string
		apply func(r *fakeResolver)
	}{
		{"error", func(r *fakeResolver) { r.fail(errors.New("timeout")) }},
		{"nxdomain", func(r *fakeResolver) {
			r.fail(&net.DNSError{Err: "no such host", Name: host, IsNotFound: true})
		}},
		{"empty answer", func(r *fakeResolver) { r.set() }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeResolver{}
			r.set("10.0.0.1")
			g := newTestGroup(r)

			a := register(g, "10.0.0.1")

			tt.apply(r)
			g.pollAll(context.Background())

			if a.closed() {
				t.Error("closed a connection after a failed lookup")
			}
		})
	}
}

func TestLateRegistrationIsCaughtOnNextPoll(t *testing.T) {
	r := &fakeResolver{}
	r.set("10.0.0.2")
	g := newTestGroup(r)

	g.pollAll(context.Background())

	// A dial that raced the change and still reached the old address.
	a := register(g, "10.0.0.1")

	g.pollAll(context.Background())

	if !a.closed() {
		t.Error("connection registered after the change was not closed on the next poll")
	}
}

func TestClosesEachConnectionOnce(t *testing.T) {
	r := &fakeResolver{}
	r.set("10.0.0.2")
	g := newTestGroup(r)

	a := register(g, "10.0.0.1")

	g.pollAll(context.Background())
	g.pollAll(context.Background())

	if n := a.closes.Load(); n != 1 {
		t.Errorf("closed %d times, want once", n)
	}
}

func TestUnregisteredConnectionIsNotClosed(t *testing.T) {
	r := &fakeResolver{}
	r.set("10.0.0.2")
	g := newTestGroup(r)

	a := register(g, "10.0.0.1")
	a.unregister()

	g.pollAll(context.Background())

	if a.closed() {
		t.Error("closed a connection after it was unregistered")
	}
}

func TestUnwatchedHostIsIgnored(t *testing.T) {
	r := &fakeResolver{}
	r.set("10.0.0.2")
	g := newTestGroup(r)

	c := &testConn{}
	unregister := g.Register("other.test", net.ParseIP("10.0.0.1"), func() { c.closes.Add(1) })
	defer unregister()

	g.pollAll(context.Background())

	if c.closed() {
		t.Error("closed a connection to a host that is not watched")
	}
}

func TestIPv6ConnectionsAreNotWatched(t *testing.T) {
	r := &fakeResolver{}
	r.set("10.0.0.1")
	g := newTestGroup(r)

	a := register(g, "fd00::1")

	g.pollAll(context.Background())

	if a.closed() {
		t.Error("closed an IPv6 connection, but the watcher only queries IPv4")
	}
}

func TestIPv4MappedAddressMatches(t *testing.T) {
	r := &fakeResolver{}
	r.set("10.0.0.1")
	g := newTestGroup(r)

	c := &testConn{}
	g.Register(host, net.ParseIP("10.0.0.1").To16(), func() { c.closes.Add(1) })

	g.pollAll(context.Background())

	if c.closed() {
		t.Error("closed a connection whose address is in the answer")
	}
}

func TestNilGroupIsSafe(t *testing.T) {
	var g *Group

	unregister := g.Register(host, net.ParseIP("10.0.0.1"), func() {})
	unregister()
	g.Stop()
}

func TestStartPollsAndStopEndsPolling(t *testing.T) {
	r := &fakeResolver{}
	r.set("10.0.0.2")
	g := newGroup(10*time.Millisecond, []string{host}, r.lookup)

	a := register(g, "10.0.0.1")

	g.Start()

	deadline := time.Now().Add(time.Second)
	for !a.closed() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if !a.closed() {
		t.Fatal("watcher did not close the connection after Start")
	}

	g.Stop()

	n := r.lookups.Load()
	time.Sleep(50 * time.Millisecond)

	if got := r.lookups.Load(); got != n {
		t.Errorf("lookups continued after Stop: %d, then %d", n, got)
	}
}

func (g *Group) pollAll(ctx context.Context) {
	for _, w := range g.watchers {
		w.poll(ctx)
	}
}

func TestCloseDoesNotWaitForCNAMELookup(t *testing.T) {
	r := &fakeResolver{}
	r.set("10.0.0.1")
	g := newTestGroup(r)

	g.pollAll(context.Background())

	var mu sync.Mutex
	var events []string
	record := func(e string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}

	for _, w := range g.watchers {
		w.lookupCNAME = func(ctx context.Context, h string) (string, error) {
			record("cname")
			return h + ".", nil
		}
	}

	g.Register(host, net.ParseIP("10.0.0.1"), func() { record("close") })

	r.set("10.0.0.2")
	g.pollAll(context.Background())

	mu.Lock()
	defer mu.Unlock()

	if len(events) == 0 || events[0] != "close" {
		t.Errorf("got %v, want the connection closed before the CNAME lookup", events)
	}
}

func TestStopDuringLookupIsNotAnError(t *testing.T) {
	const stopHost = "stop.test"

	started := make(chan struct{}, 1)
	lookup := func(ctx context.Context, h string) ([]net.IP, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	g := newGroup(time.Hour, []string{stopHost}, lookup)
	g.Start()
	<-started
	g.Stop()

	if n := testutil.ToFloat64(resolveErrors.With(prometheus.Labels{"name": stopHost})); n != 0 {
		t.Errorf("counted %v resolve errors for a lookup cancelled by Stop, want 0", n)
	}
}

func TestLookupSlowerThanIntervalStillWorks(t *testing.T) {
	r := &fakeResolver{}
	r.set("10.0.0.2")

	slow := func(ctx context.Context, h string) ([]net.IP, error) {
		select {
		case <-time.After(30 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return r.lookup(ctx, h)
	}

	g := newGroup(10*time.Millisecond, []string{host}, slow)
	a := register(g, "10.0.0.1")

	g.Start()
	defer g.Stop()

	deadline := time.Now().Add(time.Second)
	for !a.closed() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if !a.closed() {
		t.Error("a lookup slower than the interval never completed, so nothing moved")
	}
}
