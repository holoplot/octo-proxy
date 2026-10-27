// Package dnswatch moves connections off addresses that have left a
// hostname's DNS answer.
//
// One watcher polls each hostname through the local resolver. Proxies register
// every connection they dial to a watched hostname. When a successful,
// non-empty answer no longer contains a connection's address, the connection
// is closed so that the client reconnects to an address that is in the answer.
package dnswatch

import (
	"context"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/nothinux/octo-proxy/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

var (
	answerChanges = metrics.AddCounterVec("octo_dnswatch_answer_change", "total changes in the watched hostname's DNS answer")
	connsMoved    = metrics.AddCounterVec("octo_dnswatch_conn_moved", "total connections closed because their address left the DNS answer")
	resolveErrors = metrics.AddCounterVec("octo_dnswatch_resolve_error", "total failed or empty lookups of the watched hostname")
)

// LookupFunc returns the IPv4 addresses of host.
type LookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// lookupTimeout bounds one lookup. It doesn't depend on the interval, so that
// a short interval on a slow resolver still gets answers.
const lookupTimeout = 5 * time.Second

// lookupIPv4 asks the local resolver for the hostname's IPv4 addresses.
func lookupIPv4(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip4", host)
}

// Group holds one watcher per watched hostname. A nil Group watches nothing.
type Group struct {
	interval time.Duration
	watchers map[string]*watcher
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

type watcher struct {
	host   string
	lookup LookupFunc
	// lookupCNAME is only used for logging; nil skips it.
	lookupCNAME func(ctx context.Context, host string) (string, error)

	mu      sync.Mutex
	conns   map[uint64]*conn
	nextID  uint64
	answer  []string
	failing bool
}

type conn struct {
	ip     string
	close  func()
	closed bool
}

// New returns a Group that watches hosts every interval once started. A nil
// lookup uses the local resolver.
func New(interval time.Duration, hosts []string, lookup LookupFunc) *Group {
	if lookup != nil {
		return newGroup(interval, hosts, lookup)
	}

	g := newGroup(interval, hosts, lookupIPv4)

	for _, w := range g.watchers {
		w.lookupCNAME = net.DefaultResolver.LookupCNAME
	}

	return g
}

func newGroup(interval time.Duration, hosts []string, lookup LookupFunc) *Group {
	g := &Group{
		interval: interval,
		watchers: make(map[string]*watcher),
	}

	for _, h := range hosts {
		g.watchers[h] = &watcher{
			host:   h,
			lookup: lookup,
			conns:  make(map[uint64]*conn),
		}
	}

	return g
}

// Register tells the watcher for host about a connection to ip. closeFn is
// called at most once, when ip leaves the answer. The returned function must
// be called when the connection ends.
//
// Connections to hosts that are not watched, and IPv6 connections, are not
// tracked: the watcher only queries IPv4 addresses.
func (g *Group) Register(host string, ip net.IP, closeFn func()) (unregister func()) {
	if g == nil {
		return func() {}
	}

	w, ok := g.watchers[host]
	if !ok || ip.To4() == nil {
		return func() {}
	}

	w.mu.Lock()
	id := w.nextID
	w.nextID++
	w.conns[id] = &conn{ip: ip.String(), close: closeFn}
	w.mu.Unlock()

	return func() {
		w.mu.Lock()
		delete(w.conns, id)
		w.mu.Unlock()
	}
}

// Start polls every watched host once right away and then every interval.
func (g *Group) Start() {
	if g == nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	g.cancel = cancel

	for _, w := range g.watchers {
		log.Info().
			Str("host", w.host).
			Dur("interval", g.interval).
			Msg("watching DNS answer")

		g.wg.Go(func() {
			t := time.NewTicker(g.interval)
			defer t.Stop()

			for {
				w.poll(ctx)

				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		})
	}
}

// Stop ends polling and waits for the watchers to return.
func (g *Group) Stop() {
	if g == nil || g.cancel == nil {
		return
	}

	g.cancel()
	g.wg.Wait()
}

// poll looks up the host once and closes every connection whose address is
// not in a successful, non-empty answer. It re-checks all connections on every
// poll, so a dial that raced a change is caught on the next one.
func (w *watcher) poll(ctx context.Context) {
	lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	ips, err := w.lookup(lctx, w.host)
	cancel()

	// Stopped during the lookup: that isn't a failed lookup.
	if ctx.Err() != nil {
		return
	}

	if err != nil || len(ips) == 0 {
		resolveErrors.With(prometheus.Labels{"name": w.host}).Inc()

		w.mu.Lock()
		wasFailing := w.failing
		w.failing = true
		w.mu.Unlock()

		// Log only the transition: a name that never resolves fails every poll.
		if !wasFailing {
			log.Warn().
				Err(err).
				Str("host", w.host).
				Msg("DNS watch lookup failed or returned no addresses, keeping connections")
		}

		return
	}

	answer := make([]string, 0, len(ips))
	for _, ip := range ips {
		answer = append(answer, ip.String())
	}
	slices.Sort(answer)
	answer = slices.Compact(answer)

	var toClose []*conn

	w.mu.Lock()

	changed := !slices.Equal(answer, w.answer)
	first := w.answer == nil
	recovered := w.failing
	w.answer = answer
	w.failing = false

	for _, c := range w.conns {
		if !c.closed && !slices.Contains(answer, c.ip) {
			c.closed = true
			toClose = append(toClose, c)
		}
	}

	w.mu.Unlock()

	for _, c := range toClose {
		connsMoved.With(prometheus.Labels{"name": w.host}).Inc()

		log.Info().
			Str("host", w.host).
			Str("address", c.ip).
			Msg("closing connection, its address left the DNS answer")

		c.close()
	}

	// Logged after closing, so the CNAME lookup doesn't delay the move.
	if changed || recovered {
		if changed && !first {
			answerChanges.With(prometheus.Labels{"name": w.host}).Inc()
		}

		log.Info().
			Str("host", w.host).
			Strs("addresses", answer).
			Str("cname", w.cname(ctx)).
			Bool("changed", changed && !first).
			Msg("DNS watch answer")
	}
}

// cname returns the canonical name for diagnosis only; failures are ignored.
func (w *watcher) cname(ctx context.Context) string {
	if w.lookupCNAME == nil {
		return ""
	}

	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()

	name, _ := w.lookupCNAME(ctx, w.host)

	return name
}
