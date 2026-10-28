// Package dnswatch moves connections off addresses that have left a
// hostname's DNS answer.
//
// One watcher polls each hostname's A and AAAA records through the local
// resolver. Proxies register every connection they dial to a watched hostname.
// When the answer for a connection's address family no longer contains its
// address, the connection is closed so that the client reconnects to an
// address that is in the answer.
package dnswatch

import (
	"context"
	"errors"
	"maps"
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

// LookupFunc returns the addresses of host for network "ip4" or "ip6", like
// net.Resolver.LookupIP.
type LookupFunc func(ctx context.Context, network, host string) ([]net.IP, error)

// lookupTimeout bounds one lookup. It doesn't depend on the interval, so that
// a short interval on a slow resolver still gets answers.
const lookupTimeout = 5 * time.Second

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

	mu     sync.Mutex
	conns  map[uint64]*conn
	nextID uint64
	// answer holds the last known answer per family.
	answer map[string][]string
	// failing marks the families whose last lookup failed.
	failing map[string]bool
}

type conn struct {
	ip     string
	family string
	close  func()
	closed bool
}

// New returns a Group that watches hosts every interval once started. A nil
// lookup uses the local resolver.
func New(interval time.Duration, hosts []string, lookup LookupFunc) *Group {
	if lookup != nil {
		return newGroup(interval, hosts, lookup)
	}

	g := newGroup(interval, hosts, net.DefaultResolver.LookupIP)

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
			host:    h,
			lookup:  lookup,
			conns:   make(map[uint64]*conn),
			failing: make(map[string]bool),
		}
	}

	return g
}

// Register tells the watcher for host about a connection to ip. closeFn is
// called at most once, when ip leaves the answer. The returned function must
// be called when the connection ends.
//
// Connections to hosts that are not watched are not tracked.
func (g *Group) Register(host string, ip net.IP, closeFn func()) (unregister func()) {
	if g == nil || ip == nil {
		return func() {}
	}

	w, ok := g.watchers[host]
	if !ok {
		return func() {}
	}

	w.mu.Lock()
	id := w.nextID
	w.nextID++
	w.conns[id] = &conn{ip: ip.String(), family: family(ip), close: closeFn}
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

// families are the address families the watcher looks up, each on its own:
// Go's combined lookup returns one family without an error when the other
// fails, which would look as if all addresses of the failed family had left.
var families = []string{"ip4", "ip6"}

func family(ip net.IP) string {
	if ip.To4() != nil {
		return "ip4"
	}

	return "ip6"
}

type familyResult struct {
	addrs []string
	err   error
}

func (r familyResult) notFound() bool {
	var dnsErr *net.DNSError
	return errors.As(r.err, &dnsErr) && dnsErr.IsNotFound
}

// poll looks up the host once per family and closes every connection whose
// address is not in its family's answer. A family's answer counts only when
// its lookup succeeded, or when it has no records while the other family has
// addresses. It re-checks all connections on every poll, so a dial that raced
// a change is caught on the next one.
func (w *watcher) poll(ctx context.Context) {
	results := make(map[string]familyResult, len(families))
	anyAddrs := false

	for _, f := range families {
		lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
		ips, err := w.lookup(lctx, f, w.host)
		cancel()

		// Stopped during the lookup: that isn't a failed lookup.
		if ctx.Err() != nil {
			return
		}

		r := familyResult{err: err}
		for _, ip := range ips {
			r.addrs = append(r.addrs, ip.String())
		}
		slices.Sort(r.addrs)
		r.addrs = slices.Compact(r.addrs)

		if err == nil && len(r.addrs) == 0 {
			r.err = &net.DNSError{Err: "no addresses", Name: w.host, IsNotFound: true}
		}

		results[f] = r
		anyAddrs = anyAddrs || len(r.addrs) > 0
	}

	// answers holds the families whose answer is known in this poll.
	answers := make(map[string][]string, len(families))
	failed := make(map[string]error, len(families))

	for f, r := range results {
		switch {
		case r.err == nil:
			answers[f] = r.addrs
		case anyAddrs && r.notFound():
			// The name exists but has no records of this family.
			answers[f] = []string{}
		default:
			failed[f] = r.err
		}
	}

	var toClose []*conn

	w.mu.Lock()

	changed := false
	first := w.answer == nil
	if first {
		w.answer = make(map[string][]string, len(families))
	}

	for f, a := range answers {
		if old, ok := w.answer[f]; !ok || !slices.Equal(old, a) {
			changed = true
		}
		w.answer[f] = a
	}

	var newlyFailed, recovered []string
	for _, f := range families {
		_, isFailing := failed[f]
		if isFailing && !w.failing[f] {
			newlyFailed = append(newlyFailed, f)
		}
		if !isFailing && w.failing[f] {
			recovered = append(recovered, f)
		}
		w.failing[f] = isFailing
	}

	for _, c := range w.conns {
		a, known := answers[c.family]
		if known && !c.closed && !slices.Contains(a, c.ip) {
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

	for _, f := range families {
		if err, ok := failed[f]; ok {
			resolveErrors.With(prometheus.Labels{"name": w.host}).Inc()

			// Log only the transition: a name that never resolves fails every poll.
			if slices.Contains(newlyFailed, f) {
				log.Warn().
					Err(err).
					Str("host", w.host).
					Str("family", f).
					Msg("DNS watch lookup failed, keeping this family's connections")
			}
		}
	}

	// Logged after closing, so the CNAME lookup doesn't delay the move.
	if (changed || len(recovered) > 0) && len(answers) > 0 {
		if changed && !first {
			answerChanges.With(prometheus.Labels{"name": w.host}).Inc()
		}

		log.Info().
			Str("host", w.host).
			Strs("ipv4", answers["ip4"]).
			Strs("ipv6", answers["ip6"]).
			Strs("failed", slices.Sorted(maps.Keys(failed))).
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
