package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"math/rand"
	"net"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nothinux/octo-proxy/pkg/config"
	"github.com/nothinux/octo-proxy/pkg/errors"
	"github.com/nothinux/octo-proxy/pkg/mdns"
	"github.com/nothinux/octo-proxy/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/rs/zerolog/log"
)

var (
	upstreamDialErr = metrics.AddCounterVecMultiLabels("octo_upstream_dial_error", "total dial error when calling an upstream")
	mirrorDialErr   = metrics.AddCounterVecMultiLabels("octo_mirror_dial_error", "total dial error when calling an mirror upstream")
)

func newDial(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
	}
}

// lookupIPAddr resolves hostname targets. Tests replace it.
var lookupIPAddr = net.DefaultResolver.LookupIPAddr

func dialTarget(ctx context.Context, hc config.HostConfig) (net.Conn, error) {
	d := newDial(hc.ConnectTimeoutDuration)

	if hc.IsSimple() || hc.IsMutual() {
		tlsConf, err := getTLSConfig(hc.TLSConfig)
		if err != nil {
			return nil, err
		}

		log.Debug().
			Str("host", hc.Host).
			Str("port", hc.Port).
			Msg("called tls target")

		if !isHostname(hc.Host) {
			return tls.DialWithDialer(d, "tcp", net.JoinHostPort(hc.Host, hc.Port), tlsConf.Config)
		}

		c, err := dialHostname(ctx, d, hc)
		if err != nil {
			return nil, err
		}

		tlsConf.ServerName = hc.Host
		tc := tls.Client(c, tlsConf.Config)

		hctx, cancel := withOptionalTimeout(ctx, hc.ConnectTimeoutDuration)
		defer cancel()

		if err := tc.HandshakeContext(hctx); err != nil {
			c.Close()
			return nil, err
		}

		return tc, nil
	}

	if isHostname(hc.Host) {
		return dialHostname(ctx, d, hc)
	}

	return d.DialContext(ctx, "tcp", net.JoinHostPort(hc.Host, hc.Port))
}

func isHostname(host string) bool {
	return net.ParseIP(host) == nil
}

func withOptionalTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}

	return context.WithCancel(ctx)
}

// dialHostname resolves the target's hostname and dials its addresses in
// random order, so that connections spread over all of them whatever order
// the resolver returns.
func dialHostname(ctx context.Context, d *net.Dialer, hc config.HostConfig) (net.Conn, error) {
	lctx, cancel := withOptionalTimeout(ctx, hc.ConnectTimeoutDuration)
	addrs, err := lookupIPAddr(lctx, hc.Host)
	cancel()

	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: hc.Host, IsNotFound: true}
	}

	targets := make([]string, 0, len(addrs))
	for _, a := range shuffleAddrs(addrs) {
		targets = append(targets, net.JoinHostPort(a.String(), hc.Port))
	}

	return dialStaggered(ctx, targets, hc.DialStaggerDuration, d.DialContext)
}

// shuffleAddrs returns addrs in random order within each address family. The
// family of the first address, which the resolver prefers, stays first.
func shuffleAddrs(addrs []net.IPAddr) []net.IPAddr {
	var primaries, fallbacks []net.IPAddr

	for _, a := range addrs {
		if len(primaries) == 0 || (a.IP.To4() != nil) == (primaries[0].IP.To4() != nil) {
			primaries = append(primaries, a)
		} else {
			fallbacks = append(fallbacks, a)
		}
	}

	rand.Shuffle(len(primaries), func(i, j int) {
		primaries[i], primaries[j] = primaries[j], primaries[i]
	})

	rand.Shuffle(len(fallbacks), func(i, j int) {
		fallbacks[i], fallbacks[j] = fallbacks[j], fallbacks[i]
	})

	return append(primaries, fallbacks...)
}

// dialStaggered dials addrs in order. The next attempt starts when the
// previous one fails or after stagger, whichever comes first, and earlier
// attempts keep running (Happy Eyeballs, RFC 8305). The first connection wins
// and all other attempts are cancelled or closed.
func dialStaggered(ctx context.Context, addrs []string, stagger time.Duration,
	dial func(ctx context.Context, network, addr string) (net.Conn, error)) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		conn net.Conn
		err  error
	}

	results := make(chan result, len(addrs))
	next, pending := 0, 0

	start := func() {
		addr := addrs[next]
		next++
		pending++

		go func() {
			c, err := dial(ctx, "tcp", addr)
			results <- result{conn: c, err: err}
		}()
	}

	timer := time.NewTimer(stagger)
	defer timer.Stop()

	start()

	var firstErr error

	for pending > 0 {
		select {
		case r := <-results:
			pending--

			if r.err == nil {
				// Attempts that still connect after cancel() lost the race.
				go func(n int) {
					for ; n > 0; n-- {
						if late := <-results; late.conn != nil {
							late.conn.Close()
						}
					}
				}(pending)

				return r.conn, nil
			}

			if firstErr == nil {
				firstErr = r.err
			}

			if next < len(addrs) {
				start()
				timer.Reset(stagger)
			}

		case <-timer.C:
			if next < len(addrs) {
				start()
				timer.Reset(stagger)
			}
		}
	}

	return nil, firstErr
}

func dialTargets(ctx context.Context, hcs []config.HostConfig) (net.Conn, config.HostConfig, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg            sync.WaitGroup
		succeeded     atomic.Bool
		succeededConn net.Conn
		succeededConf config.HostConfig
	)

	for _, hc := range hcs {
		wg.Add(1)

		go func(hc config.HostConfig) {
			defer wg.Done()

			c, err := dialTarget(ctx, hc)
			if err == nil {
				// All other pending connection dials will return with an error
				cancel()

				if succeeded.Swap(true) {
					// Some other connection already succeeded, so we need to close ours
					_ = c.Close()
					return
				}

				if !timeoutIsZero(hc) {
					c.SetDeadline(time.Now().Add(hc.TimeoutDuration))
				}

				succeededConn = c
				succeededConf = hc
			}
		}(hc)
	}

	wg.Wait()

	if succeeded.Load() {
		return succeededConn, succeededConf, nil
	}

	return nil, config.HostConfig{}, errors.New("targets", "no backends could be reached")
}

func getTargets(c config.ServerConfig) ([]net.Conn, io.Writer, config.HostConfig, error) {
	targets := c.Targets

	if c.MDNSTarget.ServiceName != "" {
		addrs, err := mdns.ResolveService(c.MDNSTarget.ServiceName, c.MDNSTarget.IPv4, c.MDNSTarget.IPv6)
		if err == nil {
			for _, addr := range addrs {
				target := config.HostConfig{
					Host:             addr.IP.String(),
					Port:             strconv.Itoa(addr.Port),
					ConnectionConfig: c.MDNSTarget.ConnectionConfig,
					TLSConfig:        c.MDNSTarget.TLSConfig,
				}

				targets = append(targets, target)
			}
		} else {
			log.Warn().
				Err(err).
				Str("service", c.MDNSTarget.ServiceName).
				Msg("failed to lookup mdns service")
		}
	}

	rand.Shuffle(len(targets), func(i, j int) {
		targets[i], targets[j] = targets[j], targets[i]
	})

	t, tc, err := dialTargets(context.Background(), targets)
	if err != nil {
		upstreamDialErr.With(prometheus.Labels{"host": tc.Host, "port": tc.Port}).Inc()
		return nil, nil, config.HostConfig{}, errors.New(c.Name, err.Error())
	}

	var m net.Conn

	if !reflect.DeepEqual(config.HostConfig{}, c.Mirror) {
		m, err = dialTarget(context.Background(), c.Mirror)
		if err != nil {
			mirrorDialErr.With(prometheus.Labels{"host": c.Mirror.Host, "port": c.Mirror.Port}).Inc()
			log.Warn().
				Err(err).
				Str("host", c.Mirror.Host).
				Str("port", c.Mirror.Port).
				Msg("can't dial mirror backend")
		}
		if m != nil {
			if !timeoutIsZero(c.Mirror) {
				m.SetDeadline(time.Now().Add(c.Mirror.TimeoutDuration))
			}
		}
	}

	if m == nil {
		return []net.Conn{t}, io.MultiWriter(t), tc, nil
	}

	return []net.Conn{t, m}, io.MultiWriter(t, m), tc, nil
}
