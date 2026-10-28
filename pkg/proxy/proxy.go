package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	reuseport "github.com/kavu/go_reuseport"
	"github.com/nothinux/octo-proxy/pkg/config"
	"github.com/nothinux/octo-proxy/pkg/dnswatch"
	"github.com/nothinux/octo-proxy/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

var (
	downstreamConnActive = metrics.AddGaugeVec("octo_downstream_conn_active", "current active connection in downstream")
	downstreamConnTotal  = metrics.AddCounterVec("octo_downstream_conn_total", "total downstream connection")
	downstreamConnErr    = metrics.AddCounterVec("octo_downstream_conn_error", "total downsream connection error. include tcp and tls")

	upstreamConnActive = metrics.AddGaugeVecMultiLabels("octo_upstream_conn_active", "current active connection in upstreamn")
	upstreamConnTotal  = metrics.AddCounterVecMultiLabels("octo_upstream_conn_total", "total upstream connection")
	upstreamConnErr    = metrics.AddCounterVecMultiLabels("octo_upstream_conn_error", "total upstream connection error. include tcp and tls")
)

// Proxy hold running proxy data
type Proxy struct {
	Name     string
	Listener net.Listener
	Quit     context.CancelFunc
	Wg       sync.WaitGroup
	// DNSWatch closes connections to dnsWatch targets whose address left the
	// DNS answer. It may be nil.
	DNSWatch *dnswatch.Group
	sync.Mutex
	// closed is set by Shutdown so that a Run that starts afterwards
	// doesn't serve.
	closed bool
}

// New initialize new proxy
func New(name string) *Proxy {
	return &Proxy{
		Name: name,
	}
}

// Run initialize tcp or tls listener
func (p *Proxy) Run(c config.ServerConfig) {
	p.Lock()
	if p.closed {
		p.Unlock()
		return
	}

	if p.Quit != nil {
		p.Quit()
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.Quit = cancel
	p.Unlock()

	l, err := reuseport.Listen("tcp", net.JoinHostPort(c.Listener.Host, c.Listener.Port))
	if err != nil {
		log.Fatal().Err(err).Msg("failed to listen")
	}

	ts := []string{}

	for _, target := range c.Targets {
		ts = append(ts, fmt.Sprintf("%s:%s", target.Host, target.Port))
	}

	log.Info().
		Str("name", c.Name).
		Str("host", c.Listener.Host).
		Str("port", c.Listener.Port).
		Str("mdnsServiceTarget", c.MDNSTarget.ServiceName).
		Strs("targets", ts).
		Msg("running server")

	tc := c.Listener.TLSConfig
	if tc.IsSimple() || tc.IsMutual() {
		tlsConf, err := getTLSConfig(tc)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to get TLS config")
		}

		l = tls.NewListener(l, tlsConf.Config)

		log.Info().
			Str("name", c.Name).
			Str("mode", c.Listener.TLSConfig.Mode).
			Msg("running in TLS mode")
	}

	// Shutdown may have run while the listener was being set up, and then
	// had no listener to close.
	p.Lock()
	if p.closed {
		p.Unlock()
		l.Close()
		return
	}
	p.Listener = l
	p.Unlock()

	p.handleConn(ctx, c)
}

// handleConn accept incoming connection and forward it
func (p *Proxy) handleConn(ctx context.Context, c config.ServerConfig) {
	for {
		srcConn, err := p.Listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Error().
					Err(err).
					Str("name", c.Name).
					Msg("connection error")
				downstreamConnErr.With(prometheus.Labels{"name": p.Name}).Inc()
			}
		}

		downstreamConnActive.With(prometheus.Labels{"name": p.Name}).Inc()
		downstreamConnTotal.With(prometheus.Labels{"name": p.Name}).Inc()

		if !timeoutIsZero(c.Listener) {
			srcConn.SetDeadline(time.Now().Add(c.Listener.TimeoutDuration))
		}

		if err := isTLSConn(srcConn); err != nil {
			log.Error().Err(err).Msg("connection error")
			srcConn.Close()
			downstreamConnErr.With(prometheus.Labels{"name": p.Name}).Inc()
			continue
		}

		p.Wg.Add(1)
		go func() {
			p.forwardConn(ctx, c, srcConn)
			p.Wg.Done()
			downstreamConnActive.With(prometheus.Labels{"name": p.Name}).Dec()
		}()
	}
}

// forwardConn forward source connection to rarget or destination
func (p *Proxy) forwardConn(ctx context.Context, c config.ServerConfig, srcConn net.Conn) {
	targetConn, targetWr, tConf, err := getTargets(c)
	if err != nil {
		log.Error().
			Err(err).
			Str("name", c.Name).
			Msg("failed to get targets")
		srcConn.Close()
		return
	}

	// Close long-lived connections to targets that have no timeout configured forcefully on shutdown.
	if timeoutIsZero(tConf) {
		// Also return when the connection ends, or every connection leaks a
		// goroutine until shutdown.
		done := make(chan struct{})
		defer close(done)

		p.Wg.Add(1)
		go func() {
			select {
			case <-ctx.Done():
				closeConn(targetConn)
			case <-done:
			}

			p.Wg.Done()
		}()
	}

	// Move the connection when its address leaves the DNS answer: closing both
	// sides makes the client reconnect, and the new dial follows the answer.
	if tConf.DNSWatch {
		unregister := p.DNSWatch.Register(tConf.Host, remoteIP(targetConn[0]), func() {
			srcConn.Close()
			closeConn(targetConn)
		})
		defer unregister()
	}

	defer srcConn.Close()
	defer closeConn(targetConn)
	defer upstreamConnActive.With(prometheus.Labels{"host": tConf.Host, "port": tConf.Port}).Dec()

	p.Wg.Add(1)
	go func() {
		defer srcConn.Close()
		defer closeConn(targetConn)

		_, err := io.Copy(srcConn, targetConn[0])
		errCopy(err, tConf)

		p.Wg.Done()
	}()

	upstreamConnActive.With(prometheus.Labels{"host": tConf.Host, "port": tConf.Port}).Inc()
	upstreamConnTotal.With(prometheus.Labels{"host": tConf.Host, "port": tConf.Port}).Inc()

	_, err = io.Copy(targetWr, srcConn)
	errCopy(err, tConf)
}

func (p *Proxy) Shutdown() {
	p.Lock()
	p.closed = true
	if p.Quit != nil {
		p.Quit()
		p.Quit = nil
	}
	if p.Listener != nil {
		p.Listener.Close()
	}
	p.Unlock()

	// Wait without the lock: a Run that hasn't started yet needs it to see
	// that the proxy is closed.
	p.Wg.Wait()
}
