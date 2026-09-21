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

func newDial() *net.Dialer {
	return &net.Dialer{
		Timeout: 5 * time.Second,
	}
}

func dialTarget(ctx context.Context, hc config.HostConfig) (net.Conn, error) {
	d := newDial()

	if hc.IsSimple() || hc.IsMutual() {
		tlsConf, err := getTLSConfig(hc.TLSConfig)
		if err != nil {
			return nil, err
		}

		log.Debug().
			Str("host", hc.Host).
			Str("port", hc.Port).
			Msg("called tls target")

		return tls.DialWithDialer(d, "tcp", net.JoinHostPort(hc.Host, hc.Port), tlsConf.Config)
	}

	return d.DialContext(ctx, "tcp", net.JoinHostPort(hc.Host, hc.Port))
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
		addrs, err := mdns.ResolveService(c.MDNSTarget.ServiceName, c.MDNSTarget.IPv4, c.MDNSTarget.IPv6, time.Second)
		if err == nil {
			log.Debug().
				Interface("addrs", addrs).
				Msg("mDNS lookup finished")

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
