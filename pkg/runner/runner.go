package runner

import (
	"context"
	"os"
	"os/signal"
	"reflect"
	"slices"
	"sync"
	"syscall"

	"github.com/nothinux/octo-proxy/pkg/config"
	"github.com/nothinux/octo-proxy/pkg/dnswatch"
	"github.com/nothinux/octo-proxy/pkg/mdns"
	"github.com/nothinux/octo-proxy/pkg/metrics"
	"github.com/nothinux/octo-proxy/pkg/proxy"
	"github.com/okzk/sdnotify"
	"github.com/rs/zerolog/log"
)

// Octo hold list proxy server information
type Octo struct {
	sync.Mutex
	Proxies  map[string]*proxy.Proxy
	DNSWatch *dnswatch.Group
}

type Server config.Config

func Run(c *config.Config, cPath string) error {
	ss := &Server{
		ServerConfigs: c.ServerConfigs,
		MetricsConfig: c.MetricsConfig,
		DNSWatch:      c.DNSWatch,
	}

	proxies, dnsWatch := ss.runProxy()

	octo := &Octo{
		Proxies:  proxies,
		DNSWatch: dnsWatch,
	}

	var metricsServer *metrics.Metrics

	if !reflect.DeepEqual(c.MetricsConfig, config.HostConfig{}) {
		var err error
		metricsServer, err = runMetrics(c.MetricsConfig)
		if err != nil {
			return err
		}
	}

	sigTerm := make(chan os.Signal, 1)
	sigReload := make(chan os.Signal, 1)

	signal.Notify(sigTerm, os.Interrupt, syscall.SIGTERM)
	signal.Notify(sigReload, syscall.SIGUSR1, syscall.SIGUSR2)

	sdnotify.Ready()

alive:
	for {
		select {
		case <-sigTerm:
			log.Warn().Msg("octo-proxy interrupted")

			octo.Lock()
			shutdown(octo.Proxies, octo.DNSWatch, metricsServer)
			octo.Unlock()

			break alive
		case <-sigReload:
			log.Info().Msg("octo-proxy reload triggered")

			if err := reloadProxy(cPath, octo); err != nil {
				log.Error().Err(err).Msg("octo-proxy reload failed")
				continue
			}

			log.Info().Msg("octo-proxy reloaded")
		}
	}

	return nil
}

func reloadProxy(cPath string, octo *Octo) error {
	c, err := config.New(cPath)
	if err != nil {
		return err
	}

	ss := &Server{
		ServerConfigs: c.ServerConfigs,
		MetricsConfig: c.MetricsConfig,
		DNSWatch:      c.DNSWatch,
	}

	mdns.UntrackServices()

	proxies, dnsWatch := ss.runProxy()

	octo.Lock()
	// shutdown old listener in
	shutdown(octo.Proxies, octo.DNSWatch, nil)

	// set new listener
	octo.Proxies = proxies
	octo.DNSWatch = dnsWatch

	// done
	octo.Unlock()

	return nil
}

// runProxy starts all proxies and, when any target has dnsWatch set, the DNS
// watch group they share.
func (s *Server) runProxy() (map[string]*proxy.Proxy, *dnswatch.Group) {
	proxies := make(map[string]*proxy.Proxy)

	var dnsWatch *dnswatch.Group
	if hosts := watchedHosts(s.ServerConfigs); len(hosts) > 0 {
		dnsWatch = dnswatch.New(s.DNSWatch.IntervalDuration, hosts, nil)
		dnsWatch.Start()
	}

	for _, serverConfig := range s.ServerConfigs {
		sc := serverConfig

		trackMDNSServices(sc)

		//
		proxy := proxy.New(sc.Name)
		proxy.DNSWatch = dnsWatch
		proxies[sc.Name] = proxy

		// run proxy
		proxy.Wg.Add(1)
		go func() {
			proxy.Run(sc)
			proxy.Wg.Done()
		}()
	}

	return proxies, dnsWatch
}

// watchedHosts returns each hostname that a target with dnsWatch set names.
func watchedHosts(scs []config.ServerConfig) []string {
	var hosts []string

	for _, sc := range scs {
		for _, t := range sc.Targets {
			if t.DNSWatch && !slices.Contains(hosts, t.Host) {
				hosts = append(hosts, t.Host)
			}
		}
	}

	return hosts
}

func runMetrics(c config.HostConfig) (*metrics.Metrics, error) {
	m := metrics.New(c)

	go func() {
		log.Info().
			Str("host", c.Host).
			Str("port", c.Port).
			Msg("starting metrics server")
		m.Run()
	}()

	return m, nil
}

func shutdown(proxies map[string]*proxy.Proxy, dnsWatch *dnswatch.Group, m *metrics.Metrics) {
	log.Info().Msg("shutdown octo-proxy")

	for _, p := range proxies {
		p.Shutdown()
	}

	dnsWatch.Stop()

	if m != nil {
		if err := m.Shutdown(context.Background()); err != nil {
			log.Error().Err(err).Msg("shutdown failed")
		}
	}
}

func trackMDNSServices(c config.ServerConfig) {
	if c.MDNSTarget.ServiceName != "" {
		if err := mdns.TrackService(c.MDNSTarget.ServiceName, c.MDNSTarget.Interface, c.MDNSTarget.IPv4, c.MDNSTarget.IPv6); err != nil {
			log.Error().
				Err(err).
				Str("service", c.MDNSTarget.ServiceName).
				Msg("failed to track mDNS service")
		}
	}
}
