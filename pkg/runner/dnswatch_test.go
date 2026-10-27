package runner

import (
	"slices"
	"testing"
	"time"

	"github.com/nothinux/octo-proxy/pkg/config"
)

func TestWatchedHosts(t *testing.T) {
	scs := []config.ServerConfig{
		{
			Name: "proxy-a",
			Targets: []config.HostConfig{
				{Host: "backend.example.com", Port: "4222", DNSWatch: true},
				{Host: "other.example.com", Port: "4222"},
			},
		},
		{
			Name: "proxy-b",
			Targets: []config.HostConfig{
				{Host: "backend.example.com", Port: "4317", DNSWatch: true},
			},
		},
	}

	got := watchedHosts(scs)
	want := []string{"backend.example.com"}

	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRunProxySharesOneDNSWatchGroup(t *testing.T) {
	ss := &Server{
		ServerConfigs: []config.ServerConfig{
			{
				Name:     "proxy-a",
				Listener: config.HostConfig{Host: "127.0.0.1", Port: "9801"},
				Targets:  []config.HostConfig{{Host: "controller.test", Port: "4222", DNSWatch: true}},
			},
			{
				Name:     "proxy-b",
				Listener: config.HostConfig{Host: "127.0.0.1", Port: "9802"},
				Targets:  []config.HostConfig{{Host: "controller.test", Port: "4317", DNSWatch: true}},
			},
		},
		DNSWatch: config.DNSWatchConfig{IntervalDuration: time.Hour},
	}

	proxies, g := ss.runProxy()
	defer shutdown(proxies, g, nil)

	// Proxy.Shutdown deadlocks if it runs before Proxy.Run has started.
	time.Sleep(200 * time.Millisecond)

	if g == nil {
		t.Fatal("no DNS watch group although targets have dnsWatch set")
	}

	for name, p := range proxies {
		if p.DNSWatch != g {
			t.Errorf("proxy %s does not use the shared DNS watch group", name)
		}
	}
}

func TestRunProxyWithoutDNSWatch(t *testing.T) {
	ss := &Server{
		ServerConfigs: []config.ServerConfig{
			{
				Name:     "proxy-a",
				Listener: config.HostConfig{Host: "127.0.0.1", Port: "9803"},
				Targets:  []config.HostConfig{{Host: "controller.test", Port: "4222"}},
			},
		},
	}

	proxies, g := ss.runProxy()
	defer shutdown(proxies, g, nil)

	// Proxy.Shutdown deadlocks if it runs before Proxy.Run has started.
	time.Sleep(200 * time.Millisecond)

	if g != nil {
		t.Error("started a DNS watch group although no target has dnsWatch set")
	}
}
