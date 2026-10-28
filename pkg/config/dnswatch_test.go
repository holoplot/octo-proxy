package config

import (
	"strings"
	"testing"
	"time"
)

func dnsWatchTestConfig() *Config {
	return &Config{
		ServerConfigs: []ServerConfig{
			{
				Name: "proxy-a",
				Listener: HostConfig{
					Host: "127.0.0.1",
					Port: "4222",
				},
				Targets: []HostConfig{
					{
						Host:     "backend.example.com",
						Port:     "4222",
						DNSWatch: true,
					},
				},
			},
		},
	}
}

func TestDNSWatchConfigFromYAML(t *testing.T) {
	r := strings.NewReader(`
dnsWatch:
  interval: 3s
servers:
  - name: example
    listener:
      host: 127.0.0.1
      port: 4222
    targets:
      - host: backend.example.com
        port: 4222
        dnsWatch: true
        connection:
          dialStagger: 100ms
`)

	c, err := readConfig(r)
	if err != nil {
		t.Fatal(err)
	}

	c, err = validateConfig(c)
	if err != nil {
		t.Fatal(err)
	}

	if got := c.DNSWatch.IntervalDuration; got != 3*time.Second {
		t.Errorf("interval: got %v, want 3s", got)
	}

	target := c.ServerConfigs[0].Targets[0]
	if !target.DNSWatch {
		t.Error("target dnsWatch flag not parsed")
	}

	if got := target.DialStaggerDuration; got != 100*time.Millisecond {
		t.Errorf("dialStagger: got %v, want 100ms", got)
	}
}

func TestDNSWatchIntervalDefault(t *testing.T) {
	c, err := validateConfig(dnsWatchTestConfig())
	if err != nil {
		t.Fatal(err)
	}

	if got := c.DNSWatch.IntervalDuration; got != 5*time.Second {
		t.Errorf("got %v, want 5s", got)
	}
}

func TestDNSWatchIntervalInvalid(t *testing.T) {
	for _, interval := range []string{"foo", "0s", "-1s"} {
		c := dnsWatchTestConfig()
		c.DNSWatch.Interval = interval

		if _, err := validateConfig(c); err == nil {
			t.Errorf("interval %q: expected an error", interval)
		}
	}
}

func TestDNSWatchRequiresHostname(t *testing.T) {
	c := dnsWatchTestConfig()
	c.ServerConfigs[0].Targets[0].Host = "10.0.0.1"

	_, err := validateConfig(c)
	if err == nil || !strings.Contains(err.Error(), "dnsWatch requires a hostname") {
		t.Errorf("got %v, want a dnsWatch hostname error", err)
	}
}

func TestDNSWatchOnlyOnTargets(t *testing.T) {
	t.Run("listener", func(t *testing.T) {
		c := dnsWatchTestConfig()
		c.ServerConfigs[0].Listener.DNSWatch = true

		if _, err := validateConfig(c); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("mirror", func(t *testing.T) {
		c := dnsWatchTestConfig()
		c.ServerConfigs[0].Mirror = HostConfig{
			Host:     "mirror.example.com",
			Port:     "4222",
			DNSWatch: true,
		}

		if _, err := validateConfig(c); err == nil {
			t.Error("expected an error")
		}
	})

	t.Run("metrics", func(t *testing.T) {
		c := dnsWatchTestConfig()
		c.MetricsConfig = HostConfig{
			Host:     "127.0.0.1",
			Port:     "9123",
			DNSWatch: true,
		}

		if _, err := validateConfig(c); err == nil {
			t.Error("expected an error")
		}
	})
}

func TestDialStaggerDefault(t *testing.T) {
	c := dnsWatchTestConfig()
	c.ServerConfigs[0].Mirror = HostConfig{
		Host: "mirror.example.com",
		Port: "4222",
	}

	c, err := validateConfig(c)
	if err != nil {
		t.Fatal(err)
	}

	if got := c.ServerConfigs[0].Targets[0].DialStaggerDuration; got != 250*time.Millisecond {
		t.Errorf("target: got %v, want 250ms", got)
	}

	if got := c.ServerConfigs[0].Mirror.DialStaggerDuration; got != 250*time.Millisecond {
		t.Errorf("mirror: got %v, want 250ms", got)
	}
}

func TestDialStaggerZeroAllowed(t *testing.T) {
	c := dnsWatchTestConfig()
	c.ServerConfigs[0].Targets[0].DialStagger = "0s"

	c, err := validateConfig(c)
	if err != nil {
		t.Fatal(err)
	}

	if got := c.ServerConfigs[0].Targets[0].DialStaggerDuration; got != 0 {
		t.Errorf("got %v, want 0", got)
	}
}

func TestDialStaggerInvalid(t *testing.T) {
	c := dnsWatchTestConfig()
	c.ServerConfigs[0].Targets[0].DialStagger = "foo"

	if _, err := validateConfig(c); err == nil {
		t.Error("expected an error")
	}
}
