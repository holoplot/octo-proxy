package config

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/nothinux/octo-proxy/pkg/errors"
	"github.com/rs/zerolog/log"

	"gopkg.in/yaml.v2"
)

type hostConfigType int

const (
	slistener hostConfigType = iota
	starget
	smirror
	smetrics
)

type Config struct {
	ServerConfigs []ServerConfig `yaml:"servers"`
	MetricsConfig HostConfig     `yaml:"metrics"`
}

type ServerConfig struct {
	Name       string           `yaml:"name"`
	Listener   HostConfig       `yaml:"listener"`
	Targets    []HostConfig     `yaml:"targets"`
	MDNSTarget MDNSTargetConfig `yaml:"mdnsTarget"`
	Mirror     HostConfig       `yaml:"mirror"`
}

type HostConfig struct {
	Host             string `yaml:"host"`
	Port             string `yaml:"port"`
	ConnectionConfig `yaml:"connection"`
	TLSConfig        `yaml:"tls"`
}

type MDNSTargetConfig struct {
	ServiceName      string `yaml:"serviceName"`
	IPv4             bool   `yaml:"ipv4"`
	IPv6             bool   `yaml:"ipv6"`
	ConnectionConfig `yaml:"connection"`
	TLSConfig        `yaml:"tls"`
}

type ConnectionConfig struct {
	ConnectTimeout         int    `yaml:"connectTimeout"` // TODO: Implement connect timeout
	Timeout                string `yaml:"timeout"`
	IdleTimeout            int    `yaml:"idleTimeout"` // TODO: Implement idle timeout
	ConnectTimeoutDuration time.Duration
	TimeoutDuration        time.Duration
	IdleTimeoutDuration    time.Duration
}

type TLSConfig struct {
	CaCert          string   `yaml:"caCert"`
	Cert            string   `yaml:"cert"`
	Key             string   `yaml:"key"`
	Mode            string   `yaml:"mode"`
	SubjectAltNames []string `yaml:"subjectAltNames"`
	SubjectAltName
	Role
}

type SubjectAltName struct {
	IPAddress []string
	Uri       []string
	DNS       []string
}

type Role struct {
	Server bool
}

func (t TLSConfig) IsMutual() bool {
	return t.Mode == "mutual"
}

func (t TLSConfig) IsSimple() bool {
	return t.Mode == "simple"
}

func (h hostConfigType) String() string {
	return [...]string{"listener", "target", "mirror", "metrics"}[h]
}

func New(configPath string) (*Config, error) {
	c, err := openConfig(configPath)
	if err != nil {
		return nil, err
	}

	return validateConfig(c)
}

func openConfig(configPath string) (*Config, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return readConfig(f)
}

func readConfig(r io.Reader) (*Config, error) {
	config := &Config{}

	d := yaml.NewDecoder(r)
	if err := d.Decode(config); err != nil {
		return nil, err
	}

	return config, nil
}

func GenerateConfig(listener string, targets []string, metrics string) (*Config, error) {
	l := strings.Split(listener, ":")

	if len(l) != 2 {
		return nil, errors.New("error", "listener must be specified in format host:port")
	}

	c := &Config{
		ServerConfigs: []ServerConfig{
			{
				Name: "default",
				Listener: HostConfig{
					Host: l[0],
					Port: l[1],
				},
				Targets: []HostConfig{},
			},
		},
	}

	for _, target := range targets {
		t := strings.Split(target, ":")
		if len(t) != 2 {
			return nil, errors.New("error", "target must be specified in format host:port")
		}

		hc := HostConfig{
			Host: t[0],
			Port: t[1],
		}

		c.ServerConfigs[0].Targets = append(c.ServerConfigs[0].Targets, hc)
	}

	if len(metrics) > 0 {
		t := strings.Split(metrics, ":")
		if len(t) != 2 {
			return nil, errors.New("error", "metrics server address must be specified in format host:port")
		}

		c.MetricsConfig = HostConfig{
			Host: t[0],
			Port: t[1],
		}
	}

	return validateConfig(c)
}

func validateConfig(c *Config) (*Config, error) {
	if c == nil {
		return nil, errors.New("config", "error no configuration found")
	}

	if len(c.ServerConfigs) == 0 {
		return nil, errors.New("servers", "error no server configuration found")
	}

	for i := range c.ServerConfigs {
		listener := &c.ServerConfigs[i].Listener
		mirror := &c.ServerConfigs[i].Mirror

		if err := errorCheck(i, slistener, listener); err != nil {
			return nil, err
		}

		if len(c.ServerConfigs[i].Targets) == 0 && c.ServerConfigs[i].MDNSTarget.ServiceName == "" {
			return nil, errors.New("server", fmt.Sprintf("no target configurations in servers.[%d]", i))
		}

		for j := range c.ServerConfigs[i].Targets {
			if err := errorCheck(i, starget, &c.ServerConfigs[i].Targets[j]); err != nil {
				return nil, err
			}

			if err := setTimeout(&c.ServerConfigs[i].Targets[j].ConnectionConfig); err != nil {
				return nil, errors.New("server", fmt.Sprintf("failed to parse timeout servers.[%d].targets[%d]: %v", i, j, err))
			}

			setSAN(&c.ServerConfigs[i].Targets[j].TLSConfig)
		}

		if c.ServerConfigs[i].MDNSTarget.ServiceName != "" {
			if !strings.HasPrefix(c.ServerConfigs[i].MDNSTarget.ServiceName, "_") {
				return nil, errors.New("server", fmt.Sprintf("invalid mDNS service name servers.[%d].mdnsServiceTarget.serviceName: %s",
					i, c.ServerConfigs[i].MDNSTarget.ServiceName))
			}

			if !c.ServerConfigs[i].MDNSTarget.IPv4 && !c.ServerConfigs[i].MDNSTarget.IPv6 {
				return nil, errors.New("server", fmt.Sprintf("invalid mDNS service configuration servers.[%d].mdnsServiceTarget: neither v4 nor v6 is enabled", i))
			}

			if err := setTimeout(&c.ServerConfigs[i].MDNSTarget.ConnectionConfig); err != nil {
				return nil, errors.New("server", fmt.Sprintf("failed to parse timeout servers.[%d].mdnsServiceTarget: %v", i, err))
			}

			setSAN(&c.ServerConfigs[i].MDNSTarget.TLSConfig)
		}

		// check config for error only when configuration is not nil
		if !reflect.DeepEqual(HostConfig{}, *mirror) {
			if err := errorCheck(i, smirror, mirror); err != nil {
				return nil, err
			}

			if err := setTimeout(&mirror.ConnectionConfig); err != nil {
				return nil, errors.New("server", fmt.Sprintf("failed to parse timeout servers.[%d].mirror: %v", i, err))
			}

			setSAN(&mirror.TLSConfig)
		}
		// set all listener role to server
		if !reflect.DeepEqual(TLSConfig{}, c.ServerConfigs[i].Listener.TLSConfig) {
			listener.TLSConfig.Role.Server = true
		}

		if err := setTimeout(&listener.ConnectionConfig); err != nil {
			return nil, errors.New("server", fmt.Sprintf("failed to parse timeout servers.[%d]: %v", i, err))
		}

		setSAN(&listener.TLSConfig)
	}

	if !reflect.DeepEqual(HostConfig{}, c.MetricsConfig) {
		if err := errorCheck(0, smetrics, &c.MetricsConfig); err != nil {
			// TODO: handle error in errorcheck
			return nil, errors.New("metrics", strings.TrimLeft(err.Error(), "[server] host in servers.[0]."))
		}

		for _, sc := range c.ServerConfigs {
			if c.MetricsConfig.Port == sc.Listener.Port {
				return nil, errors.New("metrics", "can't bind to port that already used by listener")
			}
		}
	}

	return c, nil
}

type timeoutFormat struct {
	unit     string
	duration time.Duration
}

func setTimeout(c *ConnectionConfig) error {
	var format []timeoutFormat
	format = append(format, timeoutFormat{"ms", time.Millisecond})
	format = append(format, timeoutFormat{"s", time.Second})

	timeout := c.Timeout

	if timeout == "" {
		c.TimeoutDuration = time.Duration(300) * time.Second
		return nil
	}

	if timeout == "0" {
		return nil
	}

	for _, v := range format {
		if strings.HasSuffix(timeout, v.unit) {
			return setTimeoutDuration(c, strings.TrimSuffix(timeout, v.unit), v.duration)
		}
	}

	// use seconds if user not provide unit
	return setTimeoutDuration(c, timeout, time.Second)
}

func setTimeoutDuration(c *ConnectionConfig, timeout string, td time.Duration) error {
	t, err := strconv.Atoi(timeout)
	if err != nil {
		log.Error().Err(err).Msg("Atoi")
		return err
	}

	if t < 0 {
		return fmt.Errorf("can't use negative value for timeout")
	}

	log.Info().
		Int("seconds", t).
		Msg("Applying timeout")

	c.TimeoutDuration = time.Duration(t) * td

	return nil
}

func setSAN(c *TLSConfig) {
	if len(c.SubjectAltNames) != 0 {
		c.SubjectAltName = *parseSubjectAltNames(c.SubjectAltNames)
	}
}

func errorCheck(i int, hct hostConfigType, c *HostConfig) error {
	if reflect.DeepEqual(HostConfig{}, *c) {
		return errors.New("server", fmt.Sprintf("no %s configuration in servers.[%d]", hct.String(), i))
	}

	if c.Host == "" {
		return errors.New("server", fmt.Sprintf("host in servers.[%d].%s.host not specified", i, hct.String()))
	}

	if hct != slistener {
		if !hostIsValid(c.Host) {
			return errors.New("server", fmt.Sprintf("host in servers.[%d].%s.host is not valid ip address", i, hct.String()))
		}
	} else {
		if !hostIPIsValid(c.Host) {
			return errors.New("server", fmt.Sprintf("host in servers.[%d].%s.host is not valid ip address", i, hct.String()))
		}
	}

	if c.Port == "" {
		return errors.New("server", fmt.Sprintf("port in servers.[%d].%s.port not specified", i, hct.String()))
	}

	if !portIsValid(c.Port) {
		return errors.New("server", fmt.Sprintf("port in servers.[%d].%s.port is not valid port number", i, hct.String()))
	}

	// inform user when cacert, cert and key provided but
	if c.TLSConfig.CaCert != "" || c.TLSConfig.Cert != "" || c.TLSConfig.Key != "" {
		if c.TLSConfig.Mode == "" {
			return errors.New("server.tlsConfig", fmt.Sprintf("ignore cacert, cert or key in servers.[%d].%s because tlsConfig.mode is not set", i, hct.String()))
		}

		if !c.TLSConfig.IsMutual() && !c.TLSConfig.IsSimple() {
			return errors.New("server.tlsConfig", fmt.Sprintf("not supported mode in servers.[%d].%s", i, hct.String()))
		}
	}

	if c.TLSConfig.IsMutual() {
		// if mode is mutual cert, key and ca cert must be set
		if c.TLSConfig.CaCert == "" || c.TLSConfig.Cert == "" || c.TLSConfig.Key == "" {
			return errors.New("server.tlsConfig", fmt.Sprintf("cacert, cert and key in servers.[%d].%s must be set if mode is mutual", i, hct.String()))
		}
	}

	return nil
}
