//go:build linux

package mdns

import (
	"context"
	"fmt"
	"net"
	"sync"

	dbus "github.com/godbus/dbus/v5"
	"github.com/holoplot/go-avahi"
	"github.com/rs/zerolog/log"
)

var resolver *avahiResolver

type service struct {
	resolver   *avahi.ServiceResolver
	addrsMutex sync.RWMutex
	v4, v6     *net.TCPAddr
}

type serviceTracker struct {
	avahiServer *avahi.Server
	services    map[string]*service
	mutex       sync.Mutex
	cancelFunc  context.CancelFunc
}

type avahiResolver struct {
	dbusConn    *dbus.Conn
	avahiServer *avahi.Server

	trackerMutex sync.Mutex
	tracker      map[string]*serviceTracker
}

func makeProto(v4, v6 bool) int32 {
	if v4 && v6 {
		return avahi.ProtoUnspec
	} else if v4 {
		return avahi.ProtoInet
	} else if v6 {
		return avahi.ProtoInet6
	}

	return avahi.ProtoUnspec
}

func (a *avahiResolver) resolveService(name string, v4, v6 bool) ([]net.TCPAddr, error) {
	a.trackerMutex.Lock()
	tracker, ok := a.tracker[name]
	a.trackerMutex.Unlock()

	if !ok {
		return nil, fmt.Errorf("service %s not tracked", name)
	}

	addrs := make([]net.TCPAddr, 0)

	tracker.mutex.Lock()

	for _, service := range tracker.services {
		service.addrsMutex.RLock()

		if v4 && service.v4 != nil {
			addrs = append(addrs, *service.v4)
		}

		if v6 && service.v6 != nil {
			addrs = append(addrs, *service.v6)
		}

		service.addrsMutex.RUnlock()
	}

	tracker.mutex.Unlock()

	if len(addrs) == 0 {
		log.Debug().Str("name", name).Msg("No mDNS addresses found for service")
	} else {
		s := make([]string, len(addrs))

		for i, addr := range addrs {
			s[i] = addr.AddrPort().String()
		}

		log.Debug().Str("name", name).Strs("ips", s).Msg("Resolved mDNS service")
	}

	return addrs, nil
}

func (a *avahiResolver) trackService(name string, v4, v6 bool) error {
	a.trackerMutex.Lock()
	defer a.trackerMutex.Unlock()

	if _, ok := a.tracker[name]; ok {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	tracker := &serviceTracker{
		avahiServer: a.avahiServer,
		services:    make(map[string]*service),
		cancelFunc:  cancel,
	}

	var serviceBrowser *avahi.ServiceBrowser

	makeServiceBrowser := func() error {
		var err error

		if serviceBrowser != nil {
			a.avahiServer.ServiceBrowserFree(serviceBrowser)
		}

		serviceBrowser, err = a.avahiServer.ServiceBrowserNew(avahi.InterfaceUnspec, makeProto(v4, v6), name, "local", 0)
		if err != nil {
			return fmt.Errorf("avahi.ServiceBrowserNew() failed: %w", err)
		}

		return nil
	}

	if err := makeServiceBrowser(); err != nil {
		log.Error().Err(err).Msg("Failed to create service browser")

		return err
	}

	keyForService := func(service avahi.Service) string {
		return fmt.Sprintf("%s.%s%%%d/%d", service.Name, service.Domain, service.Interface, service.Protocol)
	}

	go func() {
		defer func() {
			a.trackerMutex.Lock()

			// Only remove ourselves conditionally, in case another tracker was installed meanwhile.
			if a.tracker[name] == tracker {
				delete(a.tracker, name)
			}

			a.trackerMutex.Unlock()

			tracker.mutex.Lock()
			services := tracker.services
			tracker.services = nil
			tracker.mutex.Unlock()

			for _, s := range services {
				a.avahiServer.ServiceResolverFree(s.resolver)
			}

			a.avahiServer.ServiceBrowserFree(serviceBrowser)
		}()

		for {
			select {
			case avahiService, ok := <-serviceBrowser.AddChannel:
				if !ok {
					return
				}

				key := keyForService(avahiService)

				tracker.mutex.Lock()
				_, tracked := tracker.services[key]
				tracker.mutex.Unlock()

				if tracked {
					continue
				}

				resolver, err := tracker.avahiServer.ServiceResolverNew(avahiService.Interface, avahiService.Protocol,
					avahiService.Name, avahiService.Type, avahiService.Domain, makeProto(v4, v6), 0)
				if err != nil {
					log.Warn().Err(err).Msg("avahi.ServiceResolverNew() failed")

					continue
				}

				s := &service{
					resolver: resolver,
				}

				tracker.mutex.Lock()
				tracker.services[key] = s
				tracker.mutex.Unlock()

				go func(s *service, resolver *avahi.ServiceResolver) {
					for resolvedService := range resolver.FoundChannel {
						addr := &net.TCPAddr{
							IP:   net.ParseIP(resolvedService.Address),
							Port: int(resolvedService.Port),
						}

						if addr.IP.IsLinkLocalUnicast() {
							if iface, err := net.InterfaceByIndex(int(resolvedService.Interface)); err == nil {
								addr.Zone = iface.Name
							}
						}

						s.addrsMutex.Lock()

						if resolvedService.Aprotocol == avahi.ProtoInet {
							s.v4 = addr
						}

						if resolvedService.Aprotocol == avahi.ProtoInet6 {
							s.v6 = addr
						}

						s.addrsMutex.Unlock()
					}
				}(s, resolver)

			case avahiService, ok := <-serviceBrowser.RemoveChannel:
				if !ok {
					return
				}

				key := keyForService(avahiService)

				tracker.mutex.Lock()
				s, ok := tracker.services[key]
				delete(tracker.services, key)
				tracker.mutex.Unlock()

				if ok {
					tracker.avahiServer.ServiceResolverFree(s.resolver)
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	a.tracker[name] = tracker

	return nil
}

func (a *avahiResolver) untrackServices() {
	a.trackerMutex.Lock()
	defer a.trackerMutex.Unlock()

	for _, tracker := range a.tracker {
		tracker.cancelFunc()
	}

	a.tracker = make(map[string]*serviceTracker)
}

func newAvahiResolver() (*avahiResolver, error) {
	dbusConn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	avahiServer, err := avahi.ServerNew(dbusConn)
	if err != nil {
		return nil, fmt.Errorf("avahi.ServerNew() failed: %w", err)
	}

	return &avahiResolver{
		dbusConn:    dbusConn,
		avahiServer: avahiServer,
		tracker:     make(map[string]*serviceTracker),
	}, nil
}

// Public interface

func TrackService(name string, v4, v6 bool) error {
	if resolver == nil {
		var err error

		resolver, err = newAvahiResolver()
		if err != nil {
			return err
		}
	}

	return resolver.trackService(name, v4, v6)
}

func UntrackServices() {
	if resolver != nil {
		resolver.untrackServices()
	}
}

func ResolveService(name string, v4, v6 bool) ([]net.TCPAddr, error) {
	if resolver == nil {
		return nil, fmt.Errorf("no resolver")
	}

	return resolver.resolveService(name, v4, v6)
}
