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

// trackerKey identifies a tracker. The same service can be tracked on all
// interfaces (iface "") and on single interfaces at the same time.
func trackerKey(name, iface string) string {
	if iface == "" {
		return name
	}

	return name + "%" + iface
}

// browseInterface returns the avahi interface index to browse on.
func browseInterface(iface string) (int32, error) {
	if iface == "" {
		return avahi.InterfaceUnspec, nil
	}

	i, err := net.InterfaceByName(iface)
	if err != nil {
		return 0, fmt.Errorf("interface %s: %w", iface, err)
	}

	return int32(i.Index), nil
}

func (a *avahiResolver) resolveService(name, iface string, v4, v6 bool) ([]net.TCPAddr, error) {
	key := trackerKey(name, iface)

	a.trackerMutex.Lock()
	tracker, ok := a.tracker[key]
	a.trackerMutex.Unlock()

	if !ok {
		return nil, fmt.Errorf("service %s not tracked", key)
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
		log.Debug().Str("name", key).Msg("No mDNS addresses found for service")
	} else {
		s := make([]string, len(addrs))

		for i, addr := range addrs {
			s[i] = fmt.Sprintf("%s:%d", addr.IP.String(), addr.Port)
		}

		log.Debug().Str("name", key).Strs("ips", s).Msg("Resolved mDNS service")
	}

	return addrs, nil
}

func (a *avahiResolver) trackService(name, iface string, v4, v6 bool) error {
	a.trackerMutex.Lock()
	defer a.trackerMutex.Unlock()

	key := trackerKey(name, iface)

	if _, ok := a.tracker[key]; ok {
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
		ifIndex, err := browseInterface(iface)
		if err != nil {
			return err
		}

		if serviceBrowser != nil {
			a.avahiServer.ServiceBrowserFree(serviceBrowser)
		}

		serviceBrowser, err = a.avahiServer.ServiceBrowserNew(ifIndex, makeProto(v4, v6), name, "local", 0)
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
			if a.tracker[key] == tracker {
				delete(a.tracker, key)
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

	a.tracker[key] = tracker

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

// TrackService starts tracking an mDNS service. With iface set, only that
// network interface is browsed.
func TrackService(name, iface string, v4, v6 bool) error {
	if resolver == nil {
		var err error

		resolver, err = newAvahiResolver()
		if err != nil {
			return err
		}
	}

	return resolver.trackService(name, iface, v4, v6)
}

func UntrackServices() {
	if resolver != nil {
		resolver.untrackServices()
	}
}

// ResolveService returns the addresses of a tracked service.
func ResolveService(name, iface string, v4, v6 bool) ([]net.TCPAddr, error) {
	if resolver == nil {
		return nil, fmt.Errorf("no resolver")
	}

	return resolver.resolveService(name, iface, v4, v6)
}
