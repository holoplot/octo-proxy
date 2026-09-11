//go:build linux

package mdns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	dbus "github.com/godbus/dbus/v5"
	"github.com/holoplot/go-avahi"
	"github.com/rs/zerolog/log"
)

var resolver *avahiResolver

type serviceTracker struct {
	avahiServer *avahi.Server
	services    map[string]avahi.Service
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

func (a *avahiResolver) resolveService(name string, v4, v6 bool, timeout time.Duration) ([]net.TCPAddr, error) {
	a.trackerMutex.Lock()
	tracker, ok := a.tracker[name]
	a.trackerMutex.Unlock()

	if !ok {
		return nil, fmt.Errorf("service %s not tracked", name)
	}

	tracker.mutex.Lock()

	var (
		addrs []net.TCPAddr
		wg    sync.WaitGroup
		mutex sync.Mutex
	)

	for _, service := range tracker.services {
		wg.Add(1)

		go func(s avahi.Service) {
			defer wg.Done()

			resolver, err := tracker.avahiServer.ServiceResolverNew(s.Interface, makeProto(v4, v6), s.Name, s.Type, s.Domain, s.Protocol, 0)
			if err != nil {
				log.Warn().Err(err).Msg("avahi.ServiceResolverNew() failed")
				return
			}

			defer tracker.avahiServer.ServiceResolverFree(resolver)

			select {
			case resolvedService, ok := <-resolver.FoundChannel:
				if !ok {
					return
				}

				addr := net.TCPAddr{
					IP:   net.ParseIP(resolvedService.Address),
					Port: int(resolvedService.Port),
				}

				mutex.Lock()
				addrs = append(addrs, addr)
				mutex.Unlock()

			case <-time.After(timeout):
			}
		}(service)
	}

	tracker.mutex.Unlock()

	wg.Wait()

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
		services:    make(map[string]avahi.Service),
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
		return fmt.Sprintf("%s.%s%%%d", service.Name, service.Domain, service.Interface)
	}

	go func() {
		for {
			select {
			case avahiService, ok := <-serviceBrowser.AddChannel:
				if !ok {
					return
				}

				tracker.mutex.Lock()
				tracker.services[keyForService(avahiService)] = avahiService
				tracker.mutex.Unlock()

			case avahiService, ok := <-serviceBrowser.RemoveChannel:
				if !ok {
					return
				}

				tracker.mutex.Lock()
				delete(tracker.services, keyForService(avahiService))
				tracker.mutex.Unlock()

			case <-time.After(time.Minute):
				// This is ugly: There is a race condition between the startup of the
				// Avahi daemon and the readiness of the interfaces will prevent any
				// services from being discovered.
				if err := makeServiceBrowser(); err != nil {
					log.Error().Err(err).Msg("Failed to re-create service browser")

					return
				}

			case <-ctx.Done():
				a.avahiServer.ServiceBrowserFree(serviceBrowser)
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

func ResolveService(name string, v4, v6 bool, timeout time.Duration) ([]net.TCPAddr, error) {
	if resolver == nil {
		return nil, fmt.Errorf("no resolver")
	}

	return resolver.resolveService(name, v4, v6, timeout)
}
