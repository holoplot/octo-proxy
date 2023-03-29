//go:build !linux

package mdns

func TrackService(string) error {
	return nil
}

func UntrackServices() {
}

func ResolveService(name string, v4, v6 bool, timeout time.Duration) ([]net.TCPAddr, error) {
	return []net.TCPAddr{}, fmt.Errorf("not implemented")
}
