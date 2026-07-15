package main

import (
	"net"
	"testing"
)

func loopbackInterface(t *testing.T) *net.Interface {
	t.Helper()
	for _, name := range []string{"lo0", "lo"} {
		if iface, err := net.InterfaceByName(name); err == nil {
			return iface
		}
	}
	t.Skip("no loopback interface found")
	return nil
}

func TestDiscoverPathMTUMatchesLoopbackInterface(t *testing.T) {
	loop := loopbackInterface(t)

	want := loop.MTU - wgOverheadBytes
	if want < minTunnelMTU {
		want = minTunnelMTU
	}
	if want > maxTunnelMTU {
		want = maxTunnelMTU
	}

	for _, endpoint := range []*net.UDPAddr{
		{IP: net.ParseIP("127.0.0.1"), Port: 65001},
		{IP: net.IPv6loopback, Port: 65002},
	} {
		// IPv6 may be disabled on this host/CI runner; skip rather than
		// asserting against the loopback interface if dialing it fails.
		if probe, err := net.DialUDP("udp", nil, endpoint); err != nil {
			t.Logf("skipping endpoint %s: dial failed: %v", endpoint, err)
			continue
		} else {
			probe.Close()
		}

		got := discoverPathMTU(endpoint)
		if got != want {
			t.Errorf("discoverPathMTU(%s) = %d, want %d (loopback %q MTU %d)", endpoint, got, want, loop.Name, loop.MTU)
		}
	}
}

func TestDiscoverPathMTUFallsBackWhenDialFails(t *testing.T) {
	// A zero-value endpoint is invalid and must use the same fallback applied
	// when route/interface discovery is impossible.
	got := discoverPathMTU(&net.UDPAddr{})
	if got != fallbackMTU {
		t.Fatalf("discoverPathMTU(zero-value endpoint) = %d, want fallback %d", got, fallbackMTU)
	}
}

func TestMTUConstantsAreConsistent(t *testing.T) {
	if fallbackMTU < minTunnelMTU {
		t.Fatalf("fallbackMTU (%d) must be >= minTunnelMTU (%d)", fallbackMTU, minTunnelMTU)
	}
	if maxTunnelMTU < minTunnelMTU {
		t.Fatalf("maxTunnelMTU (%d) must be >= minTunnelMTU (%d)", maxTunnelMTU, minTunnelMTU)
	}
	if wgOverheadBytes <= 0 {
		t.Fatalf("wgOverheadBytes must be positive, got %d", wgOverheadBytes)
	}
}
