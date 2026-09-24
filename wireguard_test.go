package main

import (
	"net"
	"testing"
)

func TestDiscoverPathMTUFallsBackOnInvalidEndpoint(t *testing.T) {
	// Every early-return guard must use the same fallback; discovery never
	// reaches DialUDP for these.
	for _, tt := range []struct {
		name     string
		endpoint *net.UDPAddr
	}{
		{"nil", nil},
		{"nil IP", &net.UDPAddr{Port: 51820}},
		{"unspecified IPv4", &net.UDPAddr{IP: net.IPv4zero, Port: 51820}},
		{"unspecified IPv6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 51820}},
		{"zero port", &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 0}},
		{"port too large", &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 65536}},
		{"negative port", &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: -1}},
		{"zero-value endpoint", &net.UDPAddr{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := discoverPathMTU(tt.endpoint); got != fallbackMTU {
				t.Fatalf("discoverPathMTU(%v) = %d, want fallback %d", tt.endpoint, got, fallbackMTU)
			}
		})
	}
}
