package main

import (
	"net"
	"testing"
)

func TestDiscoverPathMTUFallsBackWhenDialFails(t *testing.T) {
	// A zero-value endpoint is invalid and must use the same fallback applied
	// when route/interface discovery is impossible.
	got := discoverPathMTU(&net.UDPAddr{})
	if got != fallbackMTU {
		t.Fatalf("discoverPathMTU(zero-value endpoint) = %d, want fallback %d", got, fallbackMTU)
	}
}
