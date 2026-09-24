package main

import (
	"slices"
	"testing"
	"time"
)

func TestNextEndpointCandidateSkipsOnlyCurrentEndpoint(t *testing.T) {
	queue := []string{"", "candidate-a", "candidate-b", "candidate-c"}

	candidate, next, ok := nextEndpointCandidate(queue, 0, "candidate-a")
	if !ok || candidate != "candidate-b" || next != 3 {
		t.Fatalf("first fallback = (%q, %d, %v), want (%q, 3, true)", candidate, next, ok, "candidate-b")
	}

	candidate, next, ok = nextEndpointCandidate(queue, next, "candidate-b")
	if !ok || candidate != "candidate-c" || next != 4 {
		t.Fatalf("second fallback = (%q, %d, %v), want (%q, 4, true)", candidate, next, ok, "candidate-c")
	}

	if candidate, _, ok = nextEndpointCandidate([]string{"candidate-a"}, 0, "other"); !ok || candidate != "candidate-a" {
		t.Fatalf("queue head was incorrectly skipped: candidate=%q ok=%v", candidate, ok)
	}
}

func TestParseWireGuardPeerStats(t *testing.T) {
	stats := parseWireGuardPeerStats("public_key=abc\nendpoint=203.0.113.1:51820\nlast_handshake_time_sec=1700000000\nrx_bytes=42\ntx_bytes=99\n")
	if !stats.valid || stats.endpoint != "203.0.113.1:51820" || stats.rxBytes != 42 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if want := time.Unix(1700000000, 0); !stats.lastHandshake.Equal(want) {
		t.Fatalf("last handshake = %v, want %v", stats.lastHandshake, want)
	}
}

// TestParseWireGuardPeerStatsHandshakeDetection covers the values
// retryEndpointOnHandshakeTimeout relies on: only a parsed, positive
// last_handshake_time_sec counts as a completed handshake. The old inline
// parser treated any non-"0" string (including garbage) as success.
func TestParseWireGuardPeerStatsHandshakeDetection(t *testing.T) {
	for _, tt := range []struct {
		name string
		ipc  string
		want bool
	}{
		{"zero", "last_handshake_time_sec=0", false},
		{"missing", "endpoint=203.0.113.1:51820", false},
		{"empty value", "last_handshake_time_sec=", false},
		{"positive", "last_handshake_time_sec=1700000000", true},
		{"garbage", "last_handshake_time_sec=not-a-number", false},
		{"negative", "last_handshake_time_sec=-5", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := !parseWireGuardPeerStats(tt.ipc).lastHandshake.IsZero()
			if got != tt.want {
				t.Fatalf("handshake detected = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWireGuardPathActiveSinceRequiresProgressFromHealthyBaseline(t *testing.T) {
	now := time.Unix(1700000100, 0)
	baseline := wireGuardPeerStats{lastHandshake: now.Add(-time.Minute), rxBytes: 100, valid: true}
	if wireGuardPathActiveSince(baseline, baseline, now) {
		t.Fatal("unchanged WireGuard state was treated as active")
	}
	withRX := baseline
	withRX.rxBytes++
	if !wireGuardPathActiveSince(baseline, withRX, now) {
		t.Fatal("new receive traffic was not treated as active")
	}
	withHandshake := baseline
	withHandshake.lastHandshake = baseline.lastHandshake.Add(time.Second)
	if !wireGuardPathActiveSince(baseline, withHandshake, now) {
		t.Fatal("new handshake was not treated as active")
	}
}

func TestWireGuardPathActiveSinceAcceptsRecentHandshakeWithoutBaseline(t *testing.T) {
	now := time.Unix(1700000100, 0)
	current := wireGuardPeerStats{lastHandshake: now.Add(-wireGuardRecentHandshakeWindow + time.Second), valid: true}
	if !wireGuardPathActiveSince(wireGuardPeerStats{}, current, now) {
		t.Fatal("recent handshake without a baseline was not treated as active")
	}
	current.lastHandshake = now.Add(-wireGuardRecentHandshakeWindow - time.Second)
	if wireGuardPathActiveSince(wireGuardPeerStats{}, current, now) {
		t.Fatal("stale handshake without a baseline was treated as active")
	}
}

func TestBuildEndpointRecoveryOrderStartsWithCurrentAndDeduplicates(t *testing.T) {
	got := buildEndpointRecoveryOrder("candidate-b", []string{"candidate-a", "candidate-b", "", "candidate-c", "candidate-a"})
	want := []string{"candidate-b", "candidate-a", "candidate-c"}
	if !slices.Equal(got, want) {
		t.Fatalf("recovery order = %#v, want %#v", got, want)
	}
}
