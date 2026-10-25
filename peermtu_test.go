package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestBuildPaddedEchoPayloadExactSizing(t *testing.T) {
	const secretHash = "test-secret-hash-1234567890abcdef"
	const ipHeaderLen = 20 // IPv4

	for _, targetPacketSize := range []int{1280, 1360, 1400, 1420, 1440} {
		t.Run(fmt.Sprintf("%d", targetPacketSize), func(t *testing.T) {
			payload, err := buildPaddedEchoPayload(secretHash, "req-42", 3000, targetPacketSize, ipHeaderLen)
			if err != nil {
				t.Fatalf("buildPaddedEchoPayload failed: %v", err)
			}

			totalPacketSize := len(payload) + ipHeaderLen + 8
			if totalPacketSize != targetPacketSize {
				t.Fatalf("total packet size = %d, want %d (payload len = %d)", totalPacketSize, targetPacketSize, len(payload))
			}

			var parsed struct {
				SessionSecretHash string `json:"session_secret_hash"`
				RequestID         string `json:"req_id"`
				Timeout           int    `json:"timeout"`
				Padding           string `json:"pad"`
			}
			if err := json.Unmarshal(payload, &parsed); err != nil {
				t.Fatalf("unmarshal payload failed: %v", err)
			}
			if parsed.RequestID != "req-42" || parsed.SessionSecretHash != secretHash {
				t.Fatalf("payload corrupted: %+v", parsed)
			}
			if len(parsed.Padding) == 0 {
				t.Fatal("expected padding in padded payload")
			}
		})
	}
}

func TestPeerMTUProberAllMilestonesSucceed(t *testing.T) {
	prober := newPeerMTUProber(1280, 1440, 0)
	if prober.ConfirmedMTU() != 1280 {
		t.Fatalf("initial confirmed MTU = %d, want 1280", prober.ConfirmedMTU())
	}
	if prober.State() != dplpmtudStateSearching {
		t.Fatalf("initial state = %v, want SEARCHING", prober.State())
	}

	expectedMilestones := []int{1360, 1400, 1420, 1440}
	for i, expected := range expectedMilestones {
		target, ok := prober.NextProbeMTU()
		if !ok || target != expected {
			t.Fatalf("step %d: NextProbeMTU = (%d, %v), want (%d, true)", i, target, ok, expected)
		}

		changed, confirmed, done := prober.RecordProbeResult(target, true)
		if !changed || confirmed != expected {
			t.Fatalf("step %d: RecordProbeResult = (%v, %d), want (true, %d)", i, changed, confirmed, expected)
		}

		isLast := (i == len(expectedMilestones)-1)
		if done != isLast {
			t.Fatalf("step %d: done = %v, want %v", i, done, isLast)
		}
	}

	if prober.State() != dplpmtudStateSearchComplete {
		t.Fatalf("final state = %v, want SEARCH_COMPLETE", prober.State())
	}
	if prober.ConfirmedMTU() != 1440 {
		t.Fatalf("final confirmed MTU = %d, want 1440", prober.ConfirmedMTU())
	}

	// Further NextProbeMTU returns false
	if _, ok := prober.NextProbeMTU(); ok {
		t.Fatal("NextProbeMTU should return false after search is complete")
	}
}

func TestPeerMTUProberStopsAtFailure(t *testing.T) {
	// Simulate an environment like Megacable IPv6 (route MTU 1472 -> max tunnel MTU 1392)
	// 1360 succeeds, 1400 fails
	prober := newPeerMTUProber(1280, 1420, 0)

	target, ok := prober.NextProbeMTU()
	if !ok || target != 1360 {
		t.Fatalf("first probe = %d, want 1360", target)
	}

	changed, confirmed, done := prober.RecordProbeResult(1360, true)
	if !changed || confirmed != 1360 || done {
		t.Fatalf("1360 probe = (%v, %d, %v), want (true, 1360, false)", changed, confirmed, done)
	}

	target, ok = prober.NextProbeMTU()
	if !ok || target != 1400 {
		t.Fatalf("second probe = %d, want 1400", target)
	}

	// First timeout for 1400: retry allowed
	changed, confirmed, done = prober.RecordProbeResult(1400, false)
	if changed || confirmed != 1360 || done {
		t.Fatalf("1400 first fail = (%v, %d, %v), want (false, 1360, false)", changed, confirmed, done)
	}

	// Should retry 1400
	target, ok = prober.NextProbeMTU()
	if !ok || target != 1400 {
		t.Fatalf("second attempt = %d, want 1400", target)
	}

	// Second timeout for 1400: MAX_PROBES reached, search terminates and locks to 1360
	changed, confirmed, done = prober.RecordProbeResult(1400, false)
	if changed || confirmed != 1360 || !done {
		t.Fatalf("1400 second fail = (%v, %d, %v), want (false, 1360, true)", changed, confirmed, done)
	}

	if prober.State() != dplpmtudStateSearchComplete {
		t.Fatalf("state = %v, want SEARCH_COMPLETE", prober.State())
	}
	if prober.ConfirmedMTU() != 1360 {
		t.Fatalf("locked MTU = %d, want 1360", prober.ConfirmedMTU())
	}
}

func TestPeerMTUProberManualOverrideDisabled(t *testing.T) {
	prober := newPeerMTUProber(1280, 1440, 1360)
	if prober.State() != dplpmtudStateDisabled {
		t.Fatalf("state = %v, want DISABLED", prober.State())
	}
	if prober.ConfirmedMTU() != 1360 {
		t.Fatalf("confirmed MTU = %d, want 1360", prober.ConfirmedMTU())
	}
	if _, ok := prober.NextProbeMTU(); ok {
		t.Fatal("NextProbeMTU should return false when manual override is set")
	}
}

func TestPeerMTUProberReset(t *testing.T) {
	prober := newPeerMTUProber(1280, 1440, 0)
	_, _, _ = prober.RecordProbeResult(1360, true)
	if prober.ConfirmedMTU() != 1360 {
		t.Fatalf("confirmed MTU = %d, want 1360", prober.ConfirmedMTU())
	}

	prober.Reset()
	if prober.ConfirmedMTU() != baseTunnelMTU {
		t.Fatalf("after reset, confirmed MTU = %d, want %d", prober.ConfirmedMTU(), baseTunnelMTU)
	}
	if prober.State() != dplpmtudStateSearching {
		t.Fatalf("after reset, state = %v, want SEARCHING", prober.State())
	}
	target, ok := prober.NextProbeMTU()
	if !ok || target != 1360 {
		t.Fatalf("after reset, first probe = %d, want 1360", target)
	}
}
