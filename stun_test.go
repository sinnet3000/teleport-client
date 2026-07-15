package main

import "testing"

func TestStunIntegrityUsesRawSessionSecret(t *testing.T) {
	const secret = "raw-session-secret"
	if got := stunIntegrityKey(secret); got != secret {
		t.Fatalf("STUN integrity key = %q, want original session secret %q", got, secret)
	}
}

func TestSTUNNetworkFollowsFamily(t *testing.T) {
	for _, tt := range []struct {
		family networkFamily
		want   string
	}{
		{familyIPv4, "udp4"},
		{familyIPv6, "udp6"},
	} {
		got, err := stunNetwork(tt.family)
		if err != nil || got != tt.want {
			t.Fatalf("stunNetwork(%v) = (%q, %v), want (%q, nil)", tt.family, got, err, tt.want)
		}
	}
	if _, err := stunNetwork(familyDual); err == nil {
		t.Fatal("stunNetwork(familyDual) unexpectedly succeeded")
	}
}

func TestConsoleCompatibleICEServerParsing(t *testing.T) {
	ice := []iceServer{{
		URLs: []string{
			"stun:stun.example:19302",
			"turn:turn.example:3478?transport=udp",
		},
	}}
	if got, ok := stunServerFromIce(ice); !ok || got != "stun.example:19302" {
		t.Fatalf("stunServerFromIce = (%q, %v), want (%q, true)", got, ok, "stun.example:19302")
	}
	if got, ok := turnServerFromIce(ice); !ok || got != "turn.example:3478" {
		t.Fatalf("turnServerFromIce = (%q, %v), want (%q, true)", got, ok, "turn.example:3478")
	}
}

func TestTurnServerRequiresConsoleSupportedUDPURL(t *testing.T) {
	for _, rawURL := range []string{
		"turn:turn.example:3478",
		"turn:turn.example:3478?transport=tcp",
		"turns:turn.example:5349?transport=udp",
	} {
		if got, ok := turnServerFromIce([]iceServer{{URLs: []string{rawURL}}}); ok {
			t.Fatalf("turnServerFromIce(%q) = (%q, true), want unsupported", rawURL, got)
		}
	}
}

func TestValidateTurnPrerequisitesPreservesReflexCandidate(t *testing.T) {
	ice := []iceServer{{URLs: []string{
		"stun:stun.example:3478",
		"turn:turn.example:3478?transport=udp",
	}}}
	if err := validateTurnPrerequisites(ice, []candidate{{Type: "reflex", Addr: "203.0.113.10:5000"}}); err != nil {
		t.Fatalf("valid TURN prerequisites rejected: %v", err)
	}
	if err := validateTurnPrerequisites(ice, []candidate{{Type: "iface", Addr: "192.168.1.10:5000"}}); err == nil {
		t.Fatal("TURN prerequisites accepted without a reflex candidate")
	}
}
