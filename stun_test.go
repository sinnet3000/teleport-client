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
