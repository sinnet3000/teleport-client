package main

import (
	"net"
	"strings"
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

func TestResolveConfiguredMTU(t *testing.T) {
	for _, tt := range []struct {
		name      string
		cliMTU    int
		envMTU    string
		wantMTU   int
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "default unconfigured",
			cliMTU:  0,
			envMTU:  "",
			wantMTU: 0,
			wantErr: false,
		},
		{
			name:    "cli flag valid",
			cliMTU:  1360,
			envMTU:  "",
			wantMTU: 1360,
			wantErr: false,
		},
		{
			name:    "cli flag min boundary",
			cliMTU:  1280,
			envMTU:  "",
			wantMTU: 1280,
			wantErr: false,
		},
		{
			name:    "cli flag max boundary",
			cliMTU:  1500,
			envMTU:  "",
			wantMTU: 1500,
			wantErr: false,
		},
		{
			name:    "cli flag takes precedence over env",
			cliMTU:  1360,
			envMTU:  "1400",
			wantMTU: 1360,
			wantErr: false,
		},
		{
			name:      "cli flag below min",
			cliMTU:    1279,
			envMTU:    "",
			wantErr:   true,
			errSubstr: "--mtu must be between 1280 and 1500",
		},
		{
			name:      "cli flag above max",
			cliMTU:    1501,
			envMTU:    "",
			wantErr:   true,
			errSubstr: "--mtu must be between 1280 and 1500",
		},
		{
			name:    "env var valid",
			cliMTU:  0,
			envMTU:  "1360",
			wantMTU: 1360,
			wantErr: false,
		},
		{
			name:    "env var with whitespace",
			cliMTU:  0,
			envMTU:  "  1360 \t\n",
			wantMTU: 1360,
			wantErr: false,
		},
		{
			name:    "env var min boundary",
			cliMTU:  0,
			envMTU:  "1280",
			wantMTU: 1280,
			wantErr: false,
		},
		{
			name:    "env var max boundary",
			cliMTU:  0,
			envMTU:  "1500",
			wantMTU: 1500,
			wantErr: false,
		},
		{
			name:      "env var below min",
			cliMTU:    0,
			envMTU:    "1279",
			wantErr:   true,
			errSubstr: "TELEPORT_MTU must be between 1280 and 1500",
		},
		{
			name:      "env var above max",
			cliMTU:    0,
			envMTU:    "1501",
			wantErr:   true,
			errSubstr: "TELEPORT_MTU must be between 1280 and 1500",
		},
		{
			name:      "env var non-numeric",
			cliMTU:    0,
			envMTU:    "not-a-number",
			wantErr:   true,
			errSubstr: "TELEPORT_MTU must be an integer",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveConfiguredMTU(tt.cliMTU, tt.envMTU)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveConfiguredMTU(%d, %q) succeeded, want error", tt.cliMTU, tt.envMTU)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("resolveConfiguredMTU(%d, %q) error = %q, want substr %q", tt.cliMTU, tt.envMTU, err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveConfiguredMTU(%d, %q) returned unexpected error: %v", tt.cliMTU, tt.envMTU, err)
			}
			if got != tt.wantMTU {
				t.Fatalf("resolveConfiguredMTU(%d, %q) = %d, want %d", tt.cliMTU, tt.envMTU, got, tt.wantMTU)
			}
		})
	}
}

func TestBuildConfig_MTU(t *testing.T) {
	info := serverInfo{
		WGPubKey:   "peer-pubkey",
		TunnelAddr: "192.168.88.2",
		TunnelMask: 24,
	}

	confWithMTU := buildConfig("my-private-key", 51820, "203.0.113.1:51820", info, []string{"192.168.88.1"}, "10.0.0.2", 1360)
	if !strings.Contains(confWithMTU, "MTU = 1360\n") {
		t.Fatalf("buildConfig with mtu=1360 missing 'MTU = 1360':\n%s", confWithMTU)
	}

	confWithoutMTU := buildConfig("my-private-key", 51820, "203.0.113.1:51820", info, []string{"192.168.88.1"}, "10.0.0.2", 0)
	if strings.Contains(confWithoutMTU, "MTU =") {
		t.Fatalf("buildConfig with mtu=0 should not contain 'MTU =':\n%s", confWithoutMTU)
	}
}

