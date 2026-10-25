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

func TestResolveTCPCongestionControl(t *testing.T) {
	tests := []struct {
		name      string
		envVal    string
		wantCC    string
		wantErr   bool
		errSubstr string
	}{
		{"empty string", "", "", false, ""},
		{"whitespace only", "   ", "", false, ""},
		{"valid reno", "reno", "reno", false, ""},
		{"valid cubic", "cubic", "cubic", false, ""},
		{"uppercase cubic", "CUBIC", "cubic", false, ""},
		{"mixed case trimmed reno", "  Reno  ", "reno", false, ""},
		{"unsupported bbr", "bbr", "", true, "unsupported TELEPORT_TCP_CONGESTION_CONTROL"},
		{"unsupported other", "vegas", "", true, "unsupported TELEPORT_TCP_CONGESTION_CONTROL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveTCPCongestionControl(tt.envVal)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveTCPCongestionControl(%q) succeeded, want error", tt.envVal)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("resolveTCPCongestionControl(%q) error = %q, want substr %q", tt.envVal, err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveTCPCongestionControl(%q) returned unexpected error: %v", tt.envVal, err)
			}
			if got != tt.wantCC {
				t.Fatalf("resolveTCPCongestionControl(%q) = %q, want %q", tt.envVal, got, tt.wantCC)
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

func TestWireGuardOverhead(t *testing.T) {
	tests := []struct {
		name     string
		endpoint *net.UDPAddr
		want     int
	}{
		{"nil", nil, 60},
		{"nil IP", &net.UDPAddr{Port: 51820}, 60},
		{"IPv4 endpoint", &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 51820}, 60},
		{"IPv4 loopback", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 51820}, 60},
		{"IPv6 endpoint", &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 51820}, 80},
		{"IPv6 loopback", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 51820}, 80},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := wireGuardOverhead(tt.endpoint); got != tt.want {
				t.Fatalf("wireGuardOverhead(%v) = %d, want %d", tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestParseDarwinRouteMTU(t *testing.T) {
	const sampleIPv6RA = `   route to: 2001:4860:4860::8888
destination: ::
       mask: default
    gateway: fe80::1%en0
  interface: en0
      flags: <UP,GATEWAY,DONE,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1472         0 `

	if got := parseDarwinRouteMTU(sampleIPv6RA); got != 1472 {
		t.Fatalf("parseDarwinRouteMTU(sampleIPv6RA) = %d, want 1472", got)
	}

	const sampleIPv4 = `   route to: 1.1.1.1
destination: default
       mask: default
    gateway: 192.168.100.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0 `

	if got := parseDarwinRouteMTU(sampleIPv4); got != 1500 {
		t.Fatalf("parseDarwinRouteMTU(sampleIPv4) = %d, want 1500", got)
	}

	const sampleNoMTU = `   route to: 10.0.0.1
destination: 10.0.0.1
  interface: en0
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0         0         0 `

	if got := parseDarwinRouteMTU(sampleNoMTU); got != 0 {
		t.Fatalf("parseDarwinRouteMTU(sampleNoMTU) = %d, want 0", got)
	}

	if got := parseDarwinRouteMTU("garbage output\nno table here\n"); got != 0 {
		t.Fatalf("parseDarwinRouteMTU(garbage) = %d, want 0", got)
	}
}

func TestParseLinuxRouteMTU(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   int
	}{
		{
			name:   "with mtu",
			output: "1.1.1.1 via 10.0.0.1 dev enp0s6 src 10.0.0.248 mtu 1472 uid 1001\n    cache",
			want:   1472,
		},
		{
			name:   "standard without mtu",
			output: "1.1.1.1 via 10.0.0.1 dev enp0s6 src 10.0.0.248 uid 1001\n    cache",
			want:   0,
		},
		{
			name:   "ipv6 with mtu",
			output: "2606:4700::1 via fe80::1 dev eth0 metric 100 mtu 1380 pref medium",
			want:   1380,
		},
		{
			name:   "empty",
			output: "",
			want:   0,
		},
		{
			name:   "mtu lock",
			output: "1.1.1.1 via 10.0.0.1 dev eth0 mtu lock 1400",
			want:   1400,
		},
		{
			name:   "mtu without value",
			output: "1.1.1.1 dev eth0 mtu",
			want:   0,
		},
		{
			name:   "mtu with invalid value",
			output: "1.1.1.1 dev eth0 mtu notanumber",
			want:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseLinuxRouteMTU(tt.output); got != tt.want {
				t.Fatalf("parseLinuxRouteMTU(%q) = %d, want %d", tt.output, got, tt.want)
			}
		})
	}
}

func TestComputeTunnelMTU(t *testing.T) {
	tests := []struct {
		name     string
		wireMTU  int
		overhead int
		want     int
	}{
		{"standard IPv4 1500", 1500, 60, 1440},
		{"standard IPv6 1500", 1500, 80, 1420},
		{"megacable IPv6 1472", 1472, 80, 1392},
		{"pppoe IPv4 1492", 1492, 60, 1432},
		{"pppoe IPv6 1492", 1492, 80, 1412},
		{"jumbo 9000 capped at 1500 IPv4", 9000, 60, 1440},
		{"jumbo 16384 capped at 1500 IPv6", 16384, 80, 1420},
		{"narrow 1300 IPv6 clamped up to 1280", 1300, 80, 1280},
		{"sub-minimum 1000 clamped to 1280", 1000, 60, 1280},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := computeTunnelMTU(tt.wireMTU, tt.overhead); got != tt.want {
				t.Fatalf("computeTunnelMTU(%d, %d) = %d, want %d", tt.wireMTU, tt.overhead, got, tt.want)
			}
		})
	}
}

func TestDiscoverPathMTU_LiveRouteResolution(t *testing.T) {
	// IPv4 destination (e.g. Cloudflare DNS)
	v4, err := net.ResolveUDPAddr("udp", "1.1.1.1:51820")
	if err == nil {
		mtu := discoverPathMTU(v4)
		if mtu < minTunnelMTU || mtu > 1440 {
			t.Fatalf("discoverPathMTU(1.1.1.1) = %d, want between %d and 1440", mtu, minTunnelMTU)
		}
	}

	// IPv6 destination (e.g. Google DNS)
	v6, err := net.ResolveUDPAddr("udp", "[2001:4860:4860::8888]:51820")
	if err == nil {
		mtu := discoverPathMTU(v6)
		if mtu < minTunnelMTU || mtu > 1420 {
			t.Fatalf("discoverPathMTU(2001:4860:4860::8888) = %d, want between %d and 1420", mtu, minTunnelMTU)
		}
	}
}
