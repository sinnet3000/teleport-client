package tunnet

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestCreateNetTUN_DefaultOptions(t *testing.T) {
	dev, net, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("192.168.2.2")}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN failed: %v", err)
	}
	defer dev.Close()

	if net == nil {
		t.Fatal("expected non-nil Net")
	}
}

func TestCreateNetTUN_CustomOptions(t *testing.T) {
	dev, net, err := CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("192.168.2.2")},
		nil,
		1420,
		WithCongestionControl("reno"),
		WithBufferSizes(
			tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 1048576, Max: 4194304},
			tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 1048576, Max: 4194304},
		),
	)
	if err != nil {
		t.Fatalf("CreateNetTUN with custom options failed: %v", err)
	}
	defer dev.Close()

	if net == nil {
		t.Fatal("expected non-nil Net")
	}
}

func TestCreateNetTUN_InvalidCongestionControl(t *testing.T) {
	dev, net, err := CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("192.168.2.2")},
		nil,
		1420,
		WithCongestionControl("nonexistent_cc"),
	)
	if err == nil {
		if dev != nil {
			dev.Close()
		}
		t.Fatal("expected error for unsupported congestion control algorithm, got nil")
	}
	if net != nil {
		t.Fatal("expected nil Net on error")
	}
}
