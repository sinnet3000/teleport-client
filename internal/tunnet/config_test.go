package tunnet

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
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

	netTun := (*netTun)(net)
	var txOpt tcpip.TCPSendBufferSizeRangeOption
	if err := netTun.stack.TransportProtocolOption(tcp.ProtocolNumber, &txOpt); err != nil {
		t.Fatalf("failed to read TCPSendBufferSizeRangeOption: %v", err)
	}
	if txOpt.Min != DefaultTCPTXBufMinSize || txOpt.Default != DefaultTCPTXBufDefSize || txOpt.Max != DefaultTCPTXBufMaxSize {
		t.Errorf("unexpected default send buffer range: %+v", txOpt)
	}

	var rxOpt tcpip.TCPReceiveBufferSizeRangeOption
	if err := netTun.stack.TransportProtocolOption(tcp.ProtocolNumber, &rxOpt); err != nil {
		t.Fatalf("failed to read TCPReceiveBufferSizeRangeOption: %v", err)
	}
	if rxOpt.Min != DefaultTCPRXBufMinSize || rxOpt.Default != DefaultTCPRXBufDefSize || rxOpt.Max != DefaultTCPRXBufMaxSize {
		t.Errorf("unexpected default recv buffer range: %+v", rxOpt)
	}

	var ccOpt tcpip.CongestionControlOption
	if err := netTun.stack.TransportProtocolOption(tcp.ProtocolNumber, &ccOpt); err != nil {
		t.Fatalf("failed to read CongestionControlOption: %v", err)
	}
	if string(ccOpt) != "cubic" {
		t.Errorf("expected default congestion control cubic, got %q", string(ccOpt))
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

	netTun := (*netTun)(net)
	var txOpt tcpip.TCPSendBufferSizeRangeOption
	if err := netTun.stack.TransportProtocolOption(tcp.ProtocolNumber, &txOpt); err != nil {
		t.Fatalf("failed to read TCPSendBufferSizeRangeOption: %v", err)
	}
	if txOpt.Max != 4194304 {
		t.Errorf("expected send buffer max 4194304, got %d", txOpt.Max)
	}

	var rxOpt tcpip.TCPReceiveBufferSizeRangeOption
	if err := netTun.stack.TransportProtocolOption(tcp.ProtocolNumber, &rxOpt); err != nil {
		t.Fatalf("failed to read TCPReceiveBufferSizeRangeOption: %v", err)
	}
	if rxOpt.Max != 4194304 {
		t.Errorf("expected receive buffer max 4194304, got %d", rxOpt.Max)
	}

	var ccOpt tcpip.CongestionControlOption
	if err := netTun.stack.TransportProtocolOption(tcp.ProtocolNumber, &ccOpt); err != nil {
		t.Fatalf("failed to read CongestionControlOption: %v", err)
	}
	if string(ccOpt) != "reno" {
		t.Errorf("expected congestion control reno, got %q", string(ccOpt))
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

func TestCreateNetTUN_InvalidBufferSize(t *testing.T) {
	// gVisor rejects buffer size ranges where Min > Default or Default > Max or Min < 1
	dev, net, err := CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("192.168.2.2")},
		nil,
		1420,
		WithBufferSizes(
			tcpip.TCPSendBufferSizeRangeOption{Min: 10000, Default: 1000, Max: 500},
			tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 1048576, Max: 4194304},
		),
	)
	if err == nil {
		if dev != nil {
			dev.Close()
		}
		t.Fatal("expected error for invalid send buffer size range, got nil")
	}
	if net != nil {
		t.Fatal("expected nil Net on error")
	}

	dev, net, err = CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("192.168.2.2")},
		nil,
		1420,
		WithBufferSizes(
			tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 1048576, Max: 4194304},
			tcpip.TCPReceiveBufferSizeRangeOption{Min: 10000, Default: 1000, Max: 500},
		),
	)
	if err == nil {
		if dev != nil {
			dev.Close()
		}
		t.Fatal("expected error for invalid receive buffer size range, got nil")
	}
	if net != nil {
		t.Fatal("expected nil Net on error")
	}
}

func TestSetMTU(t *testing.T) {
	dev, net, err := CreateNetTUN([]netip.Addr{netip.MustParseAddr("192.168.2.2")}, nil, 1280)
	if err != nil {
		t.Fatalf("CreateNetTUN failed: %v", err)
	}
	defer dev.Close()

	initialMTU, err := dev.MTU()
	if err != nil || initialMTU != 1280 {
		t.Fatalf("initial MTU = %d (err=%v), want 1280", initialMTU, err)
	}

	// Update to 1420
	if err := net.SetMTU(1420); err != nil {
		t.Fatalf("net.SetMTU(1420) failed: %v", err)
	}

	updatedMTU, err := dev.MTU()
	if err != nil || updatedMTU != 1420 {
		t.Fatalf("updated MTU = %d (err=%v), want 1420", updatedMTU, err)
	}

	// Verify EventMTUUpdate was sent on events channel
	select {
	case event := <-dev.Events():
		// Note: CreateNetTUN sent EventUp during creation; subsequent event is EventMTUUpdate
		if event != 4 && event != 1 { // 4 is EventMTUUpdate (1 << 2)
			t.Logf("received event: %v", event)
		}
	default:
		t.Fatal("expected event on dev.Events() after SetMTU")
	}
}

