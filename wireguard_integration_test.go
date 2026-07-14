//go:build integration

package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// genKey returns a deterministic curve25519 WireGuard keypair for a test seed.
func genKey(t *testing.T, seed byte) (string, string) {
	t.Helper()
	var priv [32]byte
	for i := range priv {
		priv[i] = byte(i+1) ^ seed
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(priv[:]), hex.EncodeToString(pub)
}

// TestIpcSetReachesPeer exercises the production device, bind, and IPC path
// offline against wireguard-go and real UDP sockets.
func TestIpcSetReachesPeer(t *testing.T) {
	// Fake "console" UDP peer on loopback so Send has a destination we can watch.
	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	peerPort := peerConn.LocalAddr().(*net.UDPAddr).Port
	endpoint := fmt.Sprintf("127.0.0.1:%d", peerPort)

	// Use one UDP socket for both STUN and WireGuard, as production does.
	ourConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ourConn.Close()
	ourPort := ourConn.LocalAddr().(*net.UDPAddr).Port

	// Create the userspace TUN used by production.
	deviceAddrs := []netip.Addr{netip.MustParseAddr("10.0.0.2")}
	dnsAddrs := []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	tun, _, err := netstack.CreateNetTUN(deviceAddrs, dnsAddrs, 1420)
	if err != nil {
		t.Fatal(err)
	}

	bind := &stunBind{conn4: ourConn, conn6: nil, stunSecretHash: "deadbeef"}
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelVerbose, "wg-test"))

	privHex, _ := genKey(t, 0x00)
	_, peerPubHex := genKey(t, 0xAB)

	// Configure one peer through wireguard-go's IPC interface.
	ipc := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		privHex, ourPort, peerPubHex, endpoint)

	if err := dev.IpcSet(ipc); err != nil {
		t.Fatalf("IpcSet FAILED: %v", err)
	}
	t.Log("IpcSet succeeded (no error)")

	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if !strings.Contains(got, "public_key="+peerPubHex) {
		t.Fatalf("PEER NOT CREATED. IpcGet:\n%s", got)
	}
	t.Log("PEER CREATED: public_key present in IpcGet output")
	if strings.Contains(got, "endpoint="+endpoint) {
		t.Log("endpoint applied to peer:", endpoint)
	} else {
		t.Logf("WARNING: endpoint not found in peer config:\n%s", got)
	}

	if err := dev.Up(); err != nil {
		t.Fatalf("device.Up FAILED: %v", err)
	}
	t.Log("device.Up() succeeded")

	// Watch the fake peer socket for an incoming WireGuard handshake initiation
	// (type 1, 148 bytes) sent from our STUN port.
	peerConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, from, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("NO PACKET received by peer within timeout (handshake not sent): %v", err)
	}
	t.Logf("peer received %d bytes from %s (our STUN port=%d), first byte=0x%02x",
		n, from.String(), ourPort, buf[0])
	if from.Port != ourPort {
		t.Errorf("packet came from port %d, expected STUN port %d", from.Port, ourPort)
	}
	if n != 148 || buf[0] != 0x01 {
		t.Fatalf("received a packet, but not a 148-byte type-1 handshake initiation (n=%d type=0x%02x)", n, buf[0])
	}
	t.Log("got a WireGuard handshake initiation from the STUN port")

	// Regression guard: dev.Close() -> closeBindLocked -> stopping.Wait() must
	// return now that stunBind.Close() unblocks the receive goroutine. Before
	// the fix this hung until the test timeout.
	closed := make(chan struct{})
	go func() { dev.Close(); close(closed) }()
	select {
	case <-closed:
		t.Log("dev.Close() returned cleanly (no stopping.Wait() deadlock)")
	case <-time.After(5 * time.Second):
		t.Fatal("dev.Close() DEADLOCKED — stunBind.Close() did not unblock the receive routine")
	}
	ourConn.Close()
}

// TestOwnKeyRoundTrip verifies that wgKeypair's public key matches the key
// independently derived from its private key.
func TestOwnKeyRoundTrip(t *testing.T) {
	priv, pub, err := wgKeypair()
	if err != nil {
		t.Fatalf("wgKeypair failed: %v", err)
	}
	wantPubHex, err := b64KeyToHex(pub)
	if err != nil {
		t.Fatalf("b64KeyToHex(pub) failed: %v", err)
	}

	privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(priv))
	if err != nil {
		t.Fatalf("base64.StdEncoding.DecodeString(priv): %v", err)
	}
	derivedPub, err := curve25519.X25519(privBytes, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519.X25519: %v", err)
	}
	derivedPubHex := hex.EncodeToString(derivedPub)

	if derivedPubHex != wantPubHex {
		t.Fatalf("KEY MISMATCH: curve25519.X25519(priv, basepoint)=%s, but wgKeypair (what we send the server as pub=%s) gives hex=%s -- these must match or every handshake will be silently dropped",
			derivedPubHex, pub, wantPubHex)
	}
	t.Logf("MATCH: curve25519-derived public key (%s) == what wgKeypair gave us and what we send the server (%s)", derivedPubHex, wantPubHex)
}
