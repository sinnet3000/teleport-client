package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/stun"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
)

// wgKeypair generates a WireGuard Curve25519 keypair natively, without
// shelling out to the external `wg` CLI, so the client has no runtime
// dependency on wireguard-tools being installed.
func wgKeypair() (string, string, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv[:]), base64.StdEncoding.EncodeToString(pub), nil
}

// udpSockets are opened for candidate discovery and nomination, then handed
// to wireguard-go through stunBind so STUN and WireGuard retain the same NAT
// mappings and UDP tuples.
type udpSockets struct {
	V4 *net.UDPConn
	V6 *net.UDPConn
}

func openUDPSockets(port int, family networkFamily) (*udpSockets, error) {
	var v4, v6 *net.UDPConn
	var err error
	if family != familyIPv6 {
		v4, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
		if err != nil {
			if family == familyIPv4 {
				return nil, err
			}
			appLog.Warn("IPv4 UDP listen failed", "error", err)
		}
	}
	if family != familyIPv4 {
		v6, err = net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6zero, Port: port})
		if err != nil {
			if family == familyIPv6 {
				if v4 != nil {
					_ = v4.Close()
				}
				return nil, err
			}
			appLog.Warn("IPv6 UDP listen failed", "error", err)
		}
	}
	if v4 == nil && v6 == nil {
		return nil, errors.New("no UDP socket available")
	}
	return &udpSockets{V4: v4, V6: v6}, nil
}

func (s *udpSockets) Close() {
	if s == nil {
		return
	}
	if s.V4 != nil {
		_ = s.V4.Close()
	}
	if s.V6 != nil {
		_ = s.V6.Close()
	}
}

// stunBind wraps an existing STUN UDP socket as a conn.Bind for wireguard-go.
// It handles STUN Binding Requests inline and passes only WireGuard packets to
// wireguard-go.
type stunBind struct {
	conn4          *net.UDPConn
	conn6          *net.UDPConn
	port           uint16
	stunSecretHash string
	mu             sync.Mutex
	done           chan struct{}

	stunCount  atomic.Uint64
	recvCount  atomic.Uint64
	nomination *nominationTracker
}

func (b *stunBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.port = port
	// Fresh lifecycle for this Open; also clear any read deadline a prior
	// Close set so the receive loops can read again after a rebind.
	b.mu.Lock()
	b.done = make(chan struct{})
	done := b.done
	b.mu.Unlock()
	var fns []conn.ReceiveFunc
	if b.conn4 != nil {
		_ = b.conn4.SetReadDeadline(time.Time{})
		fns = append(fns, b.makeRecvFunc(b.conn4, done))
	}
	if b.conn6 != nil {
		_ = b.conn6.SetReadDeadline(time.Time{})
		fns = append(fns, b.makeRecvFunc(b.conn6, done))
	}
	appLog.Debug("WireGuard UDP bind opened", "port", port, "receive_loops", len(fns))
	return fns, port, nil
}

func (b *stunBind) handleSTUN(c *net.UDPConn, data []byte, addr *net.UDPAddr) {
	msg, ok := parseStunMessage(data)
	if !ok {
		return
	}
	if appLog.IsDebug() {
		n := b.stunCount.Add(1)
		appLog.Debug("received STUN packet", "type", msg.Type.String(), "remote", addr.String(), "count", n)
	}
	if msg.Type == stun.BindingRequest {
		respondToStunBindingRequest(c, msg, addr, b.stunSecretHash, b.nomination)
	}
}

func (b *stunBind) makeRecvFunc(c *net.UDPConn, done chan struct{}) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, addr, err := c.ReadFromUDP(packets[0])
			if err != nil {
				// If Close() woke us (deadline/socket close), report ErrClosed so
				// wireguard-go's receive routine exits and closeBindLocked's
				// stopping.Wait() can return instead of deadlocking.
				select {
				case <-done:
					return 0, net.ErrClosed
				default:
				}
				return 0, err
			}
			if isSTUN(packets[0][:n]) {
				b.handleSTUN(c, packets[0][:n], addr)
				continue
			}
			if appLog.IsDebug() {
				rn := b.recvCount.Add(1)
				appLog.Debug("passing UDP packet to WireGuard", "bytes", n, "remote", addr.String(), "count", rn)
			}
			sizes[0] = n
			eps[0] = &conn.StdNetEndpoint{AddrPort: addr.AddrPort()}
			return 1, nil
		}
	}
}

func (b *stunBind) Close() error {
	// We do not own the sockets' lifetime (main manages them), but we must
	// unblock any receive goroutine parked in ReadFromUDP; otherwise
	// closeBindLocked -> stopping.Wait() can deadlock during BindUpdate/Down/Close.
	b.mu.Lock()
	if b.done != nil {
		select {
		case <-b.done:
		default:
			close(b.done)
		}
	}
	b.mu.Unlock()
	now := time.Now()
	if b.conn4 != nil {
		_ = b.conn4.SetReadDeadline(now)
	}
	if b.conn6 != nil {
		_ = b.conn6.SetReadDeadline(now)
	}
	appLog.Debug("WireGuard UDP bind closed")
	return nil
}

func (b *stunBind) SetMark(uint32) error { return nil }

func (b *stunBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	se, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	addr := &net.UDPAddr{IP: se.AddrPort.Addr().AsSlice(), Port: int(se.AddrPort.Port())}
	var udpConn *net.UDPConn
	network := "udp4"
	if se.AddrPort.Addr().Is4() && b.conn4 != nil {
		udpConn = b.conn4
	} else if !se.AddrPort.Addr().Is4() && b.conn6 != nil {
		udpConn, network = b.conn6, "udp6"
	} else {
		return fmt.Errorf("no bound socket for endpoint %s address family", addr.String())
	}
	for _, buf := range bufs {
		if _, err := udpConn.WriteToUDP(buf, addr); err != nil {
			return err
		}
		if appLog.IsDebug() {
			appLog.Debug("sent WireGuard UDP packet", "bytes", len(buf), "remote", addr.String(), "network", network)
		}
	}
	return nil
}

func (b *stunBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return (&conn.StdNetBind{}).ParseEndpoint(s)
}

func (b *stunBind) BatchSize() int {
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		return conn.IdealBatchSize
	}
	return 1
}

// wgOverheadBytes is the flat per-packet overhead WireGuard adds (message
// type, key index, counter, Poly1305 tag), matching the constant wg-quick's
// auto_mtu subtracts regardless of the outer IP version.
const wgOverheadBytes = 80

// fallbackMTU is used when path MTU discovery fails outright (dial error,
// no interface listing, no matching interface).
const fallbackMTU = 1420

// minTunnelMTU is the IPv6 minimum MTU. A discovered tunnel MTU is clamped
// up to this floor rather than discarded, since a genuinely small egress
// MTU (e.g. PPPoE) must still be respected to avoid physical fragmentation.
const minTunnelMTU = 1280

// discoverPathMTU mirrors wg-quick's auto_mtu: it finds the MTU of the local
// interface the OS would use to reach endpoint, then subtracts WireGuard's
// per-packet overhead. Unlike wg-quick it doesn't shell out to `ip route
// get` / `route get`; instead it "connects" a UDP socket to the endpoint
// (no packets are sent) and reads back the OS-selected local address, then
// matches that address against net.Interfaces() to find the egress
// interface's MTU, clamped up to minTunnelMTU if the computed value is
// smaller. Falls back to fallbackMTU only if discovery fails outright.
func discoverPathMTU(endpoint *net.UDPAddr) int {
	if endpoint == nil || endpoint.IP == nil || endpoint.IP.IsUnspecified() || endpoint.Port <= 0 || endpoint.Port > 65535 {
		appLog.Debug("path MTU discovery: invalid endpoint, using fallback", "endpoint", endpoint, "mtu", fallbackMTU)
		return fallbackMTU
	}

	conn, err := net.DialUDP("udp", nil, endpoint)
	if err != nil {
		appLog.Debug("path MTU discovery: dial failed, using fallback", "endpoint", endpoint.String(), "error", err, "mtu", fallbackMTU)
		return fallbackMTU
	}
	defer conn.Close()

	localIP := conn.LocalAddr().(*net.UDPAddr).IP

	ifaces, err := net.Interfaces()
	if err != nil {
		appLog.Debug("path MTU discovery: listing interfaces failed, using fallback", "error", err, "mtu", fallbackMTU)
		return fallbackMTU
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				// Point-to-point interfaces (common for VPNs/tunnels) report
				// addresses without a subnet mask.
				ip = v.IP
			default:
				continue
			}
			if !ip.Equal(localIP) {
				continue
			}
			mtu := iface.MTU - wgOverheadBytes
			if mtu < minTunnelMTU {
				mtu = minTunnelMTU
			}
			appLog.Debug("path MTU discovery: resolved", "interface", iface.Name, "interface_mtu", iface.MTU, "tunnel_mtu", mtu)
			return mtu
		}
	}
	appLog.Debug("path MTU discovery: no matching interface found, using fallback", "local_ip", localIP.String(), "mtu", fallbackMTU)
	return fallbackMTU
}

func b64KeyToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", err
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(decoded))
	}
	return hex.EncodeToString(decoded), nil
}

func buildConfig(priv string, port int, endpoint string, info serverInfo, dns []string, clientIP string) string {
	dnsAddr := "192.168.88.1"
	if len(dns) > 0 {
		dnsAddr = dns[0]
	}
	mask := info.TunnelMask
	if mask == 0 {
		mask = 120
	}
	address := fmt.Sprintf("%s/%d", info.TunnelAddr, mask)
	if clientIP != "" {
		clientMask := "32"
		if strings.Contains(clientIP, ":") {
			clientMask = "128"
		}
		address = clientIP + "/" + clientMask + ", " + address
	}
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
ListenPort = %d
Address = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, priv, port, address, dnsAddr, info.WGPubKey, endpoint)
}
