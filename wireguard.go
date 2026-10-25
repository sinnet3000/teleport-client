package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
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
	if v4 != nil {
		tuneUDPSocketBuffers(v4, "udp4")
	}
	if v6 != nil {
		tuneUDPSocketBuffers(v6, "udp6")
	}
	return &udpSockets{V4: v4, V6: v6}, nil
}

const defaultUDPBufferSize = 4 * 1024 * 1024

func tuneUDPSocketBuffers(c *net.UDPConn, network string) {
	if c == nil {
		return
	}
	if err := c.SetReadBuffer(defaultUDPBufferSize); err != nil {
		appLog.Debug("unable to set UDP read buffer size", "network", network, "error", err)
	}
	if err := c.SetWriteBuffer(defaultUDPBufferSize); err != nil {
		appLog.Debug("unable to set UDP write buffer size", "network", network, "error", err)
	}
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
	conn4      *net.UDPConn
	conn6      *net.UDPConn
	stunSecret string
	mu         sync.Mutex
	done       chan struct{}

	stunCount  atomic.Uint64
	recvCount  atomic.Uint64
	nomination *nominationTracker
}

func (b *stunBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
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

func (b *stunBind) handleSTUN(c *net.UDPConn, data []byte, addrPort netip.AddrPort) {
	msg, ok := parseStunMessage(data)
	if !ok {
		return
	}
	if appLog.IsDebug() {
		n := b.stunCount.Add(1)
		appLog.Debug("received STUN packet", "type", msg.Type.String(), "remote", addrPort.String(), "count", n)
	}
	if msg.Type == stun.BindingRequest {
		respondToStunBindingRequestAddrPort(c, msg, addrPort, b.stunSecret, b.nomination)
	}
}

func (b *stunBind) makeRecvFunc(c *net.UDPConn, done chan struct{}) conn.ReceiveFunc {
	var last *conn.StdNetEndpoint
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, addrPort, err := c.ReadFromUDPAddrPort(packets[0])
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
				b.handleSTUN(c, packets[0][:n], addrPort)
				continue
			}
			if appLog.IsDebug() {
				rn := b.recvCount.Add(1)
				appLog.Debug("passing UDP packet to WireGuard", "bytes", n, "remote", addrPort.String(), "count", rn)
			}
			sizes[0] = n
			if last != nil && last.AddrPort == addrPort {
				eps[0] = last
			} else {
				last = &conn.StdNetEndpoint{AddrPort: addrPort}
				eps[0] = last
			}
			return 1, nil
		}
	}
}

func (b *stunBind) Close() error {
	// We do not own the sockets' lifetime (main manages them), but we must
	// unblock any receive goroutine parked in ReadFromUDPAddrPort; otherwise
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
	var udpConn *net.UDPConn
	network := "udp4"
	if se.AddrPort.Addr().Is4() && b.conn4 != nil {
		udpConn = b.conn4
	} else if !se.AddrPort.Addr().Is4() && b.conn6 != nil {
		udpConn, network = b.conn6, "udp6"
	} else {
		return fmt.Errorf("no bound socket for endpoint %s address family", se.AddrPort.String())
	}
	for _, buf := range bufs {
		if _, err := udpConn.WriteToUDPAddrPort(buf, se.AddrPort); err != nil {
			return err
		}
		if appLog.IsDebug() {
			appLog.Debug("sent WireGuard UDP packet", "bytes", len(buf), "remote", se.AddrPort.String(), "network", network)
		}
	}
	return nil
}

func (b *stunBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return (&conn.StdNetBind{}).ParseEndpoint(s)
}

func (b *stunBind) BatchSize() int {
	// stunBind currently performs single-packet reads/writes via *net.UDPConn.
	// Returning 1 prevents wireguard-go from allocating IdealBatchSize (128)
	// element buffer arrays per routine until vectorized recvmmsg/sendmmsg is implemented.
	return 1
}

// wgIPv4OverheadBytes is the encapsulation overhead for WireGuard over outer IPv4:
// 20 bytes (IPv4 header) + 8 bytes (UDP header) + 32 bytes (WireGuard header & Poly1305 MAC) = 60.
const wgIPv4OverheadBytes = 60

// wgIPv6OverheadBytes is the encapsulation overhead for WireGuard over outer IPv6:
// 40 bytes (IPv6 header) + 8 bytes (UDP header) + 32 bytes (WireGuard header & Poly1305 MAC) = 80.
const wgIPv6OverheadBytes = 80

// fallbackMTU is used when path MTU discovery fails outright (dial error,
// no interface listing, no matching interface).
const fallbackMTU = 1420

// minTunnelMTU is the IPv6 minimum MTU (RFC 8200). A discovered tunnel MTU is
// clamped up to this floor rather than discarded, since a genuinely small egress
// MTU (e.g. PPPoE) must still be respected to avoid physical fragmentation.
const minTunnelMTU = 1280

// maxInternetWireMTU is the standard maximum internet MTU without jumbo frames.
// A local interface's jumbo MTU (e.g. 9000 on a cloud VCN or 16384 on Mac lo0/utun)
// cannot safely be used across the public internet without fragmentation/blackholes.
const maxInternetWireMTU = 1500

// minConfiguredMTU is the IPv6 minimum MTU (RFC 8200). A configured tunnel MTU
// cannot be smaller without breaking IPv6 guarantees.
const minConfiguredMTU = 1280

// maxConfiguredMTU is the standard maximum internet MTU without jumbo frames.
const maxConfiguredMTU = 1500

// wireGuardOverhead returns the per-packet encapsulation overhead for endpoint:
// 80 bytes for outer IPv6, 60 bytes for outer IPv4.
func wireGuardOverhead(endpoint *net.UDPAddr) int {
	if endpoint != nil && endpoint.IP != nil && endpoint.IP.To4() == nil {
		return wgIPv6OverheadBytes
	}
	return wgIPv4OverheadBytes
}

// resolveConfiguredMTU returns the user-configured MTU override from the CLI
// flag or TELEPORT_MTU environment variable. If neither is specified, it returns
// 0 indicating automatic path MTU discovery should be used. The CLI flag takes
// precedence over the environment variable.
func resolveConfiguredMTU(cliMTU int, envMTU string) (int, error) {
	if cliMTU != 0 {
		if cliMTU < minConfiguredMTU || cliMTU > maxConfiguredMTU {
			return 0, fmt.Errorf("--mtu must be between %d and %d, got %d", minConfiguredMTU, maxConfiguredMTU, cliMTU)
		}
		return cliMTU, nil
	}

	trimmedEnv := strings.TrimSpace(envMTU)
	if trimmedEnv != "" {
		val, err := strconv.Atoi(trimmedEnv)
		if err != nil {
			return 0, fmt.Errorf("TELEPORT_MTU must be an integer between %d and %d, got %q", minConfiguredMTU, maxConfiguredMTU, trimmedEnv)
		}
		if val < minConfiguredMTU || val > maxConfiguredMTU {
			return 0, fmt.Errorf("TELEPORT_MTU must be between %d and %d, got %d", minConfiguredMTU, maxConfiguredMTU, val)
		}
		return val, nil
	}

	return 0, nil
}

// resolveTCPCongestionControl validates and normalizes the TELEPORT_TCP_CONGESTION_CONTROL
// environment variable. If empty, it returns ("", nil). Supported algorithms are
// "reno" and "cubic" (matching gVisor netstack support).
func resolveTCPCongestionControl(envVal string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(envVal))
	if trimmed == "" {
		return "", nil
	}
	switch trimmed {
	case "reno", "cubic":
		return trimmed, nil
	default:
		return "", fmt.Errorf("unsupported TELEPORT_TCP_CONGESTION_CONTROL %q; supported: reno, cubic", envVal)
	}
}

// parseDarwinRouteMTU parses the route MTU from `route -n get` output on BSD/Darwin.
// The output contains a metrics header line with an `mtu` column followed by values.
func parseDarwinRouteMTU(output string) int {
	lines := strings.Split(output, "\n")
	mtuCol := -1
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if mtuCol == -1 {
			for idx, f := range fields {
				if f == "mtu" {
					mtuCol = idx
					break
				}
			}
			continue
		}
		if len(fields) > mtuCol {
			if val, err := strconv.Atoi(fields[mtuCol]); err == nil && val > 0 {
				return val
			}
		}
		break
	}
	return 0
}

// parseLinuxRouteMTU parses the route MTU from `ip route get` output on Linux.
// When an MTU is set on the route, it contains `mtu <number>` or `mtu lock <number>`.
func parseLinuxRouteMTU(output string) int {
	fields := strings.Fields(output)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "mtu" {
			valIdx := i + 1
			if fields[valIdx] == "lock" && valIdx+1 < len(fields) {
				valIdx++
			}
			if v, err := strconv.Atoi(fields[valIdx]); err == nil && v > 0 {
				return v
			}
		}
	}
	return 0
}

// computeTunnelMTU clamps wireMTU to maxInternetWireMTU, subtracts encapsulation overhead,
// and enforces minTunnelMTU.
func computeTunnelMTU(wireMTU, overhead int) int {
	if wireMTU > maxInternetWireMTU {
		wireMTU = maxInternetWireMTU
	}
	mtu := wireMTU - overhead
	if mtu < minTunnelMTU {
		mtu = minTunnelMTU
	}
	return mtu
}

// queryRouteMTU queries the kernel routing table for a route-specific MTU toward
// target IP (e.g. 1472 bytes set by IPv6 Router Advertisements on macOS).
func queryRouteMTU(ctx context.Context, ip net.IP) int {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return 0
	}

	cmdCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()

	ipStr := ip.String()
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "netbsd":
		familyArg := "-inet"
		if ip.To4() == nil {
			familyArg = "-inet6"
		}
		out, err := exec.CommandContext(cmdCtx, "route", "-n", "get", familyArg, ipStr).Output()
		if err == nil {
			return parseDarwinRouteMTU(string(out))
		}
	case "linux":
		out, err := exec.CommandContext(cmdCtx, "ip", "route", "get", ipStr).Output()
		if err == nil {
			return parseLinuxRouteMTU(string(out))
		}
	}
	return 0
}

// discoverPathMTU determines the optimal tunnel MTU for endpoint. It inspects
// the route-level MTU (e.g. IPv6 Router Advertisement limits) and physical egress
// interface MTU, applies the exact outer family encapsulation overhead (60 bytes
// for IPv4 vs 80 bytes for IPv6), and clamps to [minTunnelMTU, maxInternetWireMTU - overhead].
// Falls back to fallbackMTU only if discovery fails outright.
func discoverPathMTU(endpoint *net.UDPAddr) int {
	if endpoint == nil || endpoint.IP == nil || endpoint.IP.IsUnspecified() || endpoint.Port <= 0 || endpoint.Port > 65535 {
		appLog.Debug("path MTU discovery: invalid endpoint, using fallback", "endpoint", endpoint, "mtu", fallbackMTU)
		return fallbackMTU
	}

	overhead := wireGuardOverhead(endpoint)

	udpConn, err := net.DialUDP("udp", nil, endpoint)
	if err != nil {
		appLog.Debug("path MTU discovery: dial failed, using fallback", "endpoint", endpoint.String(), "error", err, "mtu", fallbackMTU)
		return fallbackMTU
	}
	defer udpConn.Close()

	localIP := udpConn.LocalAddr().(*net.UDPAddr).IP

	routeMTU := queryRouteMTU(context.Background(), endpoint.IP)
	if routeMTU > 0 {
		appLog.Debug("path MTU discovery: route MTU queried", "endpoint", endpoint.IP.String(), "route_mtu", routeMTU)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		if routeMTU > 0 {
			return computeTunnelMTU(routeMTU, overhead)
		}
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

			wireMTU := iface.MTU
			if routeMTU > 0 && routeMTU < wireMTU {
				wireMTU = routeMTU
			}
			mtu := computeTunnelMTU(wireMTU, overhead)
			appLog.Debug("path MTU discovery: resolved",
				"interface", iface.Name,
				"interface_mtu", iface.MTU,
				"route_mtu", routeMTU,
				"wire_mtu", wireMTU,
				"overhead", overhead,
				"tunnel_mtu", mtu,
			)
			return mtu
		}
	}

	if routeMTU > 0 {
		mtu := computeTunnelMTU(routeMTU, overhead)
		appLog.Debug("path MTU discovery: resolved via route MTU", "route_mtu", routeMTU, "tunnel_mtu", mtu)
		return mtu
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

func buildConfig(priv string, port int, endpoint string, info serverInfo, dns []string, clientIP string, mtu int) string {
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
	var ifaceLines []string
	ifaceLines = append(ifaceLines,
		"PrivateKey = "+priv,
		fmt.Sprintf("ListenPort = %d", port),
		"Address = "+address,
		"DNS = "+dnsAddr,
	)
	if mtu > 0 {
		ifaceLines = append(ifaceLines, fmt.Sprintf("MTU = %d", mtu))
	}
	return fmt.Sprintf(`[Interface]
%s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, strings.Join(ifaceLines, "\n"), info.WGPubKey, endpoint)
}
