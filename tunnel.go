package main

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// tunnelParams collects everything runTunnel needs to bring the WireGuard
// device up over the endpoint negotiateEndpoint selected.
type tunnelParams struct {
	priv           string
	port           int
	endpoint       string
	connResp       *apiResponse
	stunSecret     string
	stunSecretHash string
	sockets        *udpSockets
	nomination     *nominationTracker
	socks5Addr     string
	debug          bool
	candidateQueue []string
}

// runTunnel brings up the WireGuard device over the negotiated endpoint,
// starts the SOCKS5 proxy and UDP echo pinger, and — if more than one
// candidate sent us a Binding Request — retries the next queued candidate on
// a handshake timeout. It blocks forever once the device is up; it only
// returns (via fatal) on setup failure.
func runTunnel(p tunnelParams, fatal func(error)) {
	privHex, err := b64KeyToHex(p.priv)
	fatal(err)
	peerPubHex, err := b64KeyToHex(p.connResp.ServerInfo.WGPubKey)
	fatal(err)

	endpointAddr, err := net.ResolveUDPAddr("udp", p.endpoint)
	fatal(err)
	epStr := endpointAddr.String()

	var deviceAddrs []netip.Addr
	if p.connResp.ServerInfo.TunnelAddr != "" {
		a, err := netip.ParseAddr(p.connResp.ServerInfo.TunnelAddr)
		if err == nil {
			deviceAddrs = append(deviceAddrs, a)
		}
	}
	if p.connResp.ClientIP != "" {
		a, err := netip.ParseAddr(p.connResp.ClientIP)
		if err == nil {
			deviceAddrs = append(deviceAddrs, a)
		}
	}
	var dnsAddrs []netip.Addr
	for _, d := range p.connResp.DNSAddrs {
		a, err := netip.ParseAddr(d)
		if err == nil {
			dnsAddrs = append(dnsAddrs, a)
		}
	}

	mtu := discoverPathMTU(endpointAddr)
	appLog.Info("path MTU discovered", "endpoint", endpointAddr.String(), "mtu", mtu)
	tun, tunnelNet, err := netstack.CreateNetTUN(deviceAddrs, dnsAddrs, mtu)
	fatal(err)

	bind := &stunBind{conn4: p.sockets.V4, conn6: p.sockets.V6, stunSecretHash: p.stunSecretHash, nomination: p.nomination}
	dev := device.NewDevice(tun, bind, newWireGuardLogger(appLog, p.debug))

	mask := p.connResp.ServerInfo.TunnelMask
	if mask == 0 {
		mask = 120
	}
	ipc := fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		privHex, p.port, peerPubHex, epStr)
	if err := dev.IpcSet(ipc); err != nil {
		fatal(err)
	}
	if err := dev.Up(); err != nil {
		fatal(err)
	}
	appLog.Debug("WireGuard device started", "endpoint", p.endpoint)
	go runUDPEchoPinger(tunnelNet, p.stunSecret, p.connResp.ServerInfo)
	fatal(startSocks5Proxy(p.socks5Addr, tunnelNet))

	if len(p.candidateQueue) > 0 {
		go retryEndpointOnHandshakeTimeout(dev, peerPubHex, p.endpoint, p.candidateQueue)
	}

	select {}
}

// retryEndpointOnHandshakeTimeout switches the WireGuard peer to the next
// queued candidate if the current endpoint hasn't completed a handshake
// within 15s, giving up after 90s total or once the queue is exhausted.
func retryEndpointOnHandshakeTimeout(dev *device.Device, peerPubHex, currentEndpoint string, candidateQueue []string) {
	queueIdx := 0
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	devUpTime := time.Now()
	lastSwitchTime := devUpTime

	for range ticker.C {
		if time.Since(devUpTime) >= 90*time.Second {
			appLog.Warn("endpoint retry stopped", "reason", "90s timeout reached")
			return
		}

		ipcData, err := dev.IpcGet()
		if err != nil {
			continue
		}

		handshakeOK := false
		lines := strings.Split(ipcData, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "last_handshake_time_sec=") {
				val := strings.TrimPrefix(line, "last_handshake_time_sec=")
				if val != "0" && val != "" {
					handshakeOK = true
				}
			}
		}

		if handshakeOK {
			return
		}

		if time.Since(lastSwitchTime) >= 15*time.Second {
			nextCandidateAddr, nextIdx, ok := nextEndpointCandidate(candidateQueue, queueIdx, currentEndpoint)
			queueIdx = nextIdx
			if ok {
				ipc := fmt.Sprintf("public_key=%s\nendpoint=%s\n", peerPubHex, nextCandidateAddr)
				if err := dev.IpcSet(ipc); err == nil {
					appLog.Warn("switching endpoint after handshake timeout", "endpoint", nextCandidateAddr)
					currentEndpoint = nextCandidateAddr
					lastSwitchTime = time.Now()
				}
			} else {
				appLog.Warn("endpoint retry stopped", "reason", "candidate queue exhausted")
				return
			}
		}
	}
}

func nextEndpointCandidate(queue []string, start int, current string) (candidate string, next int, ok bool) {
	for start < len(queue) {
		candidate = queue[start]
		start++
		if candidate == "" || candidate == current {
			continue
		}
		return candidate, start, true
	}
	return "", start, false
}
