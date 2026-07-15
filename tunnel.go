package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
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

const (
	wireGuardRecentHandshakeWindow = 3 * time.Minute
	endpointRecoveryInterval       = 15 * time.Second
	endpointRecoveryMaxBackoff     = 30 * time.Second
	endpointRecoveryRounds         = 2
)

var errTunnelRenegotiationRequired = errors.New("known WireGuard endpoints exhausted; fresh Teleport negotiation required")

type wireGuardPeerStats struct {
	endpoint      string
	lastHandshake time.Time
	rxBytes       uint64
	valid         bool
}

// runTunnel brings up the WireGuard device over the negotiated endpoint,
// starts the SOCKS5 proxy and UDP echo pinger, and retries queued observed or
// advertised candidates on a handshake timeout. It blocks while supervising
// the tunnel and automatically cycles known endpoints after correlated health
// loss; only non-recoverable local errors return through fatal.
func runTunnel(p tunnelParams, fatal func(error)) error {
	lifecycleCtx, stopLifecycle := context.WithCancel(context.Background())
	defer stopLifecycle()

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
	defer dev.Close()

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
	renegotiate := make(chan struct{}, 1)
	if len(p.candidateQueue) > 0 || p.nomination != nil {
		go retryEndpointOnHandshakeTimeout(lifecycleCtx, dev, peerPubHex, p.endpoint, p.candidateQueue, p.nomination, p.sockets, p.stunSecretHash, renegotiate)
	}
	echoStopped := make(chan error, 1)
	healthEvents := make(chan udpEchoHealthEvent)
	go func() {
		if err := runUDPEchoPinger(lifecycleCtx, tunnelNet, p.stunSecret, p.connResp.ServerInfo, healthEvents); err != nil {
			echoStopped <- err
		}
	}()
	proxy, err := startSocks5Proxy(p.socks5Addr, tunnelNet)
	if err != nil {
		return err
	}
	defer proxy.Close()

	knownEndpoints := append([]string{p.endpoint}, p.candidateQueue...)
	baseline := readWireGuardPeerStats(dev)
	var recoveryCancel context.CancelFunc
	defer func() {
		if recoveryCancel != nil {
			recoveryCancel()
		}
	}()
	for {
		select {
		case err := <-echoStopped:
			if recoveryCancel != nil {
				recoveryCancel()
			}
			return err
		case <-renegotiate:
			if recoveryCancel != nil {
				recoveryCancel()
			}
			return errTunnelRenegotiationRequired
		case event := <-healthEvents:
			current := readWireGuardPeerStats(dev)
			switch event {
			case udpEchoHealthy:
				baseline = current
				if recoveryCancel != nil {
					recoveryCancel()
					recoveryCancel = nil
					appLog.Info("WireGuard tunnel reestablished")
				}
			case udpEchoStartupFailed:
				appLog.Warn("WireGuard startup endpoints exhausted; requesting fresh Teleport negotiation")
				return errTunnelRenegotiationRequired
			case udpEchoUnhealthy:
				if wireGuardPathActiveSince(baseline, current, time.Now()) {
					appLog.Warn("UDP echo health probe unavailable while WireGuard remains active; keeping tunnel up")
					baseline = current
					continue
				}
				if recoveryCancel == nil {
					appLog.Warn("WireGuard tunnel unhealthy; starting automatic endpoint recovery")
					recoveryCancel = startWireGuardEndpointRecovery(lifecycleCtx, dev, peerPubHex, current.endpoint, knownEndpoints, p.sockets, p.stunSecretHash, renegotiate)
				}
			}
		}
	}
}

func startWireGuardEndpointRecovery(parent context.Context, dev *device.Device, peerPubHex, currentEndpoint string, knownEndpoints []string, sockets *udpSockets, stunSecretHash string, exhausted chan<- struct{}) context.CancelFunc {
	recoveryCtx, cancel := context.WithCancel(parent)
	go recoverWireGuardEndpoints(recoveryCtx, dev, peerPubHex, currentEndpoint, knownEndpoints, sockets, stunSecretHash, exhausted)
	return cancel
}

func readWireGuardPeerStats(dev *device.Device) wireGuardPeerStats {
	if dev == nil {
		return wireGuardPeerStats{}
	}
	ipcData, err := dev.IpcGet()
	if err != nil {
		return wireGuardPeerStats{}
	}
	return parseWireGuardPeerStats(ipcData)
}

func parseWireGuardPeerStats(ipcData string) wireGuardPeerStats {
	stats := wireGuardPeerStats{}
	for _, line := range strings.Split(ipcData, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "endpoint":
			stats.endpoint = value
		case "last_handshake_time_sec":
			seconds, err := strconv.ParseInt(value, 10, 64)
			if err == nil && seconds > 0 {
				stats.lastHandshake = time.Unix(seconds, 0)
			}
		case "rx_bytes":
			bytes, err := strconv.ParseUint(value, 10, 64)
			if err == nil {
				stats.rxBytes = bytes
			}
		}
	}
	stats.valid = stats.endpoint != "" || !stats.lastHandshake.IsZero() || stats.rxBytes != 0
	return stats
}

func wireGuardPathActiveSince(baseline, current wireGuardPeerStats, now time.Time) bool {
	if !current.valid {
		return false
	}
	if baseline.valid {
		return current.rxBytes > baseline.rxBytes || current.lastHandshake.After(baseline.lastHandshake)
	}
	return !current.lastHandshake.IsZero() && now.Sub(current.lastHandshake) <= wireGuardRecentHandshakeWindow
}

func recoverWireGuardEndpoints(ctx context.Context, dev *device.Device, peerPubHex, currentEndpoint string, knownEndpoints []string, sockets *udpSockets, stunSecretHash string, exhausted chan<- struct{}) {
	backoff := 5 * time.Second
	for round := 1; round <= endpointRecoveryRounds; round++ {
		endpoints := buildEndpointRecoveryOrder(currentEndpoint, knownEndpoints)
		for _, endpoint := range endpoints {
			select {
			case <-ctx.Done():
				return
			default:
			}
			sendPeerCandidateProbe(sockets, endpoint, stunSecretHash)
			ipc := fmt.Sprintf("public_key=%s\nendpoint=%s\n", peerPubHex, endpoint)
			if err := dev.IpcSet(ipc); err != nil {
				appLog.Warn("automatic endpoint recovery update failed", "endpoint", endpoint, "error", err)
			} else {
				appLog.Warn("automatic endpoint recovery trying candidate", "endpoint", endpoint, "round", round)
				currentEndpoint = endpoint
			}
			if !waitForRecovery(ctx, endpointRecoveryInterval) {
				return
			}
		}
		appLog.Warn("automatic endpoint recovery exhausted candidates; retrying", "backoff", backoff.Round(time.Second))
		if !waitForRecovery(ctx, backoff) {
			return
		}
		backoff *= 2
		if backoff > endpointRecoveryMaxBackoff {
			backoff = endpointRecoveryMaxBackoff
		}
	}
	select {
	case exhausted <- struct{}{}:
	case <-ctx.Done():
	}
}

func buildEndpointRecoveryOrder(current string, known []string) []string {
	seen := make(map[string]bool, len(known)+1)
	order := make([]string, 0, len(known)+1)
	appendEndpoint := func(endpoint string) {
		if endpoint == "" || seen[endpoint] {
			return
		}
		seen[endpoint] = true
		order = append(order, endpoint)
	}
	appendEndpoint(current)
	for _, endpoint := range known {
		appendEndpoint(endpoint)
	}
	return order
}

func waitForRecovery(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// retryEndpointOnHandshakeTimeout switches the WireGuard peer to the next
// queued candidate if the current endpoint hasn't completed a handshake
// within 15s, giving up after 90s total or once the queue is exhausted.
func retryEndpointOnHandshakeTimeout(ctx context.Context, dev *device.Device, peerPubHex, currentEndpoint string, candidateQueue []string, nomination *nominationTracker, sockets *udpSockets, stunSecretHash string, exhausted chan<- struct{}) {
	queueIdx := 0
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	var nominationSelected <-chan struct{}
	if nomination != nil {
		nominationSelected = nomination.selectedCh
	}

	devUpTime := time.Now()
	lastSwitchTime := devUpTime

	for {
		select {
		case <-ctx.Done():
			return
		case <-nominationSelected:
			nominationSelected = nil
			selected := nomination.selectedEndpoint()
			if selected == "" || selected == currentEndpoint {
				continue
			}
			sendPeerCandidateProbe(sockets, selected, stunSecretHash)
			ipc := fmt.Sprintf("public_key=%s\nendpoint=%s\n", peerPubHex, selected)
			if err := dev.IpcSet(ipc); err == nil {
				appLog.Warn("switching endpoint to late verified nomination", "endpoint", selected)
				currentEndpoint = selected
				lastSwitchTime = time.Now()
			}
		case <-ticker.C:
		}
		ipcData, err := dev.IpcGet()
		if err != nil {
			if time.Since(devUpTime) >= 90*time.Second {
				appLog.Warn("endpoint retry stopped", "reason", "90s timeout reached; WireGuard stats unavailable")
				signalEndpointExhaustion(ctx, exhausted)
				return
			}
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
		if time.Since(devUpTime) >= 90*time.Second {
			appLog.Warn("endpoint retry stopped", "reason", "90s timeout reached")
			signalEndpointExhaustion(ctx, exhausted)
			return
		}

		if time.Since(lastSwitchTime) >= 15*time.Second {
			nextCandidateAddr, nextIdx, ok := nextEndpointCandidate(candidateQueue, queueIdx, currentEndpoint)
			queueIdx = nextIdx
			if ok {
				sendPeerCandidateProbe(sockets, nextCandidateAddr, stunSecretHash)
				ipc := fmt.Sprintf("public_key=%s\nendpoint=%s\n", peerPubHex, nextCandidateAddr)
				if err := dev.IpcSet(ipc); err == nil {
					appLog.Warn("switching endpoint after handshake timeout", "endpoint", nextCandidateAddr)
					currentEndpoint = nextCandidateAddr
					lastSwitchTime = time.Now()
				}
			} else {
				appLog.Warn("endpoint retry stopped", "reason", "candidate queue exhausted")
				signalEndpointExhaustion(ctx, exhausted)
				return
			}
		}
	}
}

func signalEndpointExhaustion(ctx context.Context, exhausted chan<- struct{}) {
	if exhausted == nil {
		return
	}
	select {
	case exhausted <- struct{}{}:
	case <-ctx.Done():
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
