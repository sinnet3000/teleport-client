package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pion/stun"
)

type candidate struct {
	Type string `json:"type"`
	Addr string `json:"addr"`
}

type networkFamily uint8

const (
	familyDual networkFamily = iota
	familyIPv4
	familyIPv6
)

func (f networkFamily) String() string {
	switch f {
	case familyIPv4:
		return "ipv4"
	case familyIPv6:
		return "ipv6"
	default:
		return "dual-stack"
	}
}

type peerDesc struct {
	Candidates []candidate `json:"candidates"`
	IceConfig  []iceServer `json:"ice_config,omitempty"`
	IsMaster   bool        `json:"is_master"`
}

type endpointSelection struct {
	Endpoint string
	Mode     string
	Packets  []packetLog
}

func listenPort() int {
	b := []byte{0, 0}
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return 49152 + int(binary.BigEndian.Uint16(b))%16384
}

func localCandidates(port int, family networkFamily) []candidate {
	ifaces, _ := net.Interfaces()
	seen := map[string]bool{}
	var out []candidate
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ip := interfaceAddrIP(a)
			if ip == nil || !ip.IsGlobalUnicast() {
				continue
			}
			if family == familyIPv4 && ip.To4() == nil {
				continue
			}
			if family == familyIPv6 && ip.To4() != nil {
				continue
			}
			addr := net.JoinHostPort(ip.String(), fmt.Sprint(port))
			if !seen[addr] {
				seen[addr] = true
				out = append(out, candidate{Type: "iface", Addr: addr})
			}
		}
	}
	return out
}

func interfaceAddrIP(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}

// The Teleport peer that advertises is_master=true drives nomination. Its
// authenticated Binding Requests carry these DATA values in order; the slave
// only answers them. This sequence comes from the successful shared-Go
// capture, not from generic ICE behaviour.
var nominationWaitSequence = []int{2000, 1000, 500, 250, 125}

// nominationTracker keeps the master-driven Teleport nomination state per
// remote UDP tuple. The slave must not invent or transmit wait requests:
// doing so reverses the protocol role and prevents the console from activating
// WireGuard. It only records the authenticated DATA requests it receives.
type nominationTracker struct {
	mu         sync.Mutex
	pairs      map[string]*nominationPair
	active     bool
	selected   string
	selectedCh chan struct{}
}

type nominationPair struct {
	nextWait int
}

func newNominationTracker() *nominationTracker {
	return &nominationTracker{
		pairs:      make(map[string]*nominationPair),
		selectedCh: make(chan struct{}),
	}
}

// observe records a master nomination request and returns whether it completed
// the exact wait sequence for this remote tuple.
func (t *nominationTracker) observe(addr string, waitMs int) (selected bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.pairs[addr]
	if p == nil {
		p = &nominationPair{}
		t.pairs[addr] = p
	}
	if t.selected != "" || p.nextWait >= len(nominationWaitSequence) {
		return false
	}
	if waitMs != nominationWaitSequence[p.nextWait] {
		return false
	}
	p.nextWait++
	if p.nextWait == len(nominationWaitSequence) {
		if !t.active {
			return false
		}
		t.selected = addr
		close(t.selectedCh)
		return true
	}
	return false
}

// activate allows a completed master nomination sequence to select an
// endpoint. Progress observed before activation is retained.
func (t *nominationTracker) activate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active {
		return
	}
	t.active = true
	// The console can complete the master-driven wait sequence before our
	// CONNECT polling loop observes CONNECT_RESPONSE. Preserve that verified
	// pre-response work and select it now instead of waiting another 40 seconds.
	for addr, p := range t.pairs {
		if p.nextWait == len(nominationWaitSequence) {
			t.selected = addr
			close(t.selectedCh)
			return
		}
	}
}

func (t *nominationTracker) selectedEndpoint() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.selected
}

func (t *nominationTracker) waitForSelection(timeout time.Duration) string {
	if selected := t.selectedEndpoint(); selected != "" {
		return selected
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-t.selectedCh:
		return t.selectedEndpoint()
	case <-timer.C:
		return ""
	}
}

// stunBindingProbe is the initial, authenticated connectivity check sent to a
// peer candidate. Unlike nomination requests it deliberately has no DATA
// attribute: the console is the master and supplies the wait countdown.
//
// This is particularly important on IPv4. A STUN query to the public STUN
// server establishes a mapping for that server, but a symmetric or
// address-dependent NAT may still drop the console's first packet until we
// send a packet to the console's exact IP:port tuple.
func stunBindingProbe(secHash string) ([]byte, [12]byte) {
	var setters []stun.Setter
	setters = append(setters, stun.TransactionID, stun.BindingRequest)
	if secHash != "" {
		setters = append(setters, stun.NewShortTermIntegrity(secHash))
	}
	msg := stun.MustBuild(setters...)
	var tx [12]byte
	copy(tx[:], msg.TransactionID[:])
	return msg.Raw, tx
}

// startPeerCandidateProbes creates tuple-specific NAT state before the
// console's master-driven nomination reaches us. The desktop client sends the
// same compact, MESSAGE-INTEGRITY-only Binding Request to each candidate
// immediately after CONNECT_RESPONSE. Repeat briefly in case an early packet
// is lost, then let the existing listener handle the console's DATA countdown.
func startPeerCandidateProbes(s *udpSockets, candidates []candidate, secHash string) func() {
	done := make(chan struct{})
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(done) }) }
	if s == nil || len(candidates) == 0 {
		return stop
	}

	send := func() {
		for _, candidate := range candidates {
			host, _, err := net.SplitHostPort(candidate.Addr)
			if err != nil {
				continue
			}
			ip := net.ParseIP(strings.Trim(host, "[]"))
			if ip == nil {
				continue
			}
			conn, network := s.V6, "udp6"
			if ip.To4() != nil {
				conn, network = s.V4, "udp4"
			}
			if conn == nil {
				continue
			}
			remote, err := net.ResolveUDPAddr(network, candidate.Addr)
			if err != nil {
				continue
			}
			probe, _ := stunBindingProbe(secHash)
			_, _ = conn.WriteToUDP(probe, remote)
			appLog.Debug("sent candidate STUN probe", "candidate", candidate.Addr, "network", network)
		}
	}

	send()
	go func() {
		ticker := time.NewTicker(400 * time.Millisecond)
		defer ticker.Stop()
		deadline := time.NewTimer(5 * time.Second)
		defer deadline.Stop()
		for {
			select {
			case <-done:
				return
			case <-deadline.C:
				return
			case <-ticker.C:
				send()
			}
		}
	}()
	return stop
}

// nominationHint is an early, unverified signal that a candidate address may
// be the one the console eventually nominates; the caller confirms the real
// endpoint from earlyNominationListener.Logs() once CONNECT_RESPONSE arrives.
type nominationHint struct {
	Endpoint string
	Mode     string
}

// earlyNominationListener answers the console's authenticated STUN Binding
// Requests as soon as they arrive on the outer UDP sockets, which may be well
// before CONNECT_RESPONSE: the console can complete its nomination wait
// sequence before the CONNECT poll loop even observes a response.
type earlyNominationListener struct {
	sockets        *udpSockets
	stunSecretHash string
	nomination     *nominationTracker

	hints chan nominationHint

	mu   sync.Mutex
	logs []packetLog

	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

func newEarlyNominationListener(sockets *udpSockets, stunSecretHash string, nomination *nominationTracker) *earlyNominationListener {
	return &earlyNominationListener{
		sockets:        sockets,
		stunSecretHash: stunSecretHash,
		nomination:     nomination,
		hints:          make(chan nominationHint, 1),
		done:           make(chan struct{}),
	}
}

// Start begins reading from every open outer socket. Each listener is
// single-shot: create a new one per connection attempt rather than
// restarting one that has been Stopped.
func (l *earlyNominationListener) Start() {
	for _, conn := range []*net.UDPConn{l.sockets.V4, l.sockets.V6} {
		if conn == nil {
			continue
		}
		conn := conn
		l.wg.Add(1)
		go l.readLoop(conn)
	}
}

func (l *earlyNominationListener) readLoop(conn *net.UDPConn) {
	defer l.wg.Done()
	buf := make([]byte, 1500)
	for {
		select {
		case <-l.done:
			return
		default:
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		data := append([]byte(nil), buf[:n]...)
		l.appendLog(logPacket("in", addr, data))
		msg, ok := parseStunMessage(data)
		if !ok || msg.Type != stun.BindingRequest {
			continue
		}
		resp, accepted := respondToStunBindingRequest(conn, msg, addr, l.stunSecretHash, l.nomination)
		if !accepted {
			continue
		}
		if resp != nil {
			l.appendLog(logPacket("out", addr, resp))
		}
		select {
		case l.hints <- nominationHint{Endpoint: addr.String(), Mode: "inbound_binding_request"}:
		default:
		}
	}
}

func (l *earlyNominationListener) appendLog(p packetLog) {
	l.mu.Lock()
	l.logs = append(l.logs, p)
	l.mu.Unlock()
}

// Stop unblocks any goroutine parked in ReadFromUDP and waits for it to exit
// before returning, so it doesn't keep stealing packets from whichever reader
// (WireGuard's netstack, or the fallback probe) uses these sockets next. Safe
// to call more than once.
func (l *earlyNominationListener) Stop() {
	l.stopOnce.Do(func() {
		close(l.done)
		if l.sockets.V4 != nil {
			_ = l.sockets.V4.SetReadDeadline(time.Now())
		}
		if l.sockets.V6 != nil {
			_ = l.sockets.V6.SetReadDeadline(time.Now())
		}
		l.wg.Wait()
		if l.sockets.V4 != nil {
			_ = l.sockets.V4.SetReadDeadline(time.Time{})
		}
		if l.sockets.V6 != nil {
			_ = l.sockets.V6.SetReadDeadline(time.Time{})
		}
	})
}

// Logs returns a snapshot of packets observed so far.
func (l *earlyNominationListener) Logs() []packetLog {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]packetLog(nil), l.logs...)
}

func stunNominationWait(msg *stun.Message) (int, bool) {
	raw, err := msg.Get(stun.AttrData)
	if err != nil {
		return 0, false
	}
	var payload struct {
		Wait int `json:"wait"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0, false
	}
	return payload.Wait, true
}

// acceptBindingSuccess reports whether a Binding Success from addr echoes
// back the transaction ID of a probe we actually sent it, rather than just
// matching the source address (which a spoofed packet from a probed
// candidate's IP could also do). Each address may have multiple outstanding
// probes in flight, since a response can arrive after later ticks have
// already re-probed the same address.
func acceptBindingSuccess(probed map[string][][12]byte, addr string, msg *stun.Message) bool {
	for _, tx := range probed[addr] {
		if msg.TransactionID == tx {
			return true
		}
	}
	return false
}

func waitForNomination(s *udpSockets, port int, cands []candidate, sessionSecretHash string) endpointSelection {
	if s == nil {
		return endpointSelection{}
	}
	var logs []packetLog
	type packet struct {
		conn *net.UDPConn
		addr *net.UDPAddr
		data []byte
	}
	packets := make(chan packet, 16)
	var readWG sync.WaitGroup
	readDone := make(chan struct{})
	readLoop := func(conn *net.UDPConn) {
		defer readWG.Done()
		if conn == nil {
			return
		}
		buf := make([]byte, 1500)
		for {
			select {
			case <-readDone:
				return
			default:
			}
			// No self-timeout here: stopReadLoops explicitly unblocks and
			// cancels this loop on every return path, so re-arming a rolling
			// deadline here would race with that cancellation and could
			// overwrite it with a future deadline, hanging shutdown.
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			data := append([]byte(nil), buf[:n]...)
			select {
			case packets <- packet{conn: conn, addr: addr, data: data}:
			case <-readDone:
				return
			}
		}
	}
	readWG.Add(2)
	go readLoop(s.V4)
	go readLoop(s.V6)
	// Unblock the readLoop goroutines and wait for them to exit before
	// returning, so they don't keep stealing packets from whichever reader
	// (WireGuard's netstack, or the fallback probe) uses these sockets next.
	var stopReadOnce sync.Once
	stopReadLoops := func() {
		stopReadOnce.Do(func() {
			close(readDone)
			if s.V4 != nil {
				_ = s.V4.SetReadDeadline(time.Now())
			}
			if s.V6 != nil {
				_ = s.V6.SetReadDeadline(time.Now())
			}
			readWG.Wait()
			if s.V4 != nil {
				_ = s.V4.SetReadDeadline(time.Time{})
			}
			if s.V6 != nil {
				_ = s.V6.SetReadDeadline(time.Time{})
			}
		})
	}
	defer stopReadLoops()

	done := time.After(12 * time.Second)
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	ordered := rankCandidates(cands)
	// probed tracks the transaction IDs of the stunRequests we've sent to
	// each address; see acceptBindingSuccess.
	probed := map[string][][12]byte{}
	for {
		select {
		case pkt := <-packets:
			logs = append(logs, logPacket("in", pkt.addr, pkt.data))
			msg, ok := parseStunMessage(pkt.data)
			if !ok {
				continue
			}
			if msg.Type == stun.BindingRequest {
				resp, accepted := respondToStunBindingRequest(pkt.conn, msg, pkt.addr, sessionSecretHash, nil)
				if !accepted {
					continue
				}
				if resp != nil {
					logs = append(logs, logPacket("out", pkt.addr, resp))
				}
				return endpointSelection{Endpoint: pkt.addr.String(), Mode: "inbound_binding_request", Packets: logs}
			}
			if msg.Type == stun.BindingSuccess {
				if !acceptBindingSuccess(probed, pkt.addr.String(), msg) {
					appLog.Debug("discarded unsolicited STUN binding success", "remote", pkt.addr.String())
					continue
				}
				return endpointSelection{Endpoint: pkt.addr.String(), Mode: "binding_success", Packets: logs}
			}
		case <-tick.C:
			for _, c := range ordered {
				remote, err := net.ResolveUDPAddr("udp", c.Addr)
				if err != nil {
					continue
				}
				conn := s.V4
				if remote.IP.To4() == nil {
					conn = s.V6
				}
				if conn == nil {
					continue
				}
				req, tx := stunBindingProbe(sessionSecretHash)
				_, _ = conn.WriteToUDP(req, remote)
				addr := remote.String()
				probed[addr] = append(probed[addr], tx)
				logs = append(logs, logPacket("out", remote, req))
			}
		case <-done:
			stopReadLoops()
			return endpointSelection{Endpoint: probeCandidates(s, cands, sessionSecretHash), Mode: "fallback_probe", Packets: logs}
		}
	}
}

func rankCandidates(c []candidate) []candidate {
	out := append([]candidate(nil), c...)
	score := func(c candidate) int {
		host, _, _ := net.SplitHostPort(c.Addr)
		ip := net.ParseIP(strings.Trim(host, "[]"))
		s := 100
		switch c.Type {
		case "iface":
			s = 0
		case "reflex":
			s = 10
		case "turn":
			s = 20
		}
		if ip != nil && ip.To4() == nil {
			s -= 2
		}
		return s
	}
	sort.SliceStable(out, func(i, j int) bool { return score(out[i]) < score(out[j]) })
	return out
}

func probeCandidates(s *udpSockets, cands []candidate, sessionSecretHash string) string {
	ordered := compatibleCandidates(s, cands)
	for _, c := range ordered {
		host, _, err := net.SplitHostPort(c.Addr)
		if err != nil {
			continue
		}
		conn := s.V4
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && ip.To4() == nil {
			conn = s.V6
		}
		if conn == nil {
			continue
		}
		remote, err := net.ResolveUDPAddr("udp", c.Addr)
		if err != nil {
			continue
		}
		req, _ := stunBindingProbe(sessionSecretHash)
		deadline := time.Now().Add(350 * time.Millisecond)
		_ = conn.SetReadDeadline(deadline)
		_, _ = conn.WriteToUDP(req, remote)
		buf := make([]byte, 1500)
		matched := false
		for {
			_, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				break
			}
			if addr.String() == remote.String() {
				matched = true
				break
			}
			// Stray packet from something other than this candidate; keep
			// reading until the deadline instead of moving on immediately.
		}
		if matched {
			return c.Addr
		}
	}
	if len(ordered) > 0 {
		return ordered[0].Addr
	}
	return ""
}

// compatibleCandidates drops peer candidates that cannot be reached through
// one of our open sockets. In particular, a -4 run must never fall back to an
// IPv6 candidate merely because IPv6 has a higher generic ranking.
func compatibleCandidates(s *udpSockets, cands []candidate) []candidate {
	if s == nil {
		return nil
	}
	var compatible []candidate
	for _, c := range cands {
		host, _, err := net.SplitHostPort(c.Addr)
		if err != nil {
			continue
		}
		ip := net.ParseIP(strings.Trim(host, "[]"))
		if ip == nil {
			continue
		}
		if ip.To4() != nil && s.V4 != nil || ip.To4() == nil && s.V6 != nil {
			compatible = append(compatible, c)
		}
	}
	return rankCandidates(compatible)
}
