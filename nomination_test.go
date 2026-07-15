package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/stun"
)

func TestNominationWaitStopsWhenCanceled(t *testing.T) {
	tracker := newNominationTracker()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	if endpoint := tracker.waitForSelection(ctx, time.Minute); endpoint != "" {
		t.Fatalf("waitForSelection returned %q after cancellation", endpoint)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("nomination cancellation took %v", elapsed)
	}
}

func TestInterfaceAddrIP(t *testing.T) {
	ipv4 := net.ParseIP("192.0.2.10")
	ipv6 := net.ParseIP("2001:db8::10")
	for _, test := range []struct {
		name string
		addr net.Addr
		want net.IP
	}{
		{name: "network address", addr: &net.IPNet{IP: ipv4, Mask: net.CIDRMask(24, 32)}, want: ipv4},
		{name: "point-to-point address", addr: &net.IPAddr{IP: ipv6}, want: ipv6},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := interfaceAddrIP(test.addr); !got.Equal(test.want) {
				t.Fatalf("interfaceAddrIP(%T) = %v, want %v", test.addr, got, test.want)
			}
		})
	}
}

func TestIsRoutableCandidateIP(t *testing.T) {
	for _, tt := range []struct {
		name   string
		ip     string
		family networkFamily
		want   bool
	}{
		{"global IPv4 dual", "203.0.113.5", familyDual, true},
		{"global IPv4 wrong family", "203.0.113.5", familyIPv6, false},
		{"global IPv6 dual", "2001:db8::1", familyDual, true},
		{"global IPv6 wrong family", "2001:db8::1", familyIPv4, false},
		{"IPv6 ULA rejected", "fd07:b51a:cc66::1", familyIPv6, false},
		{"IPv6 ULA rejected even dual", "fd00::1", familyDual, false},
		{"IPv6 link-local rejected", "fe80::1", familyIPv6, false},
		{"IPv4 private LAN allowed", "192.168.1.220", familyIPv4, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("invalid test IP %q", tt.ip)
			}
			if got := isRoutableCandidateIP(ip, tt.family); got != tt.want {
				t.Fatalf("isRoutableCandidateIP(%s, %v) = %v, want %v", tt.ip, tt.family, got, tt.want)
			}
		})
	}
}

func TestIsPubliclyRoutableCandidateAddr(t *testing.T) {
	for _, tt := range []struct {
		addr string
		want bool
	}{
		{"192.168.1.220:1234", false},
		{"10.0.0.5:1234", false},
		{"[fd00::1]:1234", false},
		{"203.0.113.5:1234", true},
		{"54.244.51.38:19144", true},
		{"[2806:101e:9:28ee::1]:1234", true},
		{"127.0.0.1:1234", false},
		{"169.254.1.5:1234", false},
		{"[fe80::1]:1234", false},
	} {
		if got := isPubliclyRoutableCandidateAddr(tt.addr); got != tt.want {
			t.Fatalf("isPubliclyRoutableCandidateAddr(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestNominationTrackerAcceptsOnlyMasterWaitSequence(t *testing.T) {
	tracker := newNominationTracker()
	const first = "[2001:db8::1]:5000"
	const second = "[2001:db8::2]:5001"

	// A slave must not choose a peer before the CONNECT response activates the
	// nomination phase, even if it sees a syntactically valid master request.
	if tracker.observe(first, nominationWaitSequence[0]) {
		t.Fatal("selected before activation")
	}

	tracker.activate()
	if tracker.observe(first, 12345) {
		t.Fatal("selected an invalid wait value")
	}
	for i, want := range nominationWaitSequence[1:] {
		selected := tracker.observe(first, want)
		if selected != (i == len(nominationWaitSequence)-2) {
			t.Fatalf("first candidate step %d selected=%v", i, selected)
		}
		// A competing candidate maintains its own master-driven sequence.
		if i < len(nominationWaitSequence)-2 {
			if otherSelected := tracker.observe(second, nominationWaitSequence[i]); otherSelected {
				t.Fatalf("second candidate step %d selected too early", i)
			}
		}
	}
	if got := tracker.selectedEndpoint(); got != first {
		t.Fatalf("selected endpoint = %q, want %q", got, first)
	}
	if tracker.observe(second, nominationWaitSequence[len(nominationWaitSequence)-1]) {
		t.Fatal("selected a second candidate after first selection")
	}
}

func TestNominationTrackerRetainsPreResponseMasterSequence(t *testing.T) {
	tracker := newNominationTracker()
	const peer = "[2001:db8::1]:5000"
	for _, wait := range nominationWaitSequence {
		if tracker.observe(peer, wait) {
			t.Fatal("selected before activation")
		}
	}
	tracker.activate()
	if got := tracker.selectedEndpoint(); got != peer {
		t.Fatalf("selected endpoint after activation = %q, want %q", got, peer)
	}
}

func TestStunNominationWait(t *testing.T) {
	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest,
		stun.RawAttribute{Type: stun.AttrData, Value: []byte(`{"wait":125}`)})
	if got, ok := stunNominationWait(msg); !ok || got != 125 {
		t.Fatalf("stunNominationWait = (%d, %v), want (125, true)", got, ok)
	}
}

func TestStunBindingProbeIsAuthenticatedAndHasNoNominationData(t *testing.T) {
	const secret = "probe-secret"
	raw, _ := stunBindingProbe(secret)
	msg, ok := parseStunMessage(raw)
	if !ok {
		t.Fatal("stunBindingProbe produced an invalid STUN message")
	}
	if msg.Type != stun.BindingRequest {
		t.Fatalf("probe type = %s, want Binding Request", msg.Type)
	}
	if !validStunIntegrity(msg, secret) {
		t.Fatal("probe MESSAGE-INTEGRITY did not validate")
	}
	if _, err := msg.Get(stun.AttrData); err == nil {
		t.Fatal("probe unexpectedly carried nomination DATA")
	}
}

func TestSendPeerCandidateProbeUsesIPv4Socket(t *testing.T) {
	const secret = "recovery-probe-secret"
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	if !sendPeerCandidateProbe(&udpSockets{V4: sender}, receiver.LocalAddr().String(), secret) {
		t.Fatal("recovery STUN probe was not sent")
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	n, _, err := receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg, ok := parseStunMessage(buf[:n])
	if !ok || msg.Type != stun.BindingRequest || !validStunIntegrity(msg, secret) {
		t.Fatal("received recovery probe was not an authenticated STUN binding request")
	}
}

func TestEarlyNominationStopRestoresSocketDeadline(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	listener := newEarlyNominationListener(&udpSockets{V4: conn}, "secret", newNominationTracker())
	listener.Start()
	stopped := make(chan struct{})
	go func() {
		listener.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("early nomination listener did not stop promptly")
	}

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err := sender.WriteToUDP([]byte("deadline-check"), conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	timer := time.AfterFunc(time.Second, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer timer.Stop()
	buf := make([]byte, 32)
	if _, _, err := conn.ReadFromUDP(buf); err != nil {
		t.Fatalf("socket was not reusable after listener stop: %v", err)
	}
}

func TestProbeCandidatesSendsAuthenticatedBindingRequest(t *testing.T) {
	const secret = "fallback-probe-secret"
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()

	result := make(chan error, 1)
	go func() {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1500)
		n, remote, err := peer.ReadFromUDP(buf)
		if err != nil {
			result <- err
			return
		}
		msg, ok := parseStunMessage(buf[:n])
		if !ok || msg.Type != stun.BindingRequest || !validStunIntegrity(msg, secret) {
			result <- fmt.Errorf("fallback probe was not an authenticated Binding Request")
			return
		}
		_, err = peer.WriteToUDP(stunBindingSuccess(msg, remote, secret), remote)
		result <- err
	}()

	addr := peer.LocalAddr().String()
	ourLocal := []candidate{{Type: "iface", Addr: "127.0.0.1:1"}}
	got := probeCandidates(&udpSockets{V4: local}, []candidate{{Type: "iface", Addr: addr}}, secret, ourLocal)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if got != addr {
		t.Fatalf("probeCandidates = %q, want %q", got, addr)
	}
}

func TestAcceptBindingSuccessRequiresProbedAddressAndMatchingTransactionID(t *testing.T) {
	const addr = "192.0.2.1:5000"
	_, tx := stunRequest()
	probed := map[string][][12]byte{addr: {tx}}

	matching := stun.MustBuild(stun.NewTransactionIDSetter(tx), stun.BindingSuccess)
	if !acceptBindingSuccess(probed, addr, matching) {
		t.Fatal("rejected a Binding Success from a probed address with the matching transaction ID")
	}

	if acceptBindingSuccess(probed, "192.0.2.2:5000", matching) {
		t.Fatal("accepted a Binding Success from an address we never probed")
	}

	_, otherTx := stunRequest()
	mismatched := stun.MustBuild(stun.NewTransactionIDSetter(otherTx), stun.BindingSuccess)
	if acceptBindingSuccess(probed, addr, mismatched) {
		t.Fatal("accepted a Binding Success with a transaction ID we never sent, from a probed address")
	}

	// A delayed response to an earlier probe must still be accepted even
	// after a later tick has re-probed the same address with a new
	// transaction ID.
	_, newerTx := stunRequest()
	probed[addr] = append(probed[addr], newerTx)
	stale := stun.MustBuild(stun.NewTransactionIDSetter(tx), stun.BindingSuccess)
	if !acceptBindingSuccess(probed, addr, stale) {
		t.Fatal("rejected a delayed Binding Success matching an earlier outstanding probe")
	}
}

func TestRespondToStunBindingRequestRejectsInvalidIntegrity(t *testing.T) {
	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest,
		stun.NewShortTermIntegrity("wrong-secret"))
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 5000}

	resp, accepted := respondToStunBindingRequest(nil, msg, addr, "expected-secret", nil)
	if accepted {
		t.Fatal("accepted a Binding Request with invalid MESSAGE-INTEGRITY")
	}
	if resp != nil {
		t.Fatal("returned a response for a Binding Request that failed integrity validation")
	}
}

func TestCompatibleCandidatesHonorsOpenSocketFamilies(t *testing.T) {
	candidates := []candidate{
		{Type: "iface", Addr: "192.0.2.1:1000"},
		{Type: "iface", Addr: "[2001:db8::1]:1000"},
	}
	dualStackLocal := []candidate{
		{Type: "iface", Addr: "10.0.0.5:1000"},
		{Type: "iface", Addr: "[2001:db8::5]:1000"},
	}
	got := compatibleCandidates(&udpSockets{V4: &net.UDPConn{}}, candidates, dualStackLocal)
	if len(got) != 1 || got[0].Addr != "192.0.2.1:1000" {
		t.Fatalf("IPv4-only compatible candidates = %#v, want only IPv4", got)
	}
	got = compatibleCandidates(&udpSockets{V6: &net.UDPConn{}}, candidates, dualStackLocal)
	if len(got) != 1 || got[0].Addr != "[2001:db8::1]:1000" {
		t.Fatalf("IPv6-only compatible candidates = %#v, want only IPv6", got)
	}
}

func TestCompatibleCandidatesRequiresRealLocalCandidateNotJustOpenSocket(t *testing.T) {
	candidates := []candidate{
		{Type: "iface", Addr: "192.0.2.1:1000"},
		{Type: "iface", Addr: "[2001:db8::1]:1000"},
	}
	// Dual-stack: both sockets open, but we never found a real local IPv6
	// candidate (e.g. an IPv4-only LTE hotspot). The peer's IPv6 candidate
	// must not be treated as compatible just because a v6 socket exists.
	ipv4OnlyLocal := []candidate{{Type: "iface", Addr: "10.0.0.5:1000"}}
	got := compatibleCandidates(&udpSockets{V4: &net.UDPConn{}, V6: &net.UDPConn{}}, candidates, ipv4OnlyLocal)
	if len(got) != 1 || got[0].Addr != "192.0.2.1:1000" {
		t.Fatalf("compatibleCandidates with no real local IPv6 = %#v, want only IPv4", got)
	}
}

func TestBuildCandidateRetryQueuePreservesObservedThenAdvertised(t *testing.T) {
	got := buildCandidateRetryQueue(
		"203.0.113.1:1000",
		[]string{"203.0.113.2:2000", "203.0.113.1:1000", "203.0.113.2:2000"},
		[]candidate{
			{Type: "iface", Addr: "192.168.1.1:1000"},
			{Type: "reflex", Addr: "203.0.113.3:3000"},
			{Type: "iface", Addr: "203.0.113.2:2000"},
		},
	)
	want := []string{"203.0.113.2:2000", "203.0.113.3:3000", "192.168.1.1:1000"}
	if len(got) != len(want) {
		t.Fatalf("retry queue = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("retry queue = %#v, want %#v", got, want)
		}
	}
}

func TestValidateLocalCandidatesRejectsEmptyDualStackResult(t *testing.T) {
	if err := validateLocalCandidates(nil, familyDual); err == nil {
		t.Fatal("dual-stack mode accepted an empty candidate set")
	}
	if err := validateLocalCandidates([]candidate{{Type: "iface", Addr: "192.0.2.1:1000"}}, familyDual); err != nil {
		t.Fatalf("dual-stack mode rejected a usable candidate: %v", err)
	}
}
