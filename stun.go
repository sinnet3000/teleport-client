package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/pion/stun"
)

func stunRequest() ([]byte, [12]byte) {
	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	var tx [12]byte
	copy(tx[:], msg.TransactionID[:])
	return msg.Raw, tx
}

func parseXorMapped(data []byte) (string, bool) {
	var msg stun.Message
	msg.Raw = append(msg.Raw[:0], data...)
	if err := msg.Decode(); err != nil {
		return "", false
	}
	var addr stun.XORMappedAddress
	if err := addr.GetFrom(&msg); err != nil {
		return "", false
	}
	return net.JoinHostPort(addr.IP.String(), fmt.Sprint(addr.Port)), true
}

// stunServerFromIce returns the host and effective port of the first STUN URL
// in a fetched GET_ICE_CONFIGURATION server list.
func stunServerFromIce(ice []iceServer) (string, bool) {
	for _, s := range ice {
		for _, rawURL := range s.URLs {
			u, ok := parseConsoleICEURL(rawURL)
			if !ok || u.Scheme != "stun" || u.Hostname() == "" {
				continue
			}
			port := u.Port()
			if port == "" {
				port = "3478"
			}
			return net.JoinHostPort(u.Hostname(), port), true
		}
	}
	return "", false
}

// turnServerFromIce mirrors the console parser's important constraints. The
// recovered teleportd accepts the turn scheme only with transport=udp; turns
// and TCP/TLS relay URLs do not create its TURN worker.
func turnServerFromIce(ice []iceServer) (string, bool) {
	for _, s := range ice {
		for _, rawURL := range s.URLs {
			u, ok := parseConsoleICEURL(rawURL)
			if !ok || u.Scheme != "turn" || u.Hostname() == "" || u.Query().Get("transport") != "udp" {
				continue
			}
			port := u.Port()
			if port == "" {
				port = "3478"
			}
			return net.JoinHostPort(u.Hostname(), port), true
		}
	}
	return "", false
}

func parseConsoleICEURL(rawURL string) (*url.URL, bool) {
	// teleportd turns the first colon into :// before using net/url.Parse.
	normalized := strings.Replace(rawURL, ":", "://", 1)
	u, err := url.Parse(normalized)
	return u, err == nil
}

func stunNetwork(family networkFamily) (string, error) {
	switch family {
	case familyIPv4:
		return "udp4", nil
	case familyIPv6:
		return "udp6", nil
	default:
		return "", errors.New("a reflexive candidate requires an address family")
	}
}

func reflexiveCandidateFromConn(conn *net.UDPConn, ice []iceServer, family networkFamily) (candidate, error) {
	return reflexiveCandidateFromConnWithTimeout(conn, ice, family, 5*time.Second)
}

func reflexiveCandidateFromConnWithTimeout(conn *net.UDPConn, ice []iceServer, family networkFamily, timeout time.Duration) (candidate, error) {
	network, err := stunNetwork(family)
	if err != nil {
		return candidate{}, err
	}
	if conn == nil {
		return candidate{}, fmt.Errorf("no %s socket for reflexive candidate", network)
	}
	stunServer, ok := stunServerFromIce(ice)
	if !ok {
		return candidate{}, errors.New("ICE_CONFIGURATION supplied no console-compatible STUN endpoint")
	}
	addr, err := net.ResolveUDPAddr(network, stunServer)
	if err != nil {
		var dnsErr *net.DNSError
		if family == familyIPv6 && errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return candidate{}, fmt.Errorf("STUN host %s has no AAAA record: %w", stunServer, err)
		}
		return candidate{}, err
	}
	req, _ := stunRequest()
	// This socket is later handed to WireGuard. Restrict only the STUN read:
	// SetDeadline would leave a write deadline behind and make all later
	// WireGuard sends fail once the discovery timeout expires. Clear even the
	// read-only deadline before handing the socket to nomination; otherwise a
	// listener already blocked in ReadFromUDP exits when this stale deadline
	// fires.
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return candidate{}, err
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	if _, err := conn.WriteToUDP(req, addr); err != nil {
		return candidate{}, err
	}
	appLog.Debug("sent STUN discovery request", "network", network, "server", addr.String())
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return candidate{}, err
		}
		if from.String() != addr.String() {
			// Stray packet from something other than the STUN server; keep
			// reading until the deadline instead of failing the whole probe.
			continue
		}
		mapped, ok := parseXorMapped(buf[:n])
		if !ok {
			appLog.Debug("STUN response from server had no XOR-MAPPED-ADDRESS", "network", network, "server", addr.String())
			continue
		}
		appLog.Debug("received STUN discovery response", "network", network, "mapped_address", mapped)
		return candidate{Type: "reflex", Addr: mapped}, nil
	}
}

func parseStunMessage(data []byte) (*stun.Message, bool) {
	var msg stun.Message
	msg.Raw = append(msg.Raw[:0], data...)
	if err := msg.Decode(); err != nil {
		return nil, false
	}
	return &msg, true
}

// stunIntegrityKey is the session secret as sent to the peer. Teleport's
// reference Go transport passes this directly to Pion's MessageIntegrity;
// it is not a SHA-256 digest encoded as base64.
func stunIntegrityKey(secret string) string {
	return secret
}

func validStunIntegrity(msg *stun.Message, key string) bool {
	return key != "" && stun.NewShortTermIntegrity(key).Check(msg) == nil
}

func stunBindingSuccess(req *stun.Message, peer *net.UDPAddr, secHash string) []byte {
	if peer == nil {
		return nil
	}
	var setters []stun.Setter
	setters = append(setters, stun.NewTransactionIDSetter(req.TransactionID), stun.BindingSuccess)
	if secHash != "" {
		setters = append(setters, stun.NewShortTermIntegrity(secHash))
	}
	msg := stun.MustBuild(setters...)
	return msg.Raw
}

// respondToStunBindingRequest validates an inbound STUN Binding Request's
// MESSAGE-INTEGRITY, replies with Binding Success over conn, and feeds any
// nomination DATA payload to tracker (which may be nil where no nomination
// tracking applies). accepted is false, with no reply sent, if integrity
// validation fails; callers should discard the packet in that case instead
// of treating the sender as a verified peer.
func respondToStunBindingRequest(conn *net.UDPConn, msg *stun.Message, addr *net.UDPAddr, secretHash string, tracker *nominationTracker) (response []byte, accepted bool) {
	if !validStunIntegrity(msg, secretHash) {
		appLog.Debug("discarded STUN request with invalid integrity", "remote", addr.String())
		return nil, false
	}
	if resp := stunBindingSuccess(msg, addr, secretHash); resp != nil {
		_, _ = conn.WriteToUDP(resp, addr)
		appLog.Debug("sent STUN success response", "remote", addr.String())
		response = resp
	}
	if tracker != nil {
		if waitMs, ok := stunNominationWait(msg); ok {
			appLog.Debug("nomination sequence progress", "remote", addr.String(), "wait_ms", waitMs)
			if tracker.observe(addr.String(), waitMs) {
				appLog.Info("nomination selected endpoint", "endpoint", addr.String())
			}
		}
	}
	return response, true
}

func isSTUN(data []byte) bool {
	return len(data) >= 20 &&
		(data[0] == 0x00 || data[0] == 0x01) &&
		binary.BigEndian.Uint32(data[4:8]) == 0x2112A442
}
