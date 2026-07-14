package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

const udpEchoSummaryInterval = 30 * time.Second

type udpEchoStats struct {
	windowStart time.Time
	count       int
	total       time.Duration
	min         time.Duration
	max         time.Duration
}

func (s *udpEchoStats) observe(now time.Time, rtt time.Duration) bool {
	if s.windowStart.IsZero() {
		s.windowStart = now
	}
	s.count++
	s.total += rtt
	if s.min == 0 || rtt < s.min {
		s.min = rtt
	}
	if rtt > s.max {
		s.max = rtt
	}
	return now.Sub(s.windowStart) >= udpEchoSummaryInterval
}

func (s *udpEchoStats) logAndReset(now time.Time) {
	appLog.Info("UDP echo statistics",
		"samples", s.count,
		"average", (s.total / time.Duration(s.count)).Round(time.Millisecond),
		"minimum", s.min.Round(time.Millisecond),
		"maximum", s.max.Round(time.Millisecond),
	)
	*s = udpEchoStats{windowStart: now}
}

// runUDPEchoPinger sends Teleport's post-activation quality probe through the
// WireGuard netstack to the server-provided UDP echo endpoint.
func runUDPEchoPinger(tunnelNet *netstack.Net, secret string, info serverInfo) {
	if tunnelNet == nil || info.UDPEchoAddr == "" || info.UDPEchoPort == 0 {
		appLog.Warn("UDP echo unavailable", "reason", "server supplied no echo endpoint")
		return
	}

	remote := &net.UDPAddr{IP: net.ParseIP(info.UDPEchoAddr), Port: info.UDPEchoPort}
	if remote.IP == nil {
		appLog.Error("invalid UDP echo endpoint", "address", info.UDPEchoAddr)
		return
	}
	conn, err := tunnelNet.DialUDP(nil, remote)
	if err != nil {
		appLog.Error("failed to dial UDP echo endpoint", "endpoint", remote.String(), "error", err)
		return
	}
	defer conn.Close()

	digest := sha256.Sum256([]byte(secret))
	secretHash := base64.StdEncoding.EncodeToString(digest[:])
	buf := make([]byte, 2048)
	stats := udpEchoStats{}
	tunnelReadyLogged := false
	for requestID := 0; ; requestID++ {
		request := struct {
			SessionSecretHash string `json:"session_secret_hash"`
			RequestID         string `json:"req_id"`
			Timeout           int    `json:"timeout"`
		}{secretHash, fmt.Sprint(requestID), 3000}
		payload, err := json.Marshal(request)
		if err != nil {
			appLog.Error("failed to marshal UDP echo request", "error", err)
			return
		}

		started := time.Now()
		if _, err := conn.Write(payload); err != nil {
			appLog.Error("failed to write UDP echo request", "request_id", requestID, "error", err)
			return
		}
		appLog.Debug("sent UDP echo request", "request_id", requestID, "endpoint", remote.String())
		deadline := time.Now().Add(3 * time.Second)
		matched := false
		for !matched {
			_ = conn.SetReadDeadline(deadline)
			n, err := conn.Read(buf)
			if err != nil {
				appLog.Warn("UDP echo request timed out", "request_id", requestID, "error", err)
				break
			}
			responseID, err := parseUDPEchoResponse(buf[:n])
			if err != nil {
				appLog.Debug("invalid UDP echo response", "request_id", requestID, "parsed_id", responseID, "response_bytes", n, "error", err)
				continue
			}
			if responseID != request.RequestID {
				// Discard late replies without shifting subsequent request IDs.
				appLog.Warn("discarded stale UDP echo response", "request_id", requestID, "response_id", responseID)
			} else {
				now := time.Now()
				rtt := now.Sub(started)
				appLog.Debug("received UDP echo response", "request_id", requestID, "rtt", rtt.Round(time.Millisecond))
				if !tunnelReadyLogged {
					appLog.Info("WireGuard tunnel ready", "initial_echo_rtt", rtt.Round(time.Millisecond))
					tunnelReadyLogged = true
				}
				if stats.observe(now, rtt) {
					stats.logAndReset(now)
				}
				matched = true
			}
		}
		time.Sleep(2 * time.Second)
	}
}

// parseUDPEchoResponse accepts req_id encoded as either a string or number.
func parseUDPEchoResponse(data []byte) (string, error) {
	var response struct {
		RequestID json.RawMessage `json:"req_id"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		return "", err
	}
	if len(response.RequestID) == 0 || string(response.RequestID) == "null" {
		return "", errors.New("response has no req_id")
	}
	var stringID string
	if err := json.Unmarshal(response.RequestID, &stringID); err == nil {
		return stringID, nil
	}
	var numericID json.Number
	if err := json.Unmarshal(response.RequestID, &numericID); err == nil {
		return numericID.String(), nil
	}
	return "", fmt.Errorf("req_id has unsupported JSON value %s", response.RequestID)
}
