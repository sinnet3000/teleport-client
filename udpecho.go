package main

import (
	"context"
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

// Overridable in tests to avoid multi-second real sleeps.
var (
	// steadyStateEchoDeadline applies to request 1+.
	steadyStateEchoDeadline = 3 * time.Second
	// startupRetryInterval is the re-armed wait step for request 0.
	startupRetryInterval = 3 * time.Second
	// startupCeiling covers the complete endpoint candidate retry window.
	startupCeiling = 95 * time.Second
)

// A sustained minute without a response after the tunnel was ready is long
// enough to distinguish endpoint/session loss from a brief network stall.
const maxConsecutiveEchoFailures = 12

type udpEchoStats struct {
	windowStart time.Time
	count       int
	total       time.Duration
	min         time.Duration
	max         time.Duration
}

type udpEchoHealth struct {
	ready               bool
	consecutiveFailures int
}

type udpEchoHealthEvent int

const (
	udpEchoHealthy udpEchoHealthEvent = iota + 1
	udpEchoStartupFailed
	udpEchoUnhealthy
)

func (h *udpEchoHealth) observe(matched bool) (event udpEchoHealthEvent, firstSuccess bool) {
	if matched {
		firstSuccess = !h.ready
		h.ready = true
		h.consecutiveFailures = 0
		return udpEchoHealthy, firstSuccess
	}
	if !h.ready {
		return udpEchoStartupFailed, false
	}
	h.consecutiveFailures++
	if h.consecutiveFailures >= maxConsecutiveEchoFailures {
		h.consecutiveFailures = 0
		return udpEchoUnhealthy, false
	}
	return 0, false
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
func runUDPEchoPinger(ctx context.Context, tunnelNet *netstack.Net, secret string, info serverInfo, healthEvents chan<- udpEchoHealthEvent) error {
	if tunnelNet == nil || info.UDPEchoAddr == "" || info.UDPEchoPort == 0 {
		appLog.Warn("UDP echo unavailable", "reason", "server supplied no echo endpoint")
		return nil
	}

	remote := &net.UDPAddr{IP: net.ParseIP(info.UDPEchoAddr), Port: info.UDPEchoPort}
	if remote.IP == nil {
		return fmt.Errorf("invalid UDP echo endpoint %q", info.UDPEchoAddr)
	}
	conn, err := tunnelNet.DialUDP(nil, remote)
	if err != nil {
		return fmt.Errorf("dial UDP echo endpoint %s: %w", remote, err)
	}
	defer conn.Close()

	digest := sha256.Sum256([]byte(secret))
	secretHash := base64.StdEncoding.EncodeToString(digest[:])
	buf := make([]byte, 2048)
	stats := udpEchoStats{}
	health := udpEchoHealth{}
	for requestID := 0; ; requestID++ {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		request := struct {
			SessionSecretHash string `json:"session_secret_hash"`
			RequestID         string `json:"req_id"`
			Timeout           int    `json:"timeout"`
		}{secretHash, fmt.Sprint(requestID), 3000}
		payload, err := json.Marshal(request)
		if err != nil {
			return fmt.Errorf("marshal UDP echo request: %w", err)
		}

		started := time.Now()
		if _, err := conn.Write(payload); err != nil {
			return fmt.Errorf("write UDP echo request %d: %w", requestID, err)
		}
		appLog.Debug("sent UDP echo request", "request_id", requestID, "endpoint", remote.String())

		var matched bool
		if requestID == 0 {
			matched = waitForStartupResponse(ctx, conn, buf, requestID, request.RequestID, started, func() error {
				_, err := conn.Write(payload)
				return err
			})
		} else {
			matched = waitForSteadyStateResponse(ctx, conn, buf, requestID, request.RequestID)
		}
		if ctx.Err() != nil {
			return nil
		}

		event, firstSuccess := health.observe(matched)
		if event != 0 && healthEvents != nil {
			select {
			case healthEvents <- event:
			case <-ctx.Done():
				return nil
			}
		}
		if matched {
			now := time.Now()
			rtt := now.Sub(started)
			appLog.Debug("received UDP echo response", "request_id", requestID, "rtt", rtt.Round(time.Millisecond))
			if firstSuccess {
				appLog.Info("WireGuard tunnel ready", "initial_echo_rtt", rtt.Round(time.Millisecond))
			}
			if stats.observe(now, rtt) {
				stats.logAndReset(now)
			}
		}
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil
		}
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// waitForSteadyStateResponse waits a single steadyStateEchoDeadline for a
// reply matching wantID, discarding anything else.
func waitForSteadyStateResponse(ctx context.Context, conn net.Conn, buf []byte, requestID int, wantID string) bool {
	deadline := time.Now().Add(steadyStateEchoDeadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	for {
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			if isTimeout(err) {
				appLog.Warn("UDP echo request timed out", "request_id", requestID, "error", err)
			} else {
				appLog.Error("UDP echo read failed", "request_id", requestID, "error", err)
			}
			return false
		}
		responseID, err := parseUDPEchoResponse(buf[:n])
		if err != nil {
			appLog.Debug("invalid UDP echo response", "request_id", requestID, "parsed_id", responseID, "response_bytes", n, "error", err)
			continue
		}
		if responseID != wantID {
			appLog.Warn("discarded stale UDP echo response", "request_id", requestID, "response_id", responseID)
			continue
		}
		return true
	}
}

// waitForStartupResponse re-arms the read deadline instead of giving up
// after one timeout, so a reply delayed by a WireGuard handshake retry
// still matches request 0 rather than being discarded as stale.
func waitForStartupResponse(ctx context.Context, conn net.Conn, buf []byte, requestID int, wantID string, started time.Time, resend func() error) bool {
	ceiling := started.Add(startupCeiling)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stop()
	for {
		now := time.Now()
		if !now.Before(ceiling) {
			appLog.Error("UDP echo startup probe failed", "request_id", requestID, "elapsed", now.Sub(started).Round(time.Second))
			return false
		}
		deadline := now.Add(startupRetryInterval)
		if deadline.After(ceiling) {
			deadline = ceiling
		}
		_ = conn.SetReadDeadline(deadline)
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return false
			}
			if !isTimeout(err) {
				appLog.Error("UDP echo startup probe failed", "request_id", requestID, "error", err)
				return false
			}
			appLog.Debug("UDP echo startup probe still waiting", "request_id", requestID, "elapsed", time.Since(started).Round(time.Second))
			if resend != nil {
				if err := resend(); err != nil {
					appLog.Error("UDP echo startup probe resend failed", "request_id", requestID, "error", err)
					return false
				}
				appLog.Debug("resent UDP echo startup probe", "request_id", requestID)
			}
			continue
		}
		responseID, err := parseUDPEchoResponse(buf[:n])
		if err != nil {
			appLog.Debug("invalid UDP echo response", "request_id", requestID, "parsed_id", responseID, "response_bytes", n, "error", err)
			continue
		}
		if responseID != wantID {
			appLog.Debug("discarded unexpected UDP echo response during startup", "request_id", requestID, "response_id", responseID)
			continue
		}
		return true
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
