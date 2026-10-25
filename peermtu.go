package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// DPLPMTUD state constants per RFC 8899 Section 5.1.
type dplpmtudState int

const (
	// dplpmtudStateBase is the initial state operating at minimum guaranteed MTU (1280).
	dplpmtudStateBase dplpmtudState = iota
	// dplpmtudStateSearching indicates active probing of higher MTU milestones.
	dplpmtudStateSearching
	// dplpmtudStateSearchComplete indicates all milestones up to the path limit were probed.
	dplpmtudStateSearchComplete
	// dplpmtudStateDisabled indicates manual MTU configuration was specified.
	dplpmtudStateDisabled
)

func (s dplpmtudState) String() string {
	switch s {
	case dplpmtudStateBase:
		return "BASE"
	case dplpmtudStateSearching:
		return "SEARCHING"
	case dplpmtudStateSearchComplete:
		return "SEARCH_COMPLETE"
	case dplpmtudStateDisabled:
		return "DISABLED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(s))
	}
}

// defaultProbeMilestones are discrete MTU milestones probed per RFC 8899 / Tailscale peermtu model.
// 1280: RFC 8200 IPv6 floor
// 1360: Safe clamp for restricted transit, nested VPNs, and cellular paths
// 1400: Common conservative internet MTU
// 1420: Standard WireGuard MTU over IPv6 1500 links
// 1440: Standard WireGuard MTU over IPv4 1500 links
var defaultProbeMilestones = []int{1360, 1400, 1420, 1440}

const (
	// maxDPLPMTUDProbesPerMilestone is MAX_PROBES per RFC 8899 Section 5.1.2.
	maxDPLPMTUDProbesPerMilestone = 2
	// baseTunnelMTU is the minimum IPv6 MTU baseline (1280).
	baseTunnelMTU = minTunnelMTU
)

// peerMTUProber manages RFC 8899 Datagram PLPMTUD state, candidate probing,
// and dynamic MTU locking for a peer session.
type peerMTUProber struct {
	mu             sync.Mutex
	state          dplpmtudState
	milestones     []int
	currentIndex   int
	confirmedMTU   int
	maxTargetMTU   int
	failedAttempts int
	manualOverride bool
}

// newPeerMTUProber creates a new RFC 8899 prober. If manualMTU > 0, probing is disabled
// and the prober locks to that manual MTU. Otherwise, it prepares milestones up to maxTargetMTU.
func newPeerMTUProber(initialMTU, maxTargetMTU int, manualMTU int) *peerMTUProber {
	if manualMTU > 0 {
		return &peerMTUProber{
			state:          dplpmtudStateDisabled,
			confirmedMTU:   manualMTU,
			maxTargetMTU:   manualMTU,
			manualOverride: true,
		}
	}

	if maxTargetMTU < baseTunnelMTU {
		maxTargetMTU = baseTunnelMTU
	}

	var candidates []int
	for _, m := range defaultProbeMilestones {
		if m <= maxTargetMTU {
			candidates = append(candidates, m)
		}
	}

	confirmed := initialMTU
	if confirmed < baseTunnelMTU {
		confirmed = baseTunnelMTU
	}

	// Find starting index for probing higher milestones
	startIdx := 0
	for i, m := range candidates {
		if m <= confirmed {
			startIdx = i + 1
		}
	}

	state := dplpmtudStateSearching
	if startIdx >= len(candidates) {
		state = dplpmtudStateSearchComplete
	}

	return &peerMTUProber{
		state:        state,
		milestones:   candidates,
		currentIndex: startIdx,
		confirmedMTU: confirmed,
		maxTargetMTU: maxTargetMTU,
	}
}

// NextProbeMTU returns the next milestone to probe and true, or (0, false) if no further
// probing is needed.
func (p *peerMTUProber) NextProbeMTU() (int, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state != dplpmtudStateSearching || p.currentIndex >= len(p.milestones) {
		return 0, false
	}
	return p.milestones[p.currentIndex], true
}

// RecordProbeResult records the success or failure of a probe for targetMTU.
// Returns:
//   - mtuChanged: true if confirmed MTU was increased
//   - newMTU: the newly confirmed MTU (or current MTU)
//   - searchDone: true if search is complete (either max milestone confirmed or failed)
func (p *peerMTUProber) RecordProbeResult(targetMTU int, success bool) (bool, int, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state != dplpmtudStateSearching {
		return false, p.confirmedMTU, true
	}

	if p.currentIndex >= len(p.milestones) || p.milestones[p.currentIndex] != targetMTU {
		return false, p.confirmedMTU, false
	}

	if success {
		p.failedAttempts = 0
		mtuChanged := targetMTU > p.confirmedMTU
		p.confirmedMTU = targetMTU
		p.currentIndex++
		if p.currentIndex >= len(p.milestones) {
			p.state = dplpmtudStateSearchComplete
			return mtuChanged, p.confirmedMTU, true
		}
		return mtuChanged, p.confirmedMTU, false
	}

	// Probe failed (timeout)
	p.failedAttempts++
	if p.failedAttempts >= maxDPLPMTUDProbesPerMilestone {
		// Milestone failed twice; lock to highest confirmed MTU and finish search
		p.state = dplpmtudStateSearchComplete
		return false, p.confirmedMTU, true
	}

	return false, p.confirmedMTU, false
}

// ConfirmedMTU returns the current locked path MTU.
func (p *peerMTUProber) ConfirmedMTU() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.confirmedMTU
}

// State returns the current DPLPMTUD state.
func (p *peerMTUProber) State() dplpmtudState {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

// Reset reverts probing back to base MTU on sustained path failure.
func (p *peerMTUProber) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.manualOverride {
		return
	}
	p.state = dplpmtudStateSearching
	p.confirmedMTU = baseTunnelMTU
	p.currentIndex = 0
	p.failedAttempts = 0
}

type echoProbePayload struct {
	SessionSecretHash string `json:"session_secret_hash"`
	RequestID         string `json:"req_id"`
	Timeout           int    `json:"timeout"`
	Padding           string `json:"pad,omitempty"`
}

// buildPaddedEchoPayload constructs a JSON UDP echo request whose serialized length
// plus IP (20 bytes for IPv4) and UDP (8 bytes) headers equals targetPacketSize.
func buildPaddedEchoPayload(secretHash, reqID string, timeoutMs int, targetPacketSize int, ipHeaderLen int) ([]byte, error) {
	targetPayloadLen := targetPacketSize - ipHeaderLen - 8
	if targetPayloadLen < 64 {
		targetPayloadLen = 64
	}

	req := echoProbePayload{
		SessionSecretHash: secretHash,
		RequestID:         reqID,
		Timeout:           timeoutMs,
	}
	base, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	if len(base) >= targetPayloadLen {
		return base, nil
	}

	neededPad := targetPayloadLen - len(base) - 9
	if neededPad < 0 {
		return base, nil
	}
	req.Padding = strings.Repeat("A", neededPad)
	padded, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	for len(padded) < targetPayloadLen {
		req.Padding += "A"
		padded, _ = json.Marshal(req)
	}
	for len(padded) > targetPayloadLen && len(req.Padding) > 0 {
		req.Padding = req.Padding[:len(req.Padding)-1]
		padded, _ = json.Marshal(req)
	}
	return padded, nil
}
