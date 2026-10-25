/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (c) Tailscale Inc & contributors
 *
 * TCP buffer constants and congestion control configuration patterns
 * derived from Tailscale (tailscale/wgengine/netstack/netstack_tcpbuf_default.go
 * and tailscale/wgengine/netstack/netstack.go), licensed under BSD-3-Clause.
 */

package tunnet

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// Default Tailscale buffer tuning constants (matching tailscale/wgengine/netstack_tcpbuf_default.go)
const (
	DefaultTCPTXBufMinSize = tcp.MinBufferSize            // 4 KB
	DefaultTCPTXBufDefSize = tcp.DefaultSendBufferSize    // 1 MB
	DefaultTCPTXBufMaxSize = 6 << 20                      // 6 MiB

	DefaultTCPRXBufMinSize = tcp.MinBufferSize            // 4 KB
	DefaultTCPRXBufDefSize = tcp.DefaultReceiveBufferSize // 1 MB
	DefaultTCPRXBufMaxSize = 8 << 20                      // 8 MiB
)

// Options specifies configuration for the userspace network stack.
type Options struct {
	// CongestionControl specifies the TCP congestion control algorithm (e.g. "cubic", "reno").
	// Defaults to "cubic".
	CongestionControl string

	// SendBufferSize specifies the TCP send buffer limits.
	// If zero-valued, defaults to Tailscale's standard (Min: 4KB, Default: 1MB, Max: 6MB).
	SendBufferSize tcpip.TCPSendBufferSizeRangeOption

	// ReceiveBufferSize specifies the TCP receive buffer limits.
	// If zero-valued, defaults to Tailscale's standard (Min: 4KB, Default: 1MB, Max: 8MB).
	ReceiveBufferSize tcpip.TCPReceiveBufferSizeRangeOption
}

// Option is a functional option for configuring CreateNetTUN.
type Option func(*Options)

// WithCongestionControl sets the TCP congestion control algorithm.
func WithCongestionControl(cc string) Option {
	return func(o *Options) {
		o.CongestionControl = cc
	}
}

// WithBufferSizes sets custom send and receive buffer size ranges.
func WithBufferSizes(tx tcpip.TCPSendBufferSizeRangeOption, rx tcpip.TCPReceiveBufferSizeRangeOption) Option {
	return func(o *Options) {
		o.SendBufferSize = tx
		o.ReceiveBufferSize = rx
	}
}

func defaultOptions() Options {
	return Options{
		CongestionControl: "cubic",
		SendBufferSize: tcpip.TCPSendBufferSizeRangeOption{
			Min:     DefaultTCPTXBufMinSize,
			Default: DefaultTCPTXBufDefSize,
			Max:     DefaultTCPTXBufMaxSize,
		},
		ReceiveBufferSize: tcpip.TCPReceiveBufferSizeRangeOption{
			Min:     DefaultTCPRXBufMinSize,
			Default: DefaultTCPRXBufDefSize,
			Max:     DefaultTCPRXBufMaxSize,
		},
	}
}

func applyOptions(s *stack.Stack, opts Options) error {
	if opts.CongestionControl != "" {
		ccOpt := tcpip.CongestionControlOption(opts.CongestionControl)
		if tcpipErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &ccOpt); tcpipErr != nil {
			return fmt.Errorf("set TCP congestion control %q: %v", opts.CongestionControl, tcpipErr)
		}
	}

	if opts.SendBufferSize.Max > 0 {
		if tcpipErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opts.SendBufferSize); tcpipErr != nil {
			return fmt.Errorf("set TCP send buffer size: %v", tcpipErr)
		}
	}

	if opts.ReceiveBufferSize.Max > 0 {
		if tcpipErr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opts.ReceiveBufferSize); tcpipErr != nil {
			return fmt.Errorf("set TCP receive buffer size: %v", tcpipErr)
		}
	}

	return nil
}
