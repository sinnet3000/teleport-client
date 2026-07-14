package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/things-go/go-socks5"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// tunnelSocksResolver keeps SOCKS hostname resolution inside the Teleport
// netstack, rather than leaking it to the host's resolver. It follows the
// same userspace WireGuard pattern used by wireproxy.
type tunnelSocksResolver struct {
	net *netstack.Net
}

type loggedSocksConn struct {
	net.Conn
	network string
	target  string
}

func (c *loggedSocksConn) Close() error {
	appLog.Debug("SOCKS tunnel connection closed", "network", c.network, "target", c.target)
	return c.Conn.Close()
}

func (r tunnelSocksResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	appLog.Debug("SOCKS resolving hostname through tunnel", "hostname", name)
	addrs, err := r.net.LookupContextHost(ctx, name)
	if err != nil {
		return ctx, nil, err
	}
	// General internet egress through the tunnel is IPv4-only (see README);
	// an AAAA record here would dial out with no IPv6 route and hang until
	// TCP times out instead of failing fast. Skip IPv6 results.
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() == nil {
			continue
		}
		appLog.Debug("SOCKS resolved hostname through tunnel", "hostname", name, "address", ip.String())
		return ctx, ip, nil
	}
	return ctx, nil, fmt.Errorf("no IPv4 address found for %q", name)
}

func startSocks5Proxy(addr string, tunnelNet *netstack.Net) error {
	if tunnelNet == nil {
		return errors.New("SOCKS5 proxy requires a Teleport netstack")
	}
	if err := validateSocks5Addr(addr); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen SOCKS5 %s: %w", addr, err)
	}
	server := socks5.NewServer(
		socks5.WithDial(func(ctx context.Context, network, target string) (net.Conn, error) {
			appLog.Debug("SOCKS opening tunnel connection", "network", network, "target", target)
			if host, _, err := net.SplitHostPort(target); err == nil {
				if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
					err := fmt.Errorf("IPv6 egress %q not supported through this tunnel", target)
					appLog.Debug("SOCKS rejected IPv6 target", "target", target, "error", err)
					return nil, err
				}
			}
			conn, err := tunnelNet.DialContext(ctx, network, target)
			if err != nil {
				appLog.Debug("SOCKS tunnel connection failed", "network", network, "target", target, "error", err)
				return nil, err
			}
			appLog.Debug("SOCKS tunnel connection established", "network", network, "target", target)
			return &loggedSocksConn{Conn: conn, network: network, target: target}, nil
		}),
		socks5.WithResolver(tunnelSocksResolver{net: tunnelNet}),
		socks5.WithAuthMethods([]socks5.Authenticator{socks5.NoAuthAuthenticator{}}),
	)
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			appLog.Error("SOCKS5 proxy stopped", "error", err)
		}
	}()
	appLog.Info("SOCKS5 proxy listening", "address", listener.Addr().String(), "transport", "Teleport")
	return nil
}

func validateSocks5Addr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid SOCKS5 address %q: use HOST:PORT (IPv6 must be bracketed)", addr)
	}
	if host == "" {
		return errors.New("invalid SOCKS5 address: host is empty")
	}
	if err := validatePort(port); err != nil {
		return fmt.Errorf("invalid SOCKS5 address %q: %w", addr, err)
	}
	return nil
}

func validatePort(value string) error {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port %q must be between 1 and 65535", value)
	}
	return nil
}
