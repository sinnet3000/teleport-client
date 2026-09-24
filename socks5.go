package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

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

type socks5Proxy struct {
	listener net.Listener
	done     chan struct{}
}

// socks5Auth is optional username/password authentication for the local
// SOCKS5 proxy. Zero value means NoAuth (the default).
type socks5Auth struct {
	user string
	pass string
}

func (a socks5Auth) enabled() bool {
	return a.user != ""
}

func socks5AuthMethods(auth socks5Auth) []socks5.Authenticator {
	if auth.enabled() {
		return []socks5.Authenticator{socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{auth.user: auth.pass},
		}}
	}
	return []socks5.Authenticator{socks5.NoAuthAuthenticator{}}
}

func (p *socks5Proxy) Close() error {
	if p == nil || p.listener == nil {
		return nil
	}
	err := p.listener.Close()
	if p.done != nil {
		<-p.done
	}
	return err
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

func startSocks5Proxy(addr string, auth socks5Auth, tunnelNet *netstack.Net) (*socks5Proxy, error) {
	if tunnelNet == nil {
		return nil, errors.New("SOCKS5 proxy requires a Teleport netstack")
	}
	if err := validateSocks5Addr(addr); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen SOCKS5 %s: %w", addr, err)
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
		socks5.WithAuthMethods(socks5AuthMethods(auth)),
	)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) {
			appLog.Error("SOCKS5 proxy stopped", "error", err)
		}
	}()
	if !auth.enabled() {
		if host, _, err := net.SplitHostPort(addr); err == nil && !isLoopbackBindHost(host) {
			appLog.Warn("SOCKS5 proxy bound to a non-loopback address with no authentication; any client that can reach this listener can use the tunnel",
				"address", listener.Addr().String())
		}
	}
	appLog.Info("SOCKS5 proxy listening", "address", listener.Addr().String(), "transport", "Teleport", "auth", authLogMode(auth))
	return &socks5Proxy{listener: listener, done: done}, nil
}

func authLogMode(auth socks5Auth) string {
	if auth.enabled() {
		return "userpass"
	}
	return "none"
}

// isLoopbackBindHost reports whether a SOCKS5 bind host only accepts local
// connections. Hosts are matched case-insensitively against "localhost" and
// IPv6 zone suffixes (e.g. %lo0) are ignored. Unparseable hostnames are
// treated as non-loopback so a surprising bind still gets the
// no-authentication warning.
func isLoopbackBindHost(host string) bool {
	// Trim the DNS root dot so "localhost." matches like "localhost".
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
