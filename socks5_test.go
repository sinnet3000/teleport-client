package main

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/things-go/go-socks5"
)

const (
	socks5Ver            = 0x05
	socks5MethodNoAuth   = 0x00
	socks5MethodUserPass = 0x02
	socks5MethodNone     = 0xFF
	socks5AuthOK         = 0x00
)

func TestValidateSocks5Addr(t *testing.T) {
	for _, address := range []string{"127.0.0.1:1080", "[::1]:1080", "localhost:1080", "0.0.0.0:1080", "192.168.1.10:1080"} {
		if err := validateSocks5Addr(address); err != nil {
			t.Fatalf("validateSocks5Addr(%q): %v", address, err)
		}
	}
	for _, address := range []string{"", ":1080", "127.0.0.1:0", "127.0.0.1", "127.0.0.1:70000"} {
		if err := validateSocks5Addr(address); err == nil {
			t.Fatalf("validateSocks5Addr(%q) unexpectedly succeeded", address)
		}
	}
}

func TestIsLoopbackBindHost(t *testing.T) {
	for _, tt := range []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.53", true},
		{"::1", true},
		{"localhost", true},
		{"LocalHost", true},
		{"localhost.", true},
		{"::1%lo0", true},
		{"0.0.0.0", false},
		{"::", false},
		{"192.168.1.10", false},
		{"10.0.0.1", false},
		{"example.internal", false},
		{"", false},
	} {
		if got := isLoopbackBindHost(tt.host); got != tt.want {
			t.Fatalf("isLoopbackBindHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestSocks5AuthMethods(t *testing.T) {
	if (socks5Auth{}).enabled() {
		t.Fatal("zero socks5Auth should be disabled")
	}
	if !(socks5Auth{user: "a", pass: "b"}).enabled() {
		t.Fatal("user/pass socks5Auth should be enabled")
	}
	if got := authLogMode(socks5Auth{}); got != "none" {
		t.Fatalf("authLogMode(zero) = %q, want none", got)
	}
	if got := authLogMode(socks5Auth{user: "u", pass: "p"}); got != "userpass" {
		t.Fatalf("authLogMode(userpass) = %q, want userpass", got)
	}

	methods := socks5AuthMethods(socks5Auth{})
	if len(methods) != 1 {
		t.Fatalf("no-auth methods len = %d, want 1", len(methods))
	}
	if methods[0].GetCode() != (socks5.NoAuthAuthenticator{}).GetCode() {
		t.Fatalf("no-auth method code = %#x, want NoAuth", methods[0].GetCode())
	}

	methods = socks5AuthMethods(socks5Auth{user: "alice", pass: "secret"})
	if len(methods) != 1 {
		t.Fatalf("userpass methods len = %d, want 1", len(methods))
	}
	if methods[0].GetCode() != (socks5.UserPassAuthenticator{}).GetCode() {
		t.Fatalf("userpass method code = %#x, want UserPass", methods[0].GetCode())
	}
	up, ok := methods[0].(socks5.UserPassAuthenticator)
	if !ok {
		t.Fatalf("method type = %T, want UserPassAuthenticator", methods[0])
	}
	if !up.Credentials.Valid("alice", "secret", "") {
		t.Fatal("credentials should accept alice/secret")
	}
	if up.Credentials.Valid("alice", "wrong", "") {
		t.Fatal("credentials should reject wrong password")
	}
	if up.Credentials.Valid("bob", "secret", "") {
		t.Fatal("credentials should reject unknown user")
	}
}

// socks5Greet sends a method-selection greeting offering methods and returns
// the server's chosen method code (0xFF when none are acceptable).
func socks5Greet(t *testing.T, conn net.Conn, methods ...byte) byte {
	t.Helper()
	req := append([]byte{socks5Ver, byte(len(methods))}, methods...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read SOCKS5 method selection: %v", err)
	}
	if resp[0] != socks5Ver {
		t.Fatalf("SOCKS version = %#x, want %#x", resp[0], socks5Ver)
	}
	return resp[1]
}

// socks5UserPass performs the RFC 1929 sub-negotiation and returns the
// status byte (0 means success).
func socks5UserPass(t *testing.T, conn net.Conn, user, pass string) byte {
	t.Helper()
	if len(user) > 255 || len(pass) > 255 {
		t.Fatal("test credentials exceed RFC 1929 limits")
	}
	req := []byte{0x01, byte(len(user))}
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write SOCKS5 userpass: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read SOCKS5 userpass reply: %v", err)
	}
	if resp[0] != 0x01 {
		t.Fatalf("userpass version = %#x, want 0x01", resp[0])
	}
	return resp[1]
}

// startTestSocks5Server serves socks5AuthMethods(auth) on a loopback TCP
// listener without requiring a tunnel netstack (auth happens before CONNECT).
func startTestSocks5Server(t *testing.T, auth socks5Auth) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	server := socks5.NewServer(socks5.WithAuthMethods(socks5AuthMethods(auth)))
	go func() { _ = server.Serve(ln) }()
	return ln.Addr().String()
}

func dialTestSocks5(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS5: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	return conn
}

func TestSocks5HandshakeAuthRequired(t *testing.T) {
	const user, pass = "alice", "secret"
	auth := socks5Auth{user: user, pass: pass}

	t.Run("NoAuth-only client rejected", func(t *testing.T) {
		conn := dialTestSocks5(t, startTestSocks5Server(t, auth))
		if method := socks5Greet(t, conn, socks5MethodNoAuth); method != socks5MethodNone {
			t.Fatalf("selected method = %#x, want %#x (no acceptable methods)", method, socks5MethodNone)
		}
	})

	t.Run("wrong password rejected", func(t *testing.T) {
		conn := dialTestSocks5(t, startTestSocks5Server(t, auth))
		if method := socks5Greet(t, conn, socks5MethodUserPass); method != socks5MethodUserPass {
			t.Fatalf("selected method = %#x, want %#x", method, socks5MethodUserPass)
		}
		if status := socks5UserPass(t, conn, user, "wrong"); status == socks5AuthOK {
			t.Fatal("wrong password was accepted")
		}
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("expected server to close connection after failed auth")
		} else if err != io.EOF && err != io.ErrUnexpectedEOF {
			// RST on close is also acceptable teardown after auth failure.
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatalf("server kept connection open after failed auth (read timed out)")
			}
		}
	})

	t.Run("correct credentials accepted", func(t *testing.T) {
		conn := dialTestSocks5(t, startTestSocks5Server(t, auth))
		if method := socks5Greet(t, conn, socks5MethodUserPass); method != socks5MethodUserPass {
			t.Fatalf("selected method = %#x, want %#x", method, socks5MethodUserPass)
		}
		if status := socks5UserPass(t, conn, user, pass); status != socks5AuthOK {
			t.Fatalf("auth status = %#x, want %#x", status, socks5AuthOK)
		}
	})
}

func TestSocks5HandshakeNoAuth(t *testing.T) {
	conn := dialTestSocks5(t, startTestSocks5Server(t, socks5Auth{}))
	if method := socks5Greet(t, conn, socks5MethodNoAuth); method != socks5MethodNoAuth {
		t.Fatalf("selected method = %#x, want %#x", method, socks5MethodNoAuth)
	}
}
