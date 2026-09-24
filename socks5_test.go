package main

import (
	"testing"

	"github.com/things-go/go-socks5"
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

func TestSocks5AuthEnabled(t *testing.T) {
	if (socks5Auth{}).enabled() {
		t.Fatal("zero socks5Auth should be disabled")
	}
	if !(socks5Auth{user: "a", pass: "b"}).enabled() {
		t.Fatal("user/pass socks5Auth should be enabled")
	}
}

func TestSocks5AuthMethods(t *testing.T) {
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

func TestAuthLogMode(t *testing.T) {
	if got := authLogMode(socks5Auth{}); got != "none" {
		t.Fatalf("authLogMode(zero) = %q, want none", got)
	}
	if got := authLogMode(socks5Auth{user: "u", pass: "p"}); got != "userpass" {
		t.Fatalf("authLogMode(userpass) = %q, want userpass", got)
	}
}
