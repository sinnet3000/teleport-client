package main

import "testing"

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
