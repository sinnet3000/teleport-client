package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestAppLoggerLevelsAndRedaction(t *testing.T) {
	const secret = "do-not-log-this-token"
	var normal bytes.Buffer
	logger := newAppLogger(&normal, false)
	logger.Debug("hidden debug event", "value", "hidden")
	logger.Info("session event", "session_token", secret, "public_key", "safe-public-value")

	output := normal.String()
	if strings.Contains(output, "hidden debug event") {
		t.Fatal("normal logger emitted a debug event")
	}
	if strings.Contains(output, secret) {
		t.Fatal("normal logger exposed a sensitive value")
	}
	if !strings.Contains(output, `session_token=`+redactedLogValue) {
		t.Fatalf("normal logger did not redact the token: %q", output)
	}
	if !strings.Contains(output, "safe-public-value") {
		t.Fatalf("normal logger unexpectedly redacted a public value: %q", output)
	}

	var debug bytes.Buffer
	debugLogger := newAppLogger(&debug, true)
	debugLogger.Debug("visible debug event",
		"credential", secret,
		"stun_secret", secret,
		"private_key", secret,
		"authorization", secret,
	)
	if !strings.Contains(debug.String(), "visible debug event") {
		t.Fatalf("debug logger filtered a debug event: %q", debug.String())
	}
	if strings.Contains(debug.String(), secret) {
		t.Fatal("debug logger exposed a sensitive value")
	}
	if strings.Count(debug.String(), redactedLogValue) != 4 {
		t.Fatalf("debug logger did not redact every sensitive attribute: %q", debug.String())
	}
}

func TestWireGuardLoggerLevelSelection(t *testing.T) {
	var normal bytes.Buffer
	normalWG := newWireGuardLogger(newAppLogger(&normal, false), false)
	normalWG.Verbosef("handshake attempt %d", 1)
	normalWG.Errorf("handshake failed")
	if strings.Contains(normal.String(), "handshake attempt") {
		t.Fatal("normal WireGuard logger emitted verbose output")
	}
	if !strings.Contains(normal.String(), "handshake failed") {
		t.Fatalf("normal WireGuard logger dropped error output: %q", normal.String())
	}

	var debug bytes.Buffer
	debugWG := newWireGuardLogger(newAppLogger(&debug, true), true)
	debugWG.Verbosef("handshake attempt %d", 2)
	if !strings.Contains(debug.String(), "handshake attempt 2") {
		t.Fatalf("debug WireGuard logger dropped verbose output: %q", debug.String())
	}
}
