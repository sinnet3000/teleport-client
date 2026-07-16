package main

import (
	"context"
	"net"
	"testing"
	"time"
)

// udpConnPair returns two loopback UDP conns connected to each other.
func udpConnPair(t *testing.T) (client *net.UDPConn, server *net.UDPConn) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { server.Close() })
	client, err = net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client, server
}

// withFastEchoTimeouts shrinks the package-level deadline vars for the
// duration of a test and restores them afterward.
func withFastEchoTimeouts(t *testing.T) {
	t.Helper()
	origDeadline, origRetry, origCeiling := steadyStateEchoDeadline, startupRetryInterval, startupCeiling
	steadyStateEchoDeadline = 20 * time.Millisecond
	startupRetryInterval = 20 * time.Millisecond
	startupCeiling = 100 * time.Millisecond
	t.Cleanup(func() {
		steadyStateEchoDeadline, startupRetryInterval, startupCeiling = origDeadline, origRetry, origCeiling
	})
}

func TestWaitForStartupResponseSurvivesInitialTimeout(t *testing.T) {
	withFastEchoTimeouts(t)
	client, server := udpConnPair(t)
	started := time.Now()

	go func() {
		time.Sleep(startupRetryInterval + 10*time.Millisecond)
		peer, _ := net.ResolveUDPAddr("udp4", client.LocalAddr().String())
		_, _ = server.WriteToUDP([]byte(`{"req_id":"0"}`), peer)
	}()

	buf := make([]byte, 2048)
	if !waitForStartupResponse(context.Background(), client, buf, 0, "0", started, nil) {
		t.Fatal("expected startup response to be matched after re-arming past the first timeout")
	}
	if time.Since(started) < startupRetryInterval {
		t.Fatal("response matched before the first deadline window elapsed; re-arming did not happen")
	}
}

func TestWaitForStartupResponseFailsFastOnHardError(t *testing.T) {
	withFastEchoTimeouts(t)
	client, _ := udpConnPair(t)
	client.Close()

	buf := make([]byte, 2048)
	start := time.Now()
	if waitForStartupResponse(context.Background(), client, buf, 0, "0", start, nil) {
		t.Fatal("expected startup wait on a closed connection to fail")
	}
	if elapsed := time.Since(start); elapsed >= startupCeiling {
		t.Fatalf("hard error should fail fast, not spin until the ceiling: %v", elapsed)
	}
}

func TestWaitForStartupResponseResendsAfterTimeout(t *testing.T) {
	withFastEchoTimeouts(t)
	client, server := udpConnPair(t)
	peer, err := net.ResolveUDPAddr("udp4", client.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	resends := 0
	resend := func() error {
		resends++
		_, err := server.WriteToUDP([]byte(`{"req_id":"0"}`), peer)
		return err
	}

	if !waitForStartupResponse(context.Background(), client, make([]byte, 2048), 0, "0", time.Now(), resend) {
		t.Fatal("expected startup response after retry callback")
	}
	if resends != 1 {
		t.Fatalf("startup resends = %d, want 1", resends)
	}
}

func TestWaitForSteadyStateResponseTimesOutOnce(t *testing.T) {
	withFastEchoTimeouts(t)
	client, _ := udpConnPair(t)
	start := time.Now()
	buf := make([]byte, 2048)
	if waitForSteadyStateResponse(context.Background(), client, buf, 1, "1") {
		t.Fatal("expected no response to time out")
	}
	if elapsed := time.Since(start); elapsed >= steadyStateEchoDeadline+startupRetryInterval {
		t.Fatalf("steady-state wait re-armed past a single deadline: %v", elapsed)
	}
}

func TestParseUDPEchoResponse(t *testing.T) {
	for _, tt := range []struct {
		body string
		want string
		ok   bool
	}{
		{`{"req_id":"42"}`, "42", true},
		{`{"req_id":42}`, "42", true},
		{`{"req_id":null}`, "", false},
		{`{"request_id":"42"}`, "", false},
		{`not json`, "", false},
	} {
		got, err := parseUDPEchoResponse([]byte(tt.body))
		if (err == nil) != tt.ok || got != tt.want {
			t.Fatalf("parseUDPEchoResponse(%s) = (%q, %v), want (%q, ok=%v)", tt.body, got, err, tt.want, tt.ok)
		}
	}
}

func TestUDPEchoStatsSummaryWindow(t *testing.T) {
	start := time.Unix(100, 0)
	stats := udpEchoStats{}
	if stats.observe(start, 50*time.Millisecond) {
		t.Fatal("first observation unexpectedly completed the summary window")
	}
	if stats.observe(start.Add(29*time.Second), 100*time.Millisecond) {
		t.Fatal("observation before 30 seconds completed the summary window")
	}
	if !stats.observe(start.Add(30*time.Second), 150*time.Millisecond) {
		t.Fatal("observation at 30 seconds did not complete the summary window")
	}
	if stats.count != 3 || stats.total != 300*time.Millisecond || stats.min != 50*time.Millisecond || stats.max != 150*time.Millisecond {
		t.Fatalf("unexpected statistics: %+v", stats)
	}
}

func TestUDPEchoHealthRequiresInitialResponse(t *testing.T) {
	health := udpEchoHealth{}
	if event, _ := health.observe(false); event != udpEchoStartupFailed {
		t.Fatalf("startup failure event = %v, want startup failure", event)
	}
}

func TestUDPEchoHealthDetectsSustainedLossAndResetsOnSuccess(t *testing.T) {
	health := udpEchoHealth{}
	if event, first := health.observe(true); event != udpEchoHealthy || !first {
		t.Fatalf("initial success = (%v, first=%v), want healthy first success", event, first)
	}
	for i := 0; i < maxConsecutiveEchoFailures-1; i++ {
		if event, _ := health.observe(false); event != 0 {
			t.Fatalf("failure %d emitted early event %v", i+1, event)
		}
	}
	if event, first := health.observe(true); event != udpEchoHealthy || first {
		t.Fatalf("recovery = (%v, first=%v), want non-first healthy event", event, first)
	}
	for i := 0; i < maxConsecutiveEchoFailures-1; i++ {
		if event, _ := health.observe(false); event != 0 {
			t.Fatalf("failure %d after reset emitted early event %v", i+1, event)
		}
	}
	if event, _ := health.observe(false); event != udpEchoUnhealthy {
		t.Fatalf("%d consecutive failures emitted %v, want unhealthy", maxConsecutiveEchoFailures, event)
	}
}
