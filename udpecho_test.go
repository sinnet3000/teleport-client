package main

import (
	"testing"
	"time"
)

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
