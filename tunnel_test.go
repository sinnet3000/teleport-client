package main

import "testing"

func TestNextEndpointCandidateSkipsOnlyCurrentEndpoint(t *testing.T) {
	queue := []string{"", "candidate-a", "candidate-b", "candidate-c"}

	candidate, next, ok := nextEndpointCandidate(queue, 0, "candidate-a")
	if !ok || candidate != "candidate-b" || next != 3 {
		t.Fatalf("first fallback = (%q, %d, %v), want (%q, 3, true)", candidate, next, ok, "candidate-b")
	}

	candidate, next, ok = nextEndpointCandidate(queue, next, "candidate-b")
	if !ok || candidate != "candidate-c" || next != 4 {
		t.Fatalf("second fallback = (%q, %d, %v), want (%q, 4, true)", candidate, next, ok, "candidate-c")
	}

	if candidate, _, ok = nextEndpointCandidate([]string{"candidate-a"}, 0, "other"); !ok || candidate != "candidate-a" {
		t.Fatalf("queue head was incorrectly skipped: candidate=%q ok=%v", candidate, ok)
	}
}
