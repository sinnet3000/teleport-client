package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAPIRequestRejectsEmptyErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	if _, err := apiRequestAt(server.URL, http.MethodGet, "/", "", nil); err == nil {
		t.Fatal("apiRequest accepted an empty HTTP error response")
	}
}

func TestDebugAPIErrorResponseRedactsCredentials(t *testing.T) {
	const token = "session-token-value"
	const secret = "invite\"secret\\value\nwith-newline"
	const nestedSecret = "nested-sensitive-value"
	request := apiEnvelope{
		Token: token,
		Payload: map[string]any{
			"secret": secret,
			"authorization": map[string]any{
				"metadata": map[string]any{
					"value": nestedSecret,
				},
			},
		},
	}
	knownSecrets := append([]string{token}, collectSensitiveStrings(request)...)
	response, err := json.Marshal(map[string]any{
		"code":   "invalid_request",
		"detail": "request used " + token + ", " + secret + ", and " + nestedSecret,
		"error": map[string]any{
			"reason":     "invite rejected",
			"credential": "new-server-credential",
		},
		"secret":         "another-server-secret",
		"internal_debug": "must not be logged",
	})
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	debugAPIErrorResponse(newAppLogger(&output, true), "POST", "/", response, knownSecrets...)
	got := output.String()
	for _, forbidden := range []string{token, secret, nestedSecret, "new-server-credential", "another-server-secret", "must not be logged"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("debug API response exposed %q: %s", forbidden, got)
		}
	}
	for _, wanted := range []string{"invalid_request", "invite rejected", redactedLogValue} {
		if !strings.Contains(got, wanted) {
			t.Fatalf("debug API response omitted %q: %s", wanted, got)
		}
	}
}

func TestCollectSensitiveStringsTraversesSensitiveSubtrees(t *testing.T) {
	value := map[string]any{
		"authorization": map[string]any{
			"metadata": map[string]any{
				"value": "nested-value",
			},
			"parts": []any{"first-part", map[string]any{"value": "second-part"}},
		},
		"ordinary": "not-sensitive",
	}
	got := collectSensitiveStrings(value)
	for _, wanted := range []string{"nested-value", "first-part", "second-part"} {
		if !slices.Contains(got, wanted) {
			t.Fatalf("collectSensitiveStrings omitted %q: %v", wanted, got)
		}
	}
	if slices.Contains(got, "not-sensitive") {
		t.Fatalf("collectSensitiveStrings included an ordinary value: %v", got)
	}
}

func TestRedactKnownSecretsPrefersLongestMatch(t *testing.T) {
	got := redactKnownSecrets("value=long-secret", []string{"long", "long-secret"})
	if got != "value="+redactedLogValue {
		t.Fatalf("redactKnownSecrets = %q", got)
	}
}

func TestDebugAPIErrorResponseOmitsUnstructuredBody(t *testing.T) {
	const body = "plain-text response containing a credential"
	var output bytes.Buffer
	debugAPIErrorResponse(newAppLogger(&output, true), "GET", "/", []byte(body))
	if strings.Contains(output.String(), body) || strings.Contains(output.String(), "credential") {
		t.Fatalf("unstructured API body was logged: %s", output.String())
	}
	if !strings.Contains(output.String(), "not a JSON object") {
		t.Fatalf("omission reason was not logged: %s", output.String())
	}
}

func TestRedactAPIError(t *testing.T) {
	token := "token/with unsafe+characters"
	err := fmt.Errorf("GET https://example.test/?token=%s failed", url.QueryEscape(token))
	got := redactAPIError(err, token)
	if strings.Contains(got, token) || strings.Contains(got, url.QueryEscape(token)) {
		t.Fatalf("redactAPIError exposed token: %q", got)
	}
	if !strings.Contains(got, redactedLogValue) {
		t.Fatalf("redactAPIError did not mark redaction: %q", got)
	}
}

func TestAPIErrorTransientClassification(t *testing.T) {
	for _, tt := range []struct {
		name      string
		status    int
		transient bool
	}{
		{"network error", 0, true},
		{"server error", http.StatusInternalServerError, true},
		{"rate limited", http.StatusTooManyRequests, true},
		{"unauthorized", http.StatusUnauthorized, false},
		{"bad request", http.StatusBadRequest, false},
		{"not found", http.StatusNotFound, false},
	} {
		e := &apiError{StatusCode: tt.status, err: fmt.Errorf("boom")}
		if got := e.transient(); got != tt.transient {
			t.Fatalf("%s: transient() = %v, want %v", tt.name, got, tt.transient)
		}
	}
}

func TestPollForResponseRetriesTransientThenSucceeds(t *testing.T) {
	var calls int
	request := func(method, path, token string, body interface{}) (*apiResponse, error) {
		calls++
		if calls < 3 {
			return nil, &apiError{StatusCode: http.StatusServiceUnavailable, err: fmt.Errorf("unavailable")}
		}
		return &apiResponse{ResponseType: "READY"}, nil
	}

	poll, err := pollForResponseWith(request, "token", "req", "READY", time.Millisecond, 10, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if poll == nil || poll.ResponseType != "READY" {
		t.Fatalf("expected READY response, got %+v", poll)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls (2 transient failures + success), got %d", calls)
	}
}

func TestPollForResponseFailsFastOnPermanentError(t *testing.T) {
	var calls int
	request := func(method, path, token string, body interface{}) (*apiResponse, error) {
		calls++
		return nil, &apiError{StatusCode: http.StatusUnauthorized, err: fmt.Errorf("unauthorized")}
	}

	_, err := pollForResponseWith(request, "token", "req", "READY", time.Millisecond, 10, nil)
	if err == nil {
		t.Fatal("expected permanent error to be returned")
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 call for a permanent error, got %d", calls)
	}
}

func TestPollForResponseGivesUpAfterConsecutiveTransientErrors(t *testing.T) {
	var calls int
	request := func(method, path, token string, body interface{}) (*apiResponse, error) {
		calls++
		return nil, &apiError{StatusCode: http.StatusServiceUnavailable, err: fmt.Errorf("unavailable")}
	}

	_, err := pollForResponseWith(request, "token", "req", "READY", time.Millisecond, 100, nil)
	if err == nil {
		t.Fatal("expected error after exceeding consecutive transient failures")
	}
	if calls != maxConsecutivePollErrors {
		t.Fatalf("expected %d calls before giving up, got %d", maxConsecutivePollErrors, calls)
	}
}

func TestNormalizeInviteSecret(t *testing.T) {
	const uuid = "01234567-89ab-4def-8012-3456789abcde"
	for _, input := range []string{uuid, "  " + uuid + "  ", "https://teleport.ui.link/" + uuid} {
		got, err := normalizeInviteSecret(input)
		if err != nil || got != uuid {
			t.Fatalf("normalizeInviteSecret(%q) = (%q, %v), want (%q, nil)", input, got, err, uuid)
		}
	}
	for _, input := range []string{"not-an-invite", "https://example.com/" + uuid, "https://teleport.ui.link/not-a-uuid"} {
		if _, err := normalizeInviteSecret(input); err == nil {
			t.Fatalf("normalizeInviteSecret(%q) unexpectedly succeeded", input)
		}
	}
}
