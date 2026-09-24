package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSaveLoadSessionRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "session.json")
	want := pairedSession{
		SessionToken:  "token-value",
		SessionSecret: "secret-value",
		SavedAt:       time.Now().UTC().Truncate(time.Second),
	}
	if err := saveSession(path, want); err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	got, err := loadSession(path)
	if err != nil {
		t.Fatalf("loadSession: %v", err)
	}
	if got.SessionToken != want.SessionToken || got.SessionSecret != want.SessionSecret {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
	if !got.SavedAt.Equal(want.SavedAt) {
		t.Fatalf("SavedAt = %v, want %v", got.SavedAt, want.SavedAt)
	}
}

func TestSaveSessionUsesPrivateModeAndLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	if err := saveSession(path, pairedSession{SessionToken: "t", SessionSecret: "s"}); err != nil {
		t.Fatalf("saveSession: %v", err)
	}
	// Overwrite an existing session so the rename path is exercised.
	if err := saveSession(path, pairedSession{SessionToken: "t2", SessionSecret: "s2"}); err != nil {
		t.Fatalf("saveSession overwrite: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("session file mode = %04o, want 0600", perm)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "session.json" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory entries = %v, want only session.json", names)
	}
	got, err := loadSession(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionToken != "t2" || got.SessionSecret != "s2" {
		t.Fatalf("overwrite not visible: %+v", got)
	}
}

func TestSaveSessionOmitsUnusedCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := saveSession(path, pairedSession{SessionToken: "t", SessionSecret: "s"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"client_id", "invite_secret"} {
		if strings.Contains(string(data), key) {
			t.Fatalf("session file persisted unused credential %q: %s", key, data)
		}
	}
}

func TestLoadSessionAcceptsLegacyFileWithUnusedCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	legacy := `{"session_token":"t","session_secret":"s","client_id":"cid","invite_secret":"inv","saved_at":"2026-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadSession(path)
	if err != nil {
		t.Fatalf("loadSession rejected legacy session file: %v", err)
	}
	if got.SessionToken != "t" || got.SessionSecret != "s" {
		t.Fatalf("legacy load = %+v", got)
	}
}
