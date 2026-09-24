package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"
)

// pairedSession is the persisted result of a successful fresh-invite pairing
// (REQUEST_ACCESS -> ACCESS_GRANTED). Saving it lets subsequent runs skip
// straight to GET_ICE_CONFIGURATION/CONNECT, mirroring how the real client
// only redeems a teleport.ui.link invite once at add-device time and treats
// every later launch as a reconnect using the previously granted session.
type pairedSession struct {
	SessionToken  string    `json:"session_token"`
	SessionSecret string    `json:"session_secret"`
	SavedAt       time.Time `json:"saved_at"`
}

func loadSession(path string) (*pairedSession, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s pairedSession
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.SessionToken == "" || s.SessionSecret == "" {
		return nil, errors.New("session file missing session_token/session_secret")
	}
	return &s, nil
}

// saveSession writes s to path atomically: data goes to a temp file in the
// same directory (mode 0600), is fsynced, then renamed over path. A crash
// mid-write can therefore never leave a truncated session file, and the
// credentials-bearing file is never created with looser permissions.
func saveSession(path string, s pairedSession) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	// fsync the directory so the rename itself survives power failure.
	// Best-effort: some platforms cannot fsync a directory handle, and a
	// failed durability sync must not fail an already committed save.
	if d, err := os.Open(dir); err != nil {
		appLog.Debug("session directory open for fsync failed", "dir", dir, "error", err)
	} else {
		if err := d.Sync(); err != nil {
			appLog.Debug("session directory fsync failed", "dir", dir, "error", err)
		}
		_ = d.Close()
	}
	return nil
}

type packetLog struct {
	Direction string `json:"direction"`
	Addr      string `json:"addr"`
	Length    int    `json:"length"`
	PrefixHex string `json:"prefix_hex"`
	STUN      bool   `json:"stun"`
	STUNType  string `json:"stun_type,omitempty"`
}

func logPacket(direction string, addr *net.UDPAddr, data []byte) packetLog {
	prefixLen := len(data)
	if prefixLen > 12 {
		prefixLen = 12
	}
	entry := packetLog{Direction: direction, Length: len(data), PrefixHex: hex.EncodeToString(data[:prefixLen])}
	if addr != nil {
		entry.Addr = addr.String()
	}
	if msg, ok := parseStunMessage(data); ok {
		entry.STUN = true
		entry.STUNType = msg.Type.String()
	}
	return entry
}
