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
	ClientID      string    `json:"client_id"`
	InviteSecret  string    `json:"invite_secret"`
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

func saveSession(path string, s pairedSession) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
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
