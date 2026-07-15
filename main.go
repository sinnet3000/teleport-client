package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

var version = "v0.1.1"

// responsePollInterval is the poll interval Teleport's console-facing
// request/poll/delete cycle uses once past the initial ACCESS_GRANTED wait.
const responsePollInterval = 600 * time.Millisecond

// cliFlags holds the parsed and validated command-line configuration.
type cliFlags struct {
	invite           string
	name             string
	endpointOverride string
	printConfig      bool
	socks5Addr       string
	family           networkFamily
	debug            bool
	sessionFile      string
}

// sessionResult is what establishSession produces: either a freshly granted
// session (Access non-nil, so main can clean up the REQUEST_ACCESS request
// once done) or a reused one from a saved session file (Access nil).
type sessionResult struct {
	Token       string
	Secret      string
	DeviceToken string
	Access      *apiResponse
}

func main() {
	flags := parseFlags()
	appLog = newAppLogger(os.Stderr, flags.debug)

	fatal := func(err error) {
		if err != nil {
			appLog.Error("fatal error", "error", err)
			os.Exit(1)
		}
	}

	priv, pub, err := wgKeypair()
	if err != nil {
		panic(err)
	}

	session := establishSession(flags, fatal)

	// Request ICE configuration, then open one UDP socket per enabled
	// address family and gather interface plus server-reflexive candidates
	// from the returned STUN server.
	ice := fetchICEConfiguration(session.Token, session.Secret, fatal)

	port := listenPort()
	sockets, err := openUDPSockets(port, flags.family)
	fatal(err)
	local := gatherLocalCandidates(sockets, port, flags.family, ice)
	if flags.family != familyDual && len(local) == 0 {
		fatal(fmt.Errorf("no viable %s candidate on this host", flags.family))
	}

	stunSecret := randomB64(32)
	stunSecretHash := stunIntegrityKey(stunSecret)
	nomination := newNominationTracker()

	// The early listener begins answering the console's authenticated
	// nomination probes as soon as they arrive, which may be before
	// CONNECT_RESPONSE below.
	early := newEarlyNominationListener(sockets, stunSecretHash, nomination)
	early.Start()

	connResp := connectAndAwaitResponse(session, flags.name, pub, stunSecret, local, ice, early, fatal)

	endpoint, endpointMode, candidateQueue := negotiateEndpoint(flags.endpointOverride, sockets, port, connResp, stunSecretHash, nomination, early, local, fatal)

	conf := buildConfig(priv, port, endpoint, connResp.ServerInfo, connResp.DNSAddrs, connResp.ClientIP)
	appLog.Info("endpoint selected", "endpoint", endpoint, "mode", endpointMode)
	appLog.Debug("WireGuard peer configured", "public_key", connResp.ServerInfo.WGPubKey)
	if session.Access != nil {
		_, _ = apiRequest("DELETE", "/"+session.Access.TeleportRequestID, session.DeviceToken, nil)
	}

	if !flags.printConfig {
		early.Stop()
		runTunnel(tunnelParams{
			priv:           priv,
			port:           port,
			endpoint:       endpoint,
			connResp:       connResp,
			stunSecret:     stunSecret,
			stunSecretHash: stunSecretHash,
			sockets:        sockets,
			nomination:     nomination,
			socks5Addr:     flags.socks5Addr,
			debug:          flags.debug,
			candidateQueue: candidateQueue,
		}, fatal)
	} else {
		sockets.Close()
		fmt.Print(conf)
	}
}

// defaultClientName returns the local hostname for the --name default, so a
// fresh install reports its own device name to Teleport instead of every
// installation sharing the same placeholder. Falls back to a fixed name if
// the hostname can't be read.
func defaultClientName() string {
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		return hostname
	}
	return "Device"
}

func parseFlags() cliFlags {
	invite := flag.String("invite", "", "pair with a Teleport invite UUID or URL")
	name := flag.String("name", defaultClientName(), "set the client name")
	endpointOverride := flag.String("endpoint", "", "set the WireGuard endpoint")
	printConfig := flag.Bool("print-config", false, "print the WireGuard configuration and exit")
	socks5Addr := flag.String("socks5", "127.0.0.1:1080", "set the SOCKS5 listen address")
	forceIPv4 := flag.Bool("4", false, "use IPv4 only")
	forceIPv6 := flag.Bool("6", false, "use IPv6 only")
	debug := flag.Bool("debug", false, "enable debug logging")
	sessionFile := flag.String("session-file", "sessions/teleport-session.json", "read or save the session file")
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "teleport-client "+version)
		fmt.Fprintln(out, "\nUsage:")
		fmt.Fprintln(out, "  teleport-client --invite <uuid-or-url>")
		fmt.Fprintln(out, "  teleport-client --session-file <path>")
		fmt.Fprintln(out, "\nSession files contain credentials; do not commit or share them.")
		fmt.Fprintln(out)
		flag.PrintDefaults()
	}
	flag.Parse()

	failUsage := func(format string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, "error: "+format+"\n\n", args...)
		flag.Usage()
		os.Exit(2)
	}
	if len(flag.Args()) != 0 {
		failUsage("unexpected positional argument(s): %s", strings.Join(flag.Args(), " "))
	}
	if strings.TrimSpace(*name) == "" {
		failUsage("--name cannot be empty")
	}
	if len(*name) > 128 {
		failUsage("--name must be 128 characters or fewer")
	}
	if err := validateSocks5Addr(*socks5Addr); err != nil {
		failUsage("%v", err)
	}
	if *forceIPv4 && *forceIPv6 {
		failUsage("-4 and -6 are mutually exclusive")
	}
	if *endpointOverride != "" {
		host, port, err := net.SplitHostPort(*endpointOverride)
		if err != nil || host == "" {
			failUsage("--endpoint must be HOST:PORT (IPv6 must be bracketed)")
		}
		if err := validatePort(port); err != nil {
			failUsage("invalid --endpoint: %v", err)
		}
	}
	if *invite != "" {
		parsed, err := normalizeInviteSecret(*invite)
		if err != nil {
			failUsage("%v", err)
		}
		*invite = parsed
	} else {
		if *sessionFile == "" {
			failUsage("provide --invite for a fresh pairing or --session-file for reconnect")
		}
		info, err := os.Stat(*sessionFile)
		if err != nil {
			failUsage("cannot read session file %q: %v; provide --invite for a fresh pairing", *sessionFile, err)
		}
		if info.IsDir() {
			failUsage("--session-file %q is a directory", *sessionFile)
		}
	}

	// -4/-6 control which outer UDP sockets are opened and which candidate
	// families get advertised in CONNECT. With neither flag, family stays
	// dual and the console-selected nomination tuple decides the outer
	// family actually used.
	family := familyDual
	if *forceIPv4 {
		family = familyIPv4
	}
	if *forceIPv6 {
		family = familyIPv6
	}

	return cliFlags{
		invite:           *invite,
		name:             *name,
		endpointOverride: *endpointOverride,
		printConfig:      *printConfig,
		socks5Addr:       *socks5Addr,
		family:           family,
		debug:            *debug,
		sessionFile:      *sessionFile,
	}
}

// establishSession redeems a fresh invite via REQUEST_ACCESS when --invite is
// given, or reconnects using a previously saved session file, mirroring how
// the real client only redeems an invite once at add-device time and treats
// every later launch as a reconnect using the previously granted session.
func establishSession(flags cliFlags, fatal func(error)) sessionResult {
	if flags.invite == "" {
		// Reconnect: reuse a previously granted session, skipping REQUEST_ACCESS
		// entirely, mirroring how the real client reconnects to an
		// already-added device.
		sess, err := loadSession(flags.sessionFile)
		if err != nil {
			fatal(fmt.Errorf("no --invite given and failed to load session from %s: %w (run once with --invite to pair)", flags.sessionFile, err))
		}
		appLog.Info("reusing session", "path", flags.sessionFile, "saved_at", sess.SavedAt.Format(time.RFC3339))
		return sessionResult{Token: sess.SessionToken, Secret: sess.SessionSecret}
	}

	// Fresh pairing: redeem the invite once via REQUEST_ACCESS, then
	// persist the granted session so future runs can reconnect without
	// a new invite.
	token, err := secretToToken(flags.invite)
	if err != nil {
		panic(err)
	}
	clientID := randomUUID()

	accessBody := apiEnvelope{Token: token, Payload: map[string]interface{}{"request_type": "REQUEST_ACCESS", "secret": flags.invite, "client_id": clientID, "client_name": flags.name}}
	access, err := apiRequest("POST", "/", "", accessBody)
	fatal(err)

	poll, err := pollForResponse(token, access.TeleportRequestID, "ACCESS_GRANTED", 2*time.Second, 60, nil)
	fatal(err)
	var sessionToken, sessionSecret string
	if poll != nil {
		sessionToken, sessionSecret = poll.Token, poll.Secret
	}
	if sessionToken == "" {
		fatal(errors.New("timed out waiting for ACCESS_GRANTED"))
	}
	appLog.Info("access granted", "client_id", clientID)

	if md, err := fetchMetadata(sessionToken); err == nil {
		appLog.Info("console metadata", "name", md.Metadata.Name, "wan_ip", md.Metadata.WanIP)
	} else {
		appLog.Warn("console metadata unavailable", "error", err)
	}

	if flags.sessionFile != "" {
		if err := saveSession(flags.sessionFile, pairedSession{
			SessionToken:  sessionToken,
			SessionSecret: sessionSecret,
			ClientID:      clientID,
			InviteSecret:  flags.invite,
			SavedAt:       time.Now(),
		}); err != nil {
			appLog.Warn("failed to save session", "path", flags.sessionFile, "error", err)
		} else {
			appLog.Info("session saved", "path", flags.sessionFile)
		}
	}

	return sessionResult{Token: sessionToken, Secret: sessionSecret, DeviceToken: token, Access: access}
}

func fetchICEConfiguration(sessionToken, sessionSecret string, fatal func(error)) []iceServer {
	iceBody := apiEnvelope{Token: sessionToken, Payload: map[string]interface{}{"request_type": "GET_ICE_CONFIGURATION", "secret": sessionSecret}}
	iceReq, err := apiRequest("POST", "/", "", iceBody)
	fatal(err)

	poll, err := pollForResponse(sessionToken, iceReq.TeleportRequestID, "ICE_CONFIGURATION", responsePollInterval, 100, nil)
	fatal(err)
	var ice []iceServer
	if poll != nil {
		ice = poll.IceConfiguration
	}
	if len(ice) == 0 {
		fatal(errors.New("timed out waiting for ICE_CONFIGURATION"))
	}
	_, _ = apiRequest("DELETE", "/"+iceReq.TeleportRequestID, sessionToken, nil)
	return ice
}

// gatherLocalCandidates collects interface and server-reflexive candidates
// for the enabled address families. Reflexive gathering failures are logged
// and skipped rather than fatal: an interface candidate can still be
// nominated successfully.
func gatherLocalCandidates(sockets *udpSockets, port int, family networkFamily, ice []iceServer) []candidate {
	local := localCandidates(port, family)
	if family != familyIPv6 {
		if reflex, err := reflexiveCandidateFromConn(sockets.V4, ice, familyIPv4); err == nil {
			local = append(local, reflex)
		} else {
			appLog.Warn("IPv4 reflexive candidate unavailable", "error", err)
		}
	}
	if family != familyIPv4 {
		if reflex, err := reflexiveCandidateFromConn(sockets.V6, ice, familyIPv6); err == nil {
			local = append(local, reflex)
		} else {
			// IPv6 server-reflexive candidates are optional: a public interface
			// candidate can still be nominated successfully. In particular, the
			// supplied STUN hostname may be IPv4-only, which is not a tunnel
			// failure and should not make normal -6 output look broken.
			appLog.Debug("IPv6 reflexive candidate unavailable", "error", err)
		}
	}
	appLog.Info("candidate gathering complete", "family", family.String(), "count", len(local))
	for _, c := range local {
		appLog.Debug("local candidate", "type", c.Type, "address", c.Addr)
	}
	return local
}

// connectAndAwaitResponse sends CONNECT with the gathered candidates and
// polls for CONNECT_RESPONSE.
func connectAndAwaitResponse(session sessionResult, name, pub, stunSecret string, local []candidate, ice []iceServer, early *earlyNominationListener, fatal func(error)) *apiResponse {
	connectPayload := map[string]interface{}{
		"request_type": "CONNECT",
		"secret":       session.Secret,
		"client_name":  name,
		"client_info": map[string]interface{}{
			"wg_pub_key":          pub,
			"stun_session_secret": stunSecret,
			"peer_desc":           peerDesc{Candidates: local, IceConfig: ice, IsMaster: false},
		},
	}
	connectReq, err := apiRequest("POST", "/", "", apiEnvelope{Token: session.Token, Payload: connectPayload})
	fatal(err)

	connResp, err := pollForResponse(session.Token, connectReq.TeleportRequestID, "CONNECT_RESPONSE", responsePollInterval, 200, func() {
		select {
		case nom := <-early.hints:
			// The real endpoint/mode is recovered from early.Logs() below once
			// CONNECT_RESPONSE arrives; this just surfaces early nomination
			// for visibility while the CONNECT poll loop keeps running.
			appLog.Debug("early nomination observed", "endpoint", nom.Endpoint, "mode", nom.Mode)
		default:
		}
	})
	fatal(err)
	if connResp == nil {
		fatal(errors.New("timed out waiting for CONNECT_RESPONSE"))
	}
	_, _ = apiRequest("DELETE", "/"+connectReq.TeleportRequestID, session.Token, nil)
	return connResp
}

// negotiateEndpoint determines which candidate address to use as the
// WireGuard peer endpoint: an explicit --endpoint override, the master's
// per-tuple nomination sequence, an inbound Binding Request observed by the
// early listener, or — as a last resort — the late fallback listener in
// waitForNomination. It also returns the ranked queue of candidates that sent
// us a Binding Request, for the post-connect endpoint retry loop.
func negotiateEndpoint(endpointOverride string, sockets *udpSockets, port int, connResp *apiResponse, stunSecretHash string, nomination *nominationTracker, early *earlyNominationListener, local []candidate, fatal func(error)) (endpoint, mode string, candidateQueue []string) {
	endpoint = endpointOverride
	mode = "override"

	peerCandidates := connResp.ServerInfo.PeerDesc.Candidates
	appLog.Info("peer candidates received", "count", len(peerCandidates))
	for _, c := range peerCandidates {
		appLog.Debug("peer candidate", "type", c.Type, "address", c.Addr)
	}

	stopCandidateProbes := startPeerCandidateProbes(sockets, peerCandidates, stunSecretHash)
	if endpoint == "" {
		// Activation allows a verified per-tuple sequence received before the
		// response to select an endpoint. The Android bridge waits up to 40s.
		nomination.activate()
		appLog.Debug("waiting for per-tuple nomination", "timeout", "40s")
		endpoint = nomination.waitForSelection(40 * time.Second)
		if endpoint != "" {
			mode = "per_tuple_nomination"
		} else {
			appLog.Debug("per-tuple nomination wait timed out")
		}

		nominationPackets := early.Logs()
		if len(nominationPackets) > 0 {
			seenCandidates := make(map[string]bool)
			for _, p := range nominationPackets {
				if p.Direction == "in" && p.STUN && p.STUNType == "Binding request" {
					if !seenCandidates[p.Addr] {
						seenCandidates[p.Addr] = true
						candidateQueue = append(candidateQueue, p.Addr)
					}
					if endpoint == "" {
						endpoint = p.Addr
						mode = "inbound_binding_request"
					}
				}
			}
		}
		if endpoint == "" {
			early.Stop()
			selection := waitForNomination(sockets, port, peerCandidates, stunSecretHash, local)
			endpoint = selection.Endpoint
			mode = selection.Mode
		}
	}
	stopCandidateProbes()
	if endpoint == "" {
		fatal(errors.New("no endpoint candidate available"))
	}
	early.Stop()
	return endpoint, mode, candidateQueue
}
