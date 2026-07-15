package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// These values are replaced by release/build ldflags. The defaults keep local
// `go run` and unconfigured development builds explicit about their identity.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = ""
)

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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := runClient(ctx, flags); err != nil && !errors.Is(err, context.Canceled) {
		appLog.Error("fatal error", "error", err)
		os.Exit(1)
	}
	appLog.Info("Teleport client stopped")
}

func runClient(ctx context.Context, flags cliFlags) error {
	session, err := establishSession(ctx, flags)
	if err != nil {
		return err
	}
	reconnectBackoff := 2 * time.Second
	for attempt := 1; ; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		result, err := runConnectionAttempt(ctx, flags, &session, attempt)
		if result.printedConfig {
			return nil
		}
		if err != nil && errors.Is(err, context.Canceled) {
			return err
		}
		if !result.tunnelStarted {
			return err
		}
		if result.tunnelDuration >= 5*time.Minute {
			reconnectBackoff = 2 * time.Second
		}
		appLog.Warn("Teleport tunnel disconnected; renegotiating", "error", err, "backoff", reconnectBackoff)
		if !waitForContext(ctx, reconnectBackoff) {
			return ctx.Err()
		}
		reconnectBackoff *= 2
		if reconnectBackoff > 30*time.Second {
			reconnectBackoff = 30 * time.Second
		}
	}
}

type connectionAttemptResult struct {
	printedConfig  bool
	tunnelStarted  bool
	tunnelDuration time.Duration
}

func runConnectionAttempt(ctx context.Context, flags cliFlags, session *sessionResult, attempt int) (connectionAttemptResult, error) {
	priv, pub, err := wgKeypair()
	if err != nil {
		return connectionAttemptResult{}, err
	}

	// A fresh ICE/CONNECT exchange is required after known endpoints are
	// exhausted because the console's public UDP tuple may have changed.
	ice, err := fetchICEConfiguration(ctx, session.Token, session.Secret)
	if err != nil {
		return connectionAttemptResult{}, err
	}
	port := listenPort()
	sockets, err := openUDPSockets(port, flags.family)
	if err != nil {
		return connectionAttemptResult{}, err
	}
	defer sockets.Close()
	local := gatherLocalCandidates(sockets, port, flags.family, ice)
	if err := validateLocalCandidates(local, flags.family); err != nil {
		return connectionAttemptResult{}, err
	}

	stunSecret := randomB64(32)
	stunSecretHash := stunIntegrityKey(stunSecret)
	nomination := newNominationTracker()
	early := newEarlyNominationListener(sockets, stunSecretHash, nomination)
	early.Start()
	defer early.Stop()

	connResp, err := connectAndAwaitResponse(ctx, *session, flags.name, pub, stunSecret, local, ice, early)
	if err != nil {
		return connectionAttemptResult{}, err
	}
	endpoint, endpointMode, candidateQueue, candidateTypes, err := negotiateEndpoint(ctx, flags.endpointOverride, sockets, port, connResp, stunSecretHash, nomination, early, local)
	if err != nil {
		return connectionAttemptResult{}, err
	}

	conf := buildConfig(priv, port, endpoint, connResp.ServerInfo, connResp.DNSAddrs, connResp.ClientIP)
	appLog.Info("endpoint selected", "endpoint", endpoint, "mode", endpointMode, "connection_attempt", attempt)
	appLog.Debug("WireGuard peer configured", "public_key", connResp.ServerInfo.WGPubKey)
	if session.Access != nil {
		_, _ = apiRequestContext(ctx, "DELETE", "/"+session.Access.TeleportRequestID, session.DeviceToken, nil)
		session.Access = nil
	}

	if flags.printConfig {
		fmt.Print(conf)
		return connectionAttemptResult{printedConfig: true}, nil
	}

	early.Stop()
	tunnelStarted := time.Now()
	err = runTunnel(ctx, tunnelParams{
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
		candidateTypes: candidateTypes,
	})
	return connectionAttemptResult{
		tunnelStarted:  true,
		tunnelDuration: time.Since(tunnelStarted),
	}, err
}

func validateLocalCandidates(local []candidate, family networkFamily) error {
	if len(local) == 0 {
		return fmt.Errorf("no viable %s candidate on this host", family)
	}
	return nil
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
func establishSession(ctx context.Context, flags cliFlags) (sessionResult, error) {
	if flags.invite == "" {
		// Reconnect: reuse a previously granted session, skipping REQUEST_ACCESS
		// entirely, mirroring how the real client reconnects to an
		// already-added device.
		sess, err := loadSession(flags.sessionFile)
		if err != nil {
			return sessionResult{}, fmt.Errorf("no --invite given and failed to load session from %s: %w (run once with --invite to pair)", flags.sessionFile, err)
		}
		appLog.Info("reusing session", "path", flags.sessionFile, "saved_at", sess.SavedAt.Format(time.RFC3339))
		return sessionResult{Token: sess.SessionToken, Secret: sess.SessionSecret}, nil
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
	access, err := apiRequestContext(ctx, "POST", "/", "", accessBody)
	if err != nil {
		return sessionResult{}, err
	}

	poll, err := pollForResponseContext(ctx, token, access.TeleportRequestID, "ACCESS_GRANTED", 2*time.Second, 60, nil)
	if err != nil {
		return sessionResult{}, err
	}
	var sessionToken, sessionSecret string
	if poll != nil {
		sessionToken, sessionSecret = poll.Token, poll.Secret
	}
	if sessionToken == "" {
		return sessionResult{}, errors.New("timed out waiting for ACCESS_GRANTED")
	}
	appLog.Info("access granted", "client_id", clientID)

	if md, err := fetchMetadataContext(ctx, sessionToken); err == nil {
		appLog.Info("console metadata", "name", md.Metadata.Name, "wan_ip", md.Metadata.WanIP)
	} else {
		appLog.Warn("console metadata unavailable", "error", err)
	}
	if err := ctx.Err(); err != nil {
		return sessionResult{}, err
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

	return sessionResult{Token: sessionToken, Secret: sessionSecret, DeviceToken: token, Access: access}, nil
}

func fetchICEConfiguration(ctx context.Context, sessionToken, sessionSecret string) ([]iceServer, error) {
	iceBody := apiEnvelope{Token: sessionToken, Payload: map[string]interface{}{"request_type": "GET_ICE_CONFIGURATION", "secret": sessionSecret}}
	iceReq, err := apiRequestContext(ctx, "POST", "/", "", iceBody)
	if err != nil {
		return nil, err
	}

	poll, err := pollForResponseContext(ctx, sessionToken, iceReq.TeleportRequestID, "ICE_CONFIGURATION", responsePollInterval, 100, nil)
	if err != nil {
		return nil, err
	}
	var ice []iceServer
	if poll != nil {
		ice = poll.IceConfiguration
	}
	if len(ice) == 0 {
		return nil, errors.New("timed out waiting for ICE_CONFIGURATION")
	}
	_, _ = apiRequestContext(ctx, "DELETE", "/"+iceReq.TeleportRequestID, sessionToken, nil)
	return ice, nil
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
func connectAndAwaitResponse(ctx context.Context, session sessionResult, name, pub, stunSecret string, local []candidate, ice []iceServer, early *earlyNominationListener) (*apiResponse, error) {
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
	connectReq, err := apiRequestContext(ctx, "POST", "/", "", apiEnvelope{Token: session.Token, Payload: connectPayload})
	if err != nil {
		return nil, err
	}

	connResp, err := pollForResponseContext(ctx, session.Token, connectReq.TeleportRequestID, "CONNECT_RESPONSE", responsePollInterval, 200, func() {
		select {
		case nom := <-early.hints:
			// The real endpoint/mode is recovered from early.Logs() below once
			// CONNECT_RESPONSE arrives; this just surfaces early nomination
			// for visibility while the CONNECT poll loop keeps running.
			appLog.Debug("early nomination observed", "endpoint", nom.Endpoint, "mode", nom.Mode)
		default:
		}
	})
	if err != nil {
		return nil, err
	}
	if connResp == nil {
		return nil, errors.New("timed out waiting for CONNECT_RESPONSE")
	}
	_, _ = apiRequestContext(ctx, "DELETE", "/"+connectReq.TeleportRequestID, session.Token, nil)
	return connResp, nil
}

// negotiateEndpoint determines which candidate address to use as the
// WireGuard peer endpoint: an explicit --endpoint override, the master's
// per-tuple nomination sequence, an inbound Binding Request observed by the
// early listener, or — as a last resort — the late fallback listener in
// waitForNomination. It also returns the ranked queue of candidates that sent
// us a Binding Request, for the post-connect endpoint retry loop.
func negotiateEndpoint(ctx context.Context, endpointOverride string, sockets *udpSockets, port int, connResp *apiResponse, stunSecretHash string, nomination *nominationTracker, early *earlyNominationListener, local []candidate) (endpoint, mode string, candidateQueue []string, candidateTypes map[string]string, err error) {
	endpoint = endpointOverride
	mode = "override"

	peerCandidates := connResp.ServerInfo.PeerDesc.Candidates
	appLog.Info("peer candidates received", "count", len(peerCandidates))
	for _, c := range peerCandidates {
		appLog.Debug("peer candidate", "type", c.Type, "address", c.Addr)
	}

	stopCandidateProbes := startPeerCandidateProbes(sockets, peerCandidates, stunSecretHash)
	defer stopCandidateProbes()
	if endpoint == "" {
		// Activation allows a verified per-tuple sequence received before the
		// response to select an endpoint. The Android bridge waits up to 40s.
		nomination.activate()
		appLog.Debug("waiting for per-tuple nomination", "timeout", "40s")
		endpoint = nomination.waitForSelection(ctx, 40*time.Second)
		if err := ctx.Err(); err != nil {
			return "", "", nil, nil, err
		}
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
			selection := waitForNomination(ctx, sockets, port, peerCandidates, stunSecretHash, local)
			if err := ctx.Err(); err != nil {
				return "", "", nil, nil, err
			}
			endpoint = selection.Endpoint
			mode = selection.Mode
		}
	}
	stopCandidateProbes()
	if endpoint == "" {
		return "", "", nil, nil, errors.New("no endpoint candidate available")
	}
	early.Stop()
	candidateQueue = buildCandidateRetryQueue(endpoint, candidateQueue, compatibleCandidates(sockets, peerCandidates, local))
	candidateTypes = candidateTypeMap(peerCandidates)
	return endpoint, mode, candidateQueue, candidateTypes, nil
}

// candidateTypeMap maps each advertised candidate's address to its type
// (iface/reflex/turn) so the retry loop can size its per-candidate patience
// to how likely that address is to still be establishing a path (e.g. a TURN
// relay allocation) versus simply dead.
func candidateTypeMap(peerCandidates []candidate) map[string]string {
	types := make(map[string]string, len(peerCandidates))
	for _, c := range peerCandidates {
		types[c.Addr] = c.Type
	}
	return types
}

// buildCandidateRetryQueue preserves candidates that actually reached us
// first, then appends every compatible candidate advertised by the peer. A
// late/fallback selection may otherwise leave the retry queue empty even
// though the CONNECT_RESPONSE supplied viable alternatives.
func buildCandidateRetryQueue(endpoint string, observed []string, advertised []candidate) []string {
	seen := map[string]bool{endpoint: true}
	queue := make([]string, 0, len(observed)+len(advertised))
	appendCandidate := func(addr string) {
		if addr == "" || seen[addr] {
			return
		}
		seen[addr] = true
		queue = append(queue, addr)
	}
	for _, addr := range observed {
		appendCandidate(addr)
	}
	// Once observed candidates are exhausted, public reflexive/relay tuples
	// are materially more likely to work across networks than peer-private
	// interface addresses. Keep each group's existing rank stable.
	for _, public := range []bool{true, false} {
		for _, candidate := range advertised {
			if isPubliclyRoutableCandidateAddr(candidate.Addr) == public {
				appendCandidate(candidate.Addr)
			}
		}
	}
	return queue
}
