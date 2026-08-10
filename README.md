# teleport-client

An experimental, reverse-engineered Go client for UniFi Teleport. It implements
the Teleport cloud exchange, authenticated STUN nomination, in-process
WireGuard, and a local SOCKS5 proxy.

This project is intended for interoperability research, experimentation, and
authorized use with systems you own or administer. It is unofficial,
unsupported, and may stop working if the underlying service or protocol
changes.

Users are responsible for ensuring that their use complies with applicable
laws, software licenses, service terms, and Ubiquiti terms.

It is primarily intended for headless systems and selective access through a
local SOCKS5 proxy without routing the entire host through the tunnel.

> **Notice of non-affiliation:** This project is not affiliated with, endorsed
> by, or officially connected to Ubiquiti Inc. UniFi and Teleport are
> trademarks of their respective owners.

## Repository layout

- `main.go`: CLI lifecycle and in-tunnel UDP echo loop.
- `api.go` and `session.go`: Teleport API exchange and local session state.
- `stun.go` and `nomination.go`: STUN mechanics and Teleport endpoint selection.
- `wireguard.go` and `socks5.go`: tunnel transport and local proxy integration.
- `*_test.go`: unit tests for the corresponding protocol components.
- `wireguard_integration_test.go`: offline integration tests against a real wireguard-go device and `wg` CLI (build tag `integration`).

## Requirements

- Go 1.25 or later (see `go.mod`)
- A reachable UniFi console with Teleport enabled
- A fresh `https://teleport.ui.link/<UUID>` invite for the first pairing

## Get a binary

Download a release binary, or build your own.

**Release**: grab `teleport-client_<os>_<arch>` (or `.exe` on Windows) for
your platform from the [GitHub Releases](https://github.com/sinnet3000/teleport-client/releases)
page, then `chmod +x` it (not needed on Windows).

**Build from source**:

```sh
git clone https://github.com/sinnet3000/teleport-client.git
cd teleport-client
make build   # cross-compiles all platforms into bin/
```

That fills `bin/` with a `teleport-client_<os>_<arch>` for each platform
listed in `PLATFORMS` in the `Makefile`. A few other targets:

```sh
make test    # go test ./...
make vet     # go vet ./...
make clean   # remove bin/
```

The commands below assume the binary is installed or renamed to
`teleport-client` and available on your `PATH`. You can also invoke a downloaded
or locally built binary by its path; the flags are the same.

## First connection

Use the UUID portion of a fresh invite. Store the resulting session JSON in a
private location; it contains credentials and must not be committed or shared.

```sh
teleport-client \
  --session-file ~/.config/teleport-client/session.json \
  --invite <uuid-or-url>
```

Leave that process running. You should see all of this in the output:

- `level=INFO msg="endpoint selected" ... mode=per_tuple_nomination`
- `level=INFO msg="WireGuard tunnel ready" ...`
- periodic `level=INFO msg="UDP echo statistics" ...` summaries
- `level=INFO msg="SOCKS5 proxy listening" address=127.0.0.1:1080 ...`

Stop it with Ctrl-C. The saved session remains available for reconnecting.

## Reconnect

Do not reuse the invite UUID. Reuse the saved session instead:

```sh
teleport-client \
  --session-file ~/.config/teleport-client/session.json
```

If a prior session no longer receives a console candidate, create a new invite
and run the first-connection command again with a new session-file path.

During startup, the client retries compatible observed and console-advertised
endpoints if the first WireGuard handshake does not complete. If an established
tunnel later stops answering its in-tunnel health probe for about one minute,
the client compares the probe failure with WireGuard handshake and receive
progress. It keeps a demonstrably active tunnel up if only the echo service is
unavailable; otherwise it automatically cycles the known compatible endpoints
with bounded backoff. If those endpoints remain unreachable, it closes the old
tunnel and performs a fresh ICE/CONNECT negotiation with the saved session so
the console can advertise a new UDP tuple. The SOCKS listener is recreated as
part of that recovery; existing connections cannot survive a broken tunnel.

## Use the SOCKS proxy

The proxy defaults to loopback and supports TCP CONNECT. `socks5h` resolves
hostnames inside the Teleport tunnel.

```sh
curl --proxy socks5h://127.0.0.1:1080 https://ipinfo.io/json
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

The proxy has no authentication. Binding it to a non-loopback address exposes
it to other hosts on that network. SOCKS UDP ASSOCIATE is not implemented.

## Address family

IPv4 and IPv6 are enabled by default. Restrict the outer connection with:

```sh
teleport-client -4 --session-file ~/.config/teleport-client/session.json
teleport-client -6 --session-file ~/.config/teleport-client/session.json
```

## Useful flags

- `--name <name>`: set the Teleport client name.
- `--debug`: enable debug logging.
- `--endpoint <host:port>`: force the WireGuard endpoint.
- `--turn`: require and use a console TURN relay.
- `--print-config`: print the WireGuard configuration and exit.
- `--socks5 <host:port>`: set the SOCKS5 listen address (default
  `127.0.0.1:1080`).

## Run as a service

Use the OS service manager to keep the client running. Pair once before you
install a service; the service reads the saved session on every start. Keep
invite URLs and session files out of service definitions.

### macOS (`launchd`)

Build the binary, copy the template, and replace `__USER__` with your account
name.

```sh
mkdir -p ~/.local/bin ~/.config/teleport-client ~/Library/LaunchAgents
go build -o ~/.local/bin/teleport-client .
cp deploy/launchd/com.example.teleport-client.plist \
  ~/Library/LaunchAgents/com.example.teleport-client.plist
sed -i '' "s/__USER__/$(id -un)/g" \
  ~/Library/LaunchAgents/com.example.teleport-client.plist
launchctl bootstrap "gui/$(id -u)" \
  ~/Library/LaunchAgents/com.example.teleport-client.plist
```

The agent starts at login and writes to `~/Library/Logs/teleport-client.log`.
To stop and remove it:

```sh
launchctl bootout "gui/$(id -u)" \
  ~/Library/LaunchAgents/com.example.teleport-client.plist
```

### Linux (`systemd --user`)

Install the binary at the path used by the unit, then enable the per-user
service:

```sh
go build -o teleport-client .
sudo install -m 0755 teleport-client /usr/local/bin/teleport-client
mkdir -p ~/.config/systemd/user ~/.config/teleport-client
cp deploy/systemd/teleport-client.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now teleport-client.service
```

On a server, enable lingering once so this user service starts after boot:

```sh
sudo loginctl enable-linger "$USER"
```

Check the service and follow its logs with:

```sh
systemctl --user status teleport-client.service
journalctl --user -u teleport-client.service -f
```

The unit reads `~/.config/teleport-client/session.json`. Pair with that path,
or change `--session-file` in your copied unit.

## Verification

```sh
go test ./...
go vet ./...
```
