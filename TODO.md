# Engineering Roadmap & Future Optimizations

This document tracks upcoming performance optimizations, systems enhancements, and architectural upgrades for `teleport-client`.

---

## 1. Vectorized UDP Batching on Linux (`recvmmsg` / `sendmmsg`)

### Status: Backlog / Planned
Currently, `stunBind.BatchSize()` returns `1`, and both `makeRecvFunc` and `Send()` perform single-packet reads and writes via `*net.UDPConn` (`ReadFromUDPAddrPort` and `WriteToUDPAddrPort`). 

While this eliminated the unused 128-slot allocation overhead in `wireguard-go`, implementing true vectorized batching on Linux will significantly reduce user-to-kernel context switches under high-throughput transfers.

### Implementation Blueprint:
1. **Socket Wrapping:**
   - Wrap `conn4` and `conn6` using `ipv4.NewPacketConn(c)` / `ipv6.NewPacketConn(c)` from `golang.org/x/net`.
   - Maintain pre-allocated `[]ipv4.Message` and `[]ipv6.Message` descriptors per receive/send worker.
2. **Batch Receive & Inline STUN Demuxing:**
   - In `makeRecvFunc`: Call `ReadBatch(msgs, 0)` to pull up to `conn.IdealBatchSize` (32 or 128) datagrams in a single `recvmmsg` syscall.
   - Iterate through the received batch:
     - Check each buffer with `isSTUN(buf)`.
     - If STUN: dispatch `handleSTUN()` immediately inline.
     - If WireGuard: compact the packet into the active slice returned to `wireguard-go`.
     - If the entire batch consisted of STUN packets, loop to refill without returning empty slices to WireGuard.
3. **Batch Transmit:**
   - In `Send(bufs [][]byte, ep conn.Endpoint)`: `wireguard-go` already delivers outgoing packets pre-batched per destination peer.
   - Use `WriteBatch(msgs, 0)` to send the full slice of buffers in a single `sendmmsg` syscall.
   - Handle partial writes by advancing the offset slice until all buffers are drained.
4. **Activation:**
   - Re-enable `conn.IdealBatchSize` in `stunBind.BatchSize()` for Linux/Android once the vector I/O loop is verified.
   - *(Optional future step)*: Evaluate UDP GSO/GRO (`UDP_SEGMENT` / `UDP_GRO`) offload if CPU bottlenecks emerge at gigabit speeds.

---

## 2. Userspace `netstack` TCP Window & Buffer Tuning

### Status: Completed
Implemented in `internal/tunnet/` following Tailscale's production blueprint:
- Vendored and wrapped `wireguard-go/tun/netstack` to expose gVisor TCP configuration hooks.
- Upgraded `gvisor.dev/gvisor` to Tailscale's pinned revision (`v0.0.0-20260915211658-a6f909f08a72`) containing upstream CUBIC growth-credit and ingress ACK timing fixes.
- Switched default TCP congestion control to **CUBIC** (with `TELEPORT_TCP_CONGESTION_CONTROL` env override).
- Configured dynamic auto-tuning TCP buffer limits using Tailscale defaults:
  - TX Buffer: Min 4 KB, Default 1 MB, Max 6 MB
  - RX Buffer: Min 4 KB, Default 1 MB, Max 8 MB

---

## 3. SOCKS5 Relay Buffer Pooling

### Status: Low Priority / Quality-of-Life
* `github.com/things-go/go-socks5` uses standard `io.Copy(dst, src)` for bi-directional streaming between the local TCP client and `tunnelNet.DialContext`.
* Under heavy concurrent connections (e.g., modern web browsers opening 40+ parallel TCP sockets per domain), `io.Copy` allocates a 32 KB buffer per stream.
* Introducing a `sync.Pool` for 32 KB relay buffers in the SOCKS handler can further minimize transient heap churn during heavy browser usage.
