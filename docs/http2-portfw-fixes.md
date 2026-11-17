# HTTP/2 port-forwarding fixes in this fork

This fork is based on upstream usque v4.2.1 (6aa03fc97d12848dce34eedbd187fb1077b5d1ea). It contains the reliability and security fixes used for a standard-user Windows HTTP/2 forwarding setup. The Go module path remains unchanged so existing internal imports continue to build.

## Changes

- Keep one continuously draining TUN reader across reconnects. A bounded 1024-packet handoff matches the existing wireguard/netstack queue capacity. Full queues drop IP packets instead of deadlocking synchronous netstack replies. Connection workers finish before reconnect; the caller closes the device after maintenance returns.
- Retain the packet that triggers idle reconnect across failed dial attempts. Do not blindly replay attempted sends: completion can be ambiguous and the CONNECT-IP writer changes TTL/HopLimit in place.
- Use a one-use standard Go HTTP transport for each HTTP/2 tunnel. Keep endpoint ECDSA public-key pinning, including with empty SNI; require h2 ALPN on the outer MASQUE connection. Closed/rejected tunnel streams release their sockets. Cancellation is tested with an actual flow-control-stalled sender.
- Bind every forwarding listener before starting the tunnel. Roll back partial binds and report configuration/bind/accept failures through Cobra RunE. Stop accept loops on listener errors and observe unexpected maintenance termination.
- Remove the unrelated startup HTTP request for local-only forwarding. Remote forwarding retains a context-bound 30-second activation request.
- Strip Proxy-Authorization and Proxy-Connection from classic HTTP proxy requests before sending them to an origin.
- Update compatible x/net, x/text, x/crypto and x/sys dependencies. The module prefers the reviewed Go 1.27.4 toolchain; workflow files remain inherited from upstream.

## Build and verify

Use Go 1.27.4. The go.mod directive retains the upstream language compatibility level; it is not a recommendation to build with an unpatched compiler.

```sh
go mod verify
go build -trimpath ./...
go vet ./...
go test -timeout 45s ./...
```

There are 13 focused regression tests. They generate temporary dummy TLS keys and use local HTTP/2 servers or an in-process virtual network; they do not need a WARP registration or live Cloudflare access. Tests cover pin/ALPN rejection, socket cleanup, idle reconnects, failed-dial packet retention, synchronous reply draining, stalled-send cancellation, listener rollback/cancellation and origin header stripping. The original upstream code fails the socket-cleanup and idle-wakeup regressions.

The reviewed Windows build passed these checks, source/binary govulncheck scans, and live fixed-destination TLS/HTTP2 forwarding checks on 2026-11-16. These observations do not establish long-term stability, full native-device/proxy coverage, or absence of vulnerabilities. The inherited CI workflow targets Linux; consult the fork's Actions results for actual run status. Its compiler selection is not a claim about the security-reviewed local artifact. Release metadata points to this fork. No fork release workflow has been run and no fork release assets have been published.

## Scope and limits

The tested deployment uses explicit loopback listeners and fixed destinations. It does not require the official Cloudflare WARP desktop app, a system VPN adapter, a system proxy, host DNS changes or default-route changes. Native TUN, generic proxy exposure, executable hooks and insecure mode were outside that deployment.

The pinned CONNECT-IP fork still permits an authenticated MASQUE peer to accumulate a large incomplete capsule. Upstream release tooling also retains its existing mutable-tooling assumptions. These fixes are not a full dependency audit or a security guarantee. Keep WARP identity files private with restrictive filesystem permissions; no local identity, machine configuration or deployment logs are included in this repository.
