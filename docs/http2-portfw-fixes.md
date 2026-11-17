# HTTP/2 port-forwarding fixes in this fork

This fork is based on upstream usque v4.2.1 (6aa03fc97d12848dce34eedbd187fb1077b5d1ea). It contains the reliability and security fixes used for a standard-user Windows HTTP/2 forwarding setup. The Go module path remains unchanged so existing internal imports continue to build.

## Changes

- Keep one continuously draining TUN reader across reconnects. A bounded 1024-packet handoff matches the existing wireguard/netstack queue capacity. Full queues drop IP packets instead of deadlocking synchronous netstack replies. Connection workers finish before reconnect; the caller closes the device after maintenance returns.
- Retain the packet that triggers idle reconnect across failed dial attempts. Do not blindly replay attempted sends: completion can be ambiguous and the CONNECT-IP writer changes TTL/HopLimit in place.
- Use a one-use standard Go HTTP transport for each HTTP/2 tunnel. Keep endpoint ECDSA public-key pinning, including with empty SNI; require h2 ALPN on the outer MASQUE connection. Closed/rejected tunnel streams release their sockets. Cancellation is tested with an actual flow-control-stalled sender.
- Bind every forwarding listener before starting the tunnel. Roll back partial binds and report configuration/bind/accept failures through Cobra RunE. Stop accept loops on listener errors and observe unexpected maintenance termination.
- Remove the unrelated startup HTTP request for local-only forwarding. Remote forwarding retains a context-bound 30-second activation request.
- Adopt [upstream PR #137](https://github.com/Diniboy1123/usque/pull/137) for application HTTP proxy handling: reuse clients, bound custom DNS lookups, share TCP relay handling, preserve authentication-disabled behavior, and strip hop-by-hop headers from requests and responses. This supersedes the fork's original two-header filter; the source commit and author are preserved.
- Update compatible x/net, x/text, x/crypto and x/sys dependencies. The module prefers the reviewed Go 1.27.4 toolchain; workflow files remain inherited from upstream.

## Build and verify

Use Go 1.27.4. The go.mod directive retains the upstream language compatibility level; it is not a recommendation to build with an unpatched compiler.

```sh
go mod verify
go build -trimpath ./...
go vet ./...
go test -timeout 45s ./...
```

There are 16 focused regression tests: the fork's 13 tests plus PR #137's three authentication/header tests. They generate temporary dummy TLS keys and use local HTTP/2 servers or an in-process virtual network; they do not need a WARP registration or live Cloudflare access. Tests cover pin/ALPN rejection, socket cleanup, idle reconnects, failed-dial packet retention, synchronous reply draining, stalled-send cancellation, listener rollback/cancellation and origin header stripping. The original upstream code fails the socket-cleanup and idle-wakeup regressions.

The pre-adoption Windows build passed these checks, source/binary govulncheck scans, and live fixed-destination TLS/HTTP2 forwarding checks on 2026-11-16. These observations do not establish long-term stability, full native-device/proxy coverage, or absence of vulnerabilities. The inherited CI workflow targets Linux; consult the fork's Actions results for actual run status. Its compiler selection is not a claim about the security-reviewed local artifact. Release metadata points to this fork. No fork release workflow has been run and no fork release assets have been published.

PR #137 integration passes the test suite and vet with Go 1.27.4 on Windows/amd64. It has not been deployed or rescanned for vulnerabilities. Client pooling, CONNECT relay and custom DNS behavior have not been fully exercised end to end; the prior build's live validation does not establish those behaviors.

## Scope and limits

The tested deployment uses explicit loopback listeners and fixed destinations. It does not require the official Cloudflare WARP desktop app, a system VPN adapter, a system proxy, host DNS changes or default-route changes. Native TUN, generic proxy exposure, executable hooks and insecure mode were outside that deployment.

The pinned CONNECT-IP fork still permits an authenticated MASQUE peer to accumulate a large incomplete capsule. Upstream release tooling also retains its existing mutable-tooling assumptions. These fixes are not a full dependency audit or a security guarantee. Keep WARP identity files private with restrictive filesystem permissions; no local identity, machine configuration or deployment logs are included in this repository.

## Upstream coverage audit (2026-11-17)

The functional comparison is pinned to fork commit `d3c29e6723be3a09a3fbb83147823183eeed9b7e` against upstream `6aa03fc97d12848dce34eedbd187fb1077b5d1ea`. It changes 13 files. Every file is accounted for below; this is an inventory of submissions and retained choices, not a claim that every change has been submitted or merged.

### Submitted and existing work

- [#141](https://github.com/Diniboy1123/usque/pull/141): HTTP/2 socket ownership/cleanup and transport regressions.
- [#142](https://github.com/Diniboy1123/usque/pull/142), head `6e0202e`: startup configuration and bind errors, partial listener rollback, owner-close termination and normalized IPv6 binding. Startup failures now exit nonzero. The raw IPv6 mapping parser is unchanged.
- [#143](https://github.com/Diniboy1123/usque/pull/143): skip the activation website probe for nonempty local-only forwarding; preserve remote, mixed and zero-mapping behavior.
- [#144](https://github.com/Diniboy1123/usque/pull/144): minimum compiler/library security updates. It remains a draft dependent on #141; it does not duplicate that transport implementation.
- Existing [#137](https://github.com/Diniboy1123/usque/pull/137): adopted proxy/auth/header/client handling, with its author preserved. An additional origin-boundary regression is [offered as a test-only contribution](https://github.com/Diniboy1123/usque/pull/137#issuecomment-6956343154).
- Existing [#116](https://github.com/Diniboy1123/usque/pull/116): [targeted lifecycle tests and fixes](https://github.com/Diniboy1123/usque/pull/116#issuecomment-6956342342), retaining that PR's persistent-reader architecture. Related evidence was [shared on #103](https://github.com/Diniboy1123/usque/pull/103#issuecomment-6956342760), explicitly limited to incoming-packet back-pressure, not an ICMP-generation test or proof of a defect in #103. No competing reader PR was opened.

### File coverage

| File at the pinned fork snapshot | Disposition |
| --- | --- |
| `README.md` | Fork identification; retained here. |
| `api/masque.go` | #141. |
| `api/tunnel.go` | Demonstrated lifecycle fixes offered to #116; alternative fork architecture and hook/error policy retained. |
| `api/tunnel_test.go` | Transport cases in #141; lifecycle cases offered to #116. Fork-specific fixtures and organization retained. |
| `cmd/httpproxy.go` | Existing #137, adopted with original authorship. |
| `cmd/l4_http_proxy.go` | Existing #137. |
| `cmd/portfw.go` | #142 and #143; command supervision and policy differences listed below remain unsubmitted. |
| `cmd/portfw_test.go` | Startup cases in #142, origin case offered to #137; fork command-cancellation fixture retained with its lifecycle contract. |
| `cmd/proxy_helpers_test.go` | Existing #137. |
| `docs/http2-portfw-fixes.md` | Fork scope, validation and this coverage record; retained here. |
| `go.mod` | Minimum security updates in #144; existing pflag direct-use annotation in #142; later version preferences retained here. |
| `go.sum` | Security dependency closure in #144; later preferred versions retained here. |
| `goreleaser.yml` | Fork release ownership; retained here. |

### Intentionally retained or deferred

- **Reader implementation:** this fork's alternative packet/supervisor/cycle-context layout, stricter HTTP/2 failure handling and intentional-shutdown hook/log policy remain here. The demonstrated lifecycle fixes and regressions were adapted to #116 instead of submitting another implementation.
- **Command lifecycle:** `cmd.Context`, maintenance termination supervision and their command-cancellation test remain unsubmitted pending an agreed command lifecycle after #116. The current root execution path does not provide a cancellable SIGINT context. These differences are explicitly not claimed as upstream-covered.
- **Forwarding policy:** rejecting zero mappings, enforcing a hard 30-second context-bound remote activation deadline and returning on every accept error are fork choices. Upstream submissions preserve existing zero-mapping/remote activation behavior and transient accept retries. A portable activation cutoff has not been established for slow first connections.
- **Version preferences:** the Go 1.27.4 preference and newer x/net, x/crypto, x/sys and x/text versions remain fork build choices. #144 proposes the minimum fixed versions established by the recorded vulnerability scan.
- **Metadata and presentation:** fork branding, release owner, scope/validation notes, helper/test organization and log wording stay in this fork.

### Separate contribution branches and verification

The 13-file inventory describes the pinned functional snapshot only. These later contributions are on separate branches and have not been merged into fork main:

- #142: `fix/portfw-startup-errors` at `6e0202ecae0263c879346157fba0ff23d8b71afd`; includes new `cmd/portfw_startup_test.go` and the existing pflag dependency's direct annotation.
- #116 contribution: `contribute/tunnel-reader-regressions` at `3c3690be4dd974b1e859c95e611f70e77bc575c2`; includes `api/tunnel_lifecycle_test.go`. Original #116 fails all five local lifecycle fixtures; the contribution passes them. Its final H3 cancellation guard is defensive and has not been executed in an H3 test.
- #137 contribution: `contribute/proxy-origin-regression` at `ffa8019107b5ee01fe5a3ec326fa55216c65d897`; adds only `cmd/proxy_origin_test.go`, including import grouping. It changes no production proxy code. The test passes #137 and fails a deliberate request-filter omission.

Repeated shuffled tests pass with Go 1.26.3 on Windows/amd64; build, vet and golangci-lint checks pass for the submitted scopes. An actual startup-error CLI run prints one error and exits 1 without a usage dump. Claude Opus 5.5 independently reviewed the public changes; its startup visibility, test isolation and cancellation findings were resolved or verified. Native TUN, H3 execution and ICMP generation were not validated by these fixtures. GitHub CI still needs maintainer approval; local checks do not establish that CI passed. Upstream review and merges remain maintainer decisions.

This audit update changes this existing document only. It does not change the functional fork snapshot or deploy a new binary.
