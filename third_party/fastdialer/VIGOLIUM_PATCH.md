# Vigolium fastdialer patch

Base: `github.com/projectdiscovery/fastdialer v0.5.25`, MIT (see `LICENSE.md`).
Source copied byte-for-byte from its Go module ZIP. This directory retains the
upstream `go.mod`, `go.sum`, README, production Go sources and package tests.
CI, examples, and the separate external-network `tests/` directory are omitted.
The root version-specific `go.mod` replacement applies to direct and transitive
consumers without changing the exported API or upgrading unrelated dependencies.

## First-connection errors must not become permanent reachability state

Upstream `utils.DialWrap.DialContext` replays the first non-cancellation error to
all later callers. The wrapper cache has no TTL; `ConnectionCacheExpiry` expires
successful prefetched sockets, not that error. A long-lived Vigolium server can
therefore keep declaring a recovered URL unreachable across native scans.

The changes in `fastdialer/dialer.go` and `fastdialer/dialer_private.go` evict only
the wrapper whose initial socket failure is identified by
`utils.ErrPortClosedOrFiltered`, after `dialIPS` completes. This call keeps its
original error and retry/fallback behavior. A later call builds a new wrapper
through normal cached-DNS lookup and IP/port/target validation. A private mutex
makes identity-checked eviction atomic with publication: a late failed caller
cannot remove a newer healthy wrapper. No lock is held while resolving DNS,
validating targets, dialing, waiting for connections or handshaking.

This does **not** add a retry loop, change HTTP retry counts, bypass preflight or
policy, purge DNS, replace the shared dialer, or close another scan's sockets.
Already-running callers can still receive their attempt's error. Healthy
wrappers, TLS-handshake failures and normal cancelled waiters are not evicted.
Successful first-socket handoff, validated-address selection, timeout counters,
contexts, TLS/session behavior, and proxy behavior remain unchanged.

A smaller candidate that changed `DialWrap` itself was rejected during testing:
it could activate a second real socket attempt in the existing ZTLS fallback
within the first plain-HTTP request. The final patch leaves `utils/dialwrap.go`
byte-identical to upstream and invalidates only after that call finishes.

## Local regressions

- `fastdialer/connection_recovery_test.go`: controlled no-route, refused,
  deadline and cancellation errors; still-failing sockets; eight concurrent
  recovery callers; cancelled/expired callers must not open a socket.
- `fastdialer/dialer_recovery_test.go`: literal and pinned hostname recovery;
  IP/port/validation policy rejection before any socket attempt; original
  single underlying socket attempt for the first failing call.
- `fastdialer/cache_eviction_test.go`: stale failed callers cannot evict a
  successor or unrelated destination; positive DNS is retained; mixed
  allowed/denied DNS answers stay filtered; positive wrappers stay cached.
- `fastdialer/cache_interleaving_test.go`: pause eviction after it reads the old
  pointer; the production publication helper must not Set before removal. A
  disposable unlocked mutation demonstrably loses the successor and fails.
- `fastdialer/inflight_recovery_test.go`: actually cancel/expire a dial blocked
  inside `ControlContext`, require a prompt error and a successful fresh caller.
- `fastdialer/nonpoisoning_errors_test.go`: a successful socket wrapper remains
  cached across certificate rejection, valid TLS recovery and cancellation.
- Vigolium `internal/runner/preflight_recovery_test.go`: failed preflight followed
  by independent HTTP200 and successful new scans over HTTP and HTTPS, borrowing
  the same dialer. Still-dead targets remain rejected.

The nested module's tests are not discovered by root `go test ./...`. From the
root, use its dependency graph and apply the CPU limits, one Go job at a time:

```sh
taskset -c 0,1 env GOMAXPROCS=2 GOFLAGS=-p=1 \
  go test -mod=readonly -short -race -parallel=1 -count=1 \
  -run '^(TestDialerConnectionRecovery|TestDialerInflightCancellationAndDeadlineRecover|TestDialerRecoveryAndPolicy|TestFailedWrapperEviction.*|TestRecoveryKeepsDNSAndFiltersDeniedAnswers|TestHandshakeAndCancellationKeepHealthyWrapper|TestDialWrapFirstDialOpensOneConnection|TestDialTLSHandshakeFailureNoGoroutineLeak)$' \
  github.com/projectdiscovery/fastdialer/fastdialer/utils \
  github.com/projectdiscovery/fastdialer/fastdialer
```

Upstream tests accessing public DNS/HTTP endpoints are deliberately not part of
the offline gate. A local gate is not full scan/deployment or overnight-stability
validation. DNS refresh, mutable validation callbacks on cache hits, and upstream
first-dial fan-out coordination are separate existing limitations; this patch
claims neither to fix nor newly guarantee them. Remove the replacement only
after a selected upstream release passes the recovery and neighboring tests.
