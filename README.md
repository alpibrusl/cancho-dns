<p align="center"><img src="docs/assets/cancho-dns-logo-256.png" alt="cancho-dns" width="200"></p>

# cancho-dns

[![ci](https://github.com/alpibrusl/cancho-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/alpibrusl/cancho-dns/actions/workflows/ci.yml)

**A DNS resolver you can audit, with an honest limit.** A forwarding and caching resolver written in
[cancho](https://github.com/alpibrusl/cancho): no `Ffi`, no `unsafe`, one thread, one poller, memory sized at
start, and an authority report the compiler writes and CI checks. It does **not** prove which upstreams it
reaches: a cancho program has one network bound shared by listening and dialling (measured,
[`docs/design.md`](docs/design.md) §2), so the upstream set is compiled in from `upstreams.conf` and enforced
in code before every query, and tested; the compiler does not vouch for it. A bug in the packet parser is a
bounds trap, not a memory-safety hole. The [project page](https://alpibrusl.github.io/cancho-dns/) has the
pictures.

**Status: v1 built and gated, not benchmarked against the incumbents on this host.** Every task of the epic
has its pull request and every gate is green in CI; ours' numbers are below and in
[`docs/numbers-d10.md`](docs/numbers-d10.md). The comparison against Unbound, dnsmasq, CoreDNS and Knot
Resolver runs where they are installed (CI installs them) and **no ratio is claimed here that was not
measured**. The plan and its tasks are in the epic, [cancho-dns#18](https://github.com/alpibrusl/cancho-dns/issues/18).

## What you get

* **A forwarding cache, bounded.** UDP and TCP on one poller, EDNS0, truncation; a cache with TTLs, negative
  caching and LRU eviction in a fixed arena; a 4 MiB cache stays 4 MiB, and the arenas are flat once warm
  (measured to the end: +0 KiB over four consecutive 150,000-query rounds).
* **Local answers, closed by default.** Records, overrides and blocklists compiled in from `local.conf` (at
  most 512 directives, every bound a generation-time refusal naming file and line); the access list allows
  loopback only until you open it, and a per-/24 response-rate limiter drops a flood.
* **Hard to poison.** A fresh source port and a random transaction id per upstream query, 0x20 case
  randomisation, strict question matching, bailiwick checks; a forged reply that fails any of them is
  dropped, and the spoofing harness sends wrong id, wrong case, wrong question and out-of-bailiwick records
  to prove none is cached.
* **Operable by an agent.** `introspect`, `skill`, `check`, `explain` and `diff` answer before the server
  binds -- byte-stable, validated against a published schema, the authority report embedded at a fixed point
  -- and every startup refusal is `{code, rule, message, hint, repair, detail}` with a stable rule tag. While
  it runs, `stats.bind` and `histogram.bind` (class CH) answer the counters and a latency histogram, and a
  query log -- one bounded JSON line on standard error, off by default because a name is personal data --
  says what happened to each query.
* **No files but its entropy source.** The authority row is `args, clock, heap, err_write, io_write,
  udp_recv, udp_send, conn_accept, conn_read, conn_write, poll, net_in(""), net_out(""),
  fs_read("/dev/urandom"), fs_read("conf/")` -- the last is `dns diff`'s two configuration files, and the
  row is diffed against a ceiling in CI, embedded by the manifest at a fixed point, and printed by
  `introspect`.

## Quick start (building from source)

You need `git`, Rust, Python 3 and dnspython (`pip install dnspython`).

```sh
git clone https://github.com/alpibrusl/cancho                           # the compiler
git clone https://github.com/alpibrusl/cancho-dns && cd cancho-dns
REV=$(sed -n 's/^ *CANCHO_REV: *//p' .github/workflows/ci.yml)          # the compiler these sources need
(cd ../cancho && git fetch -q origin && git checkout "$REV" && cargo build --release -p cancho)
export CANCHO=$PWD/../cancho/target/release/cancho

python3 tests/gen_local.py local.conf src/localtab.cho                  # the compiled-in tables
mkdir -p build
$CANCHO build --std src/server.cho src/dns.cho src/stub.cho src/cache.cho src/store.cho src/rng.cho \
    src/forward.cho src/upstreams.cho src/limit.cho src/access.cho src/local.cho src/localtab.cho \
    src/cli.cho src/rules.cho src/log.cho generated/built.cho -o build/server

build/server introspect | python3 -m json.tool | head                   # what it is, what it may touch
build/server check | python3 -m json.tool | head                        # the configuration it would run with
build/server explain www.example A                                     # what would happen to one query

build/server 5300 &                                                     # the resolver (loopback only, by default)
python3 -c 'import dns.query, dns.message; \
  print(dns.query.udp(dns.message.make_query("www.example", "A"), "127.0.0.1", port=5300).answer)'
```

With no upstream compiled in, the server answers from a test stub. Add one -- a line per upstream in
`upstreams.conf`, regenerated the same way -- and misses are forwarded with retries and health checks.

## Measured on ours, on one loopback host

([`docs/numbers-d10.md`](docs/numbers-d10.md), a cranelift build, this host; the release/LLVM build and the
incumbents' comparison are CI's on its pinned runner.)

| | |
|---|---|
| **~146,000 q/s** | answered on the cache-hit path, 64-deep pipeline |
| **~5,500 q/s** | forwarded to an instant local stub (the fresh-socket-per-query cost) |
| **~24,000 q/s** | over one persistent TCP connection |
| **0.06 ms** | p50 latency at half of the hit rate (p99 0.10 ms) |
| **228 KB / 8 ms** | the binary, and the time to be listening |
| **flat once warm** | RSS stops at the arena's size; +0 KiB over four consecutive 150,000-query rounds |

The incumbents are the yardsticks, with the cells pre-registered in the design (§8.1); the ratio is CI's to
measure, and losses will be reported as plainly as wins.

## We try to break it

* **20,006 random datagrams and 2,000 TCP frames** -- four byte distributions, every truncation of a valid
  query, frames split at random points -- **no trap**, and a valid query is answered afterwards.
* **Every limit at its edge**: a 4,096-byte TCP frame served and a 4,098-byte one closed; 140 connections
  against the 128 cap with UDP still answered; a silent client closed at the idle timeout; the cache's key
  cap evicting, never growing.
* **Six misbehaving upstreams** -- wrong case, unasked-for records, truncation without TC, oversized,
  garbage, silence -- each answered SERVFAIL or dropped, never a wrong answer, the resolver alive after each.
* **Amplification bounded**: an ANY query's answer and a 512-byte advertisement honoured; a garbage flood
  under a tight bucket answered **0 times** (garbage is never answered at all) with the drops counted.

**What the gates found, and what was done:**

* A question echo reading past a 32-byte message killed the server on the first `histogram.bind` -- fixed,
  and the gate that found it runs in CI.
* The "per-query memory leak" was the arena's first touch, not a leak: `VmData` constant while RSS grew,
  then +0 over 750,000 queries once the sweep had covered the arena. Issue #31, closed by the measurement.
* A dnspython release began refusing 17-hop pointer chains, moving a differential case between the gate's
  own columns; the gate's "the list cannot go stale" rule fired, and the case moved with the reason.
* The compiler cannot narrow a `Net` by direction or by set (measured, §2): the headline was corrected in
  place, and the language work was filed as [cancho#362](https://github.com/alpibrusl/cancho/issues/362).

## Intended scope, and what is not in v1

In v1: everything above, over UDP and TCP with EDNS0.

Not in v1: iterating from the root servers (a later stage), DNSSEC validation (stage 2; cancho has RSA,
ECDSA and Ed25519), DNS over TLS and HTTPS (TLS needs foreign code today, which would make the authority
report unbounded), zone transfers, dynamic update, views, clustering, serve-stale (RFC 8767: not claimed).
The RFC coverage table -- 1034/1035, 2181, 2308, 6891, 7766, 8020, each naming the gate that checks it --
is in [`docs/design.md`](docs/design.md) §20, checked for staleness in CI.

## Contributing

Design before code, in [`docs/design.md`](docs/design.md), with claims measured; a gate is fixed before the
code it judges and must be able to fail; a claim that turns out false is corrected in place. See the epic
for the working rules.

## Licence

[EUPL-1.2](LICENSE).
