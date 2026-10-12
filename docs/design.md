# cancho-dns: a forwarding and caching resolver in cancho

Status: **design (task #1 of the epic, [#18](https://github.com/alpibrusl/cancho-dns/issues/18)); D0, the codec (section 12), D1, the UDP and TCP server (section 13), and D2, the cache (section 14), and D3, the forwarder (section 15), and D3b, the access list and rate limiter (section 16), are built; the benchmark is not.** **Confirmed by the maintainer on
2026-10-07:** the v1 claim and the compiled-in upstream table (section 3), the proposed limits, policy values and benchmark criteria (sections 5, 6
and 8, still labelled *proposed* below because they are values, not measurements; they are now fixed, and changing one is a change to this
document, made in place with the reason), and filing the cancho prerequisite ([alpibrusl/cancho#362](https://github.com/alpibrusl/cancho/issues/362)).
A gate is fixed before the code it judges, so none of them moves to suit a result. The measurements in section 2 were taken on cancho at `alpibrusl/cancho@0567e72` (after its UDP work,
`docs/udp.md`).

## 1. What this is for, and the claim it must survive

A DNS resolver that forwards to a configured set of upstream resolvers and caches: UDP and TCP on one poller, a cache in a fixed arena,
strict bounded parsing, no `Ffi`, no `unsafe`, one thread. Its popular peers are C programs with a long record of parser memory-safety bugs,
and a cache that an attacker wants to poison. The model is [cancho-cache](https://github.com/alpibrusl/cancho-cache): fix the gate first,
build the smallest thing, measure, report losses as plainly as wins.

The README's first draft made a stronger claim than this section can: that the authority report would **name the exact upstreams** the
program can reach. Section 2 measures why cancho cannot say that today, and section 3 says what this project claims instead. **The README
and the project page are corrected in place by the same change that adds this document.**

The performance claim is modest and stated before measuring: a DNS packet is tiny, so throughput is bounded by the kernel as much as by us.
The aim is **parity per core with much lower memory**. A big speed win is not the claim.

## 2. What the compiler can and cannot prove about the network (measured)

The epic asked task #1 to settle how an upstream set becomes a literal. Before choosing, three facts about `Net` were checked against the
real compiler (`cancho build`, `cancho authority`; programs under "Reproduce" below).

1. **A `Net` is narrowed once.** `narrow` consumes the capability. Narrowing the same `net` to a second literal is refused:
   `` `net` has already been consumed; a `res` value is used exactly once ``. One program therefore holds **one** bound.
2. **That one bound string serves both directions, and the two shapes do not mix.** Outbound reads it as `host:port`, inbound reads it as a
   port. With `Net("127.0.0.1:5353")`, `udp_bind` traps; with `Net("5353")`, `udp_connect` traps. Only the unnarrowed `Net("")` allowed both,
   and the report then reads `net_in("")` and `net_out("")`. **A resolver needs both** (it listens on 53 and sends to upstreams), so it
   cannot carry a narrowed `Net` at all.
3. **The host half of a bound is a plain prefix.** Under `Net("127.0.0.1:5353")`, `udp_connect(n, "127.0.0.10", 5353)` was **not** refused,
   and the report still printed `net_out("127.0.0.1:5353")`. By the code of `checked_host` the same holds for names: the bound
   `ns1.example.com` admits `ns1.example.com.attacker.net`. (Exercised for the IP-literal case; the name case is from reading the code.) The
   report's `"bounded": true` also reads true for the empty bound, so what that flag means must be confirmed with cancho's maintainers
   before the report is quoted as a proof of anything.

Consequence: **with cancho as it is, no compiler-checked statement of the form "this program reaches only upstreams U1..Un" can be made for
a forwarding resolver**, by a generator, by a hybrid, or by any layout of one binary. The epic's question is answered by the language, not by
a design choice here.

What cancho would need, filed as a prerequisite: [alpibrusl/cancho#362](https://github.com/alpibrusl/cancho/issues/362) (the same way UDP was, #355):

* separate inbound and outbound bounds (two capabilities from `split`, or two bounds on one `Net`);
* a bound that is a **set** of hosts (there is precedent: `Signals` narrows as a set, `docs/signals.md` §2.1);
* host matching that is exact, or has a boundary, instead of a bare prefix.

Two askers are the repository's bar for a feature (`docs/standard-library.md`); cancho-dns is one, and any proxy that listens and dials
(`cancho-pg`, a connection pooler) is another.

## 3. Decision (proposed): what v1 claims, and how upstreams are held

**v1 holds an unnarrowed `Net` and enforces the upstream set in code from a table.** The table is **compiled in**: a generator turns a
checked configuration file into a `static` table and the build is one binary per deployment. This keeps `fs_read` out of the row apart from
the entropy source (a run-time config file would add a path to the report), and it gives `check`, `explain` and CI one artefact to diff.

What the authority report then **does** prove, and the only thing the README may say:

* no `Ffi`, no `unsafe`, no process, no signal handling in v1;
* no file is written; the only file read is the entropy source (section 7);
* the network authority is the whole network (`net_in("")`, `net_out("")`), so **which hosts the program sends to is a property of its code
  and its table, not of the compiler**; the table is what `check` and `explain` print, and a test asserts that the only `udp_connect` and
  `tcp_connect` calls in the source take their host from it (a grep-level gate: weak, and called weak).

When cancho can bound a `Net` by set and by direction (section 2), the table moves into the type and the original headline becomes true.
Until then it is a target, and the page says so.

Alternatives considered and rejected: a bound of a covering prefix such as `10.0.0.:53` (cannot also bind port 53, fact 2; and prefix-matches
neighbours, fact 3); two cooperating processes, a listener with `Net("53")` and a dialler with `Net("host:port")` (they would need to talk
to each other over the network, which gives the listener an outbound need); and a run-time config file (adds a path to the report for no
proof in exchange).

## 4. Scope

**v1:** a forwarding cache. UDP and TCP with EDNS0 and truncation; a cache with TTLs, negative caching and LRU eviction in a fixed arena;
forwarding to a fixed upstream set with timeouts, retries and health; local records and overrides from a small bounded file; the defences in
section 6; bounded JSON logs and metrics (stderr, no files); operable by an agent: `introspect`, `skill`, `check` and `explain`, errors as data
with rule tags.

**Not in v1** (task #17 records each): iterating from the root, DNSSEC validation (stage 2; cancho has RSA, ECDSA and Ed25519), DNS over TLS
or HTTPS (TLS needs foreign code today, which would make the report unbounded), zone transfers, dynamic update, views, clustering, IPv6
sockets (cancho's sockets are IPv4; AAAA *records* are carried as data like any other).

## 5. Design

**One thread, one `Poller`.** UDP listener socket (`udp_bind`, `udp_recv_from`, `udp_send_to` with a ticket per pending client query), a TCP
listener for large answers and clients that ask for it, and one **fresh connected UDP socket per upstream query**
(`udp_connect`, a new kernel-chosen source port each time, closed when answered or timed out). The loop is `wait`, `next`, `respond`, as in
cancho-cache. Tickets are valid for 65,536 received datagrams (`docs/udp.md` §10); a pending query older than that loses its reply, which is
counted, and the timeout (default 2 s) makes that unreachable below about 32,000 queries a second.

**Codec: sans-io.** A pure function from `(buffer, position)` to a parsed message in offsets into the caller's buffer, or *need more* (TCP
framing), or a refusal. No allocation on a well-formed parse. Encoding writes into a caller's buffer and refuses rather than overrun.

**Every input is bounded and has its own refusal** (proposed limits; each is a constant in one file and each has a test at the edge):

| input | limit | refusal tag | reply |
|---|---|---|---|
| datagram / TCP message | 512 bytes plain, 1232 with EDNS (the 2020 flag-day size); TCP 65,535 by the wire format, **4,096 read by the D1 server** (a smaller bound than planned: a query is a few hundred bytes, and a per-connection 4,098-byte input buffer keeps 128 connections at about 0.5 MB; a longer frame closes the connection) | `dns-message-too-long` | `FORMERR` / close |
| header | 12 bytes, `QDCOUNT` exactly 1, `ANCOUNT`+`NSCOUNT`+`ARCOUNT` bounded below | `dns-bad-header`, `dns-bad-counts` | `FORMERR` |
| name | 255 bytes on the wire, labels at most 63 | `dns-name-too-long`, `dns-label-too-long` | `FORMERR` |
| compression | pointer strictly backwards, at most 16 hops | `dns-bad-pointer` | `FORMERR` |
| records per section | 64 answer, 16 authority, 32 additional | `dns-too-many-records` | upstream reply dropped, client `SERVFAIL` |
| EDNS | one `OPT`, version 0, unknown options ignored not echoed | `dns-bad-edns` | `FORMERR` / `BADVERS` |
| opcode / class / type | `QUERY`, `IN`; others refused | `dns-not-implemented`, `dns-refused` | `NOTIMP` / `REFUSED` |
| TCP framing | length prefix honoured, idle and slow-read timeouts, bounded connections | `dns-tcp-limit` | close |

No input reaches a panic: this is the cancho rule, and gate 2 in section 8 tests it exhaustively on the name parser and by fuzz on the rest.

## 6. Cache and security policy (proposed values in brackets)

**Cache.** One arena of records and one open-addressing index, sized at start, nothing allocated afterwards (cancho-cache's `store.cho` is the
model and may be reused as a library once it is one). Keys are `(name, type, class)` compared case-insensitively. TTLs are clamped to
[10 s, 1 day]; negative answers are cached from the SOA `MINIMUM` per RFC 2308, clamped to [10 s, 1 hour]; expiry is lazy plus a bounded sweep
per loop iteration, time from `Clock`. Eviction is by sampled LRU, as in cancho-cache. `SERVFAIL` is cached for 5 s, so a dead upstream is not
re-asked on every query.

**Only the answer chain is cached.** From an upstream reply the resolver keeps the records reachable from the question name by following
`CNAME`/`DNAME` records in order, plus an `SOA` in the authority section for a negative answer. Everything else, additional-section glue
included, is discarded. This is the bailiwick rule applied to a forwarder, and it removes the class of attacks where a reply plants records for
names that were never asked.

**Matching a reply to a query.** A reply is accepted only if it arrives on the socket opened for that query (so from the upstream the socket was
connected to, the kernel drops any other source), carries the 16-bit transaction ID drawn for it, and repeats the question section. **0x20**:
the question name's letter case is randomised in the upstream query and the reply must echo it exactly; a mismatch is dropped and counted. An
upstream that mangles case can have the check switched off in the configuration, and `explain` says that this weakens it.

**Entropy.** Transaction IDs and the 0x20 pattern come from a ChaCha20 DRBG seeded from `/dev/urandom` through `Fs`, as the language has no
randomness source (`docs/tls-pure.md`). Source ports come from the kernel (a fresh socket per query); **how unpredictable they are is measured
(gate 5), not assumed**.

**Response rate limiting.** A bounded table of token buckets per client /24 [4096 buckets, 1000 responses a second, burst 2000]; a client over
its bucket is dropped, not truncated. `dns-rate-limited` is counted. Open-resolver use is a non-goal; the default listen policy refuses clients
outside configured prefixes with `REFUSED`.

## 7. Expected authority row (a target, to be diffed in CI against a ceiling file)

`args`, `clock`, `heap`, `err_write`, `conn_accept`, `conn_read`, `conn_write`, `udp_recv`, `udp_send`, `poll`, `net_in("")`, `net_out("")`,
`fs_read("/dev/urandom")`. **Never:** `ffi`, `fs_write`, `exec`, `signals`. The two `net` labels are empty bounds for the reason in section 2;
the row will say so, and the README will not call it a proof of the upstream set.

## 8. Gates, fixed before the code

**Correctness gates (these come first).**

1. **Differential parser test.** A corpus of real and constructed messages is decoded by this codec and by `dnspython`; the accept/reject class
   and the decoded fields must agree, except for a listed set of deliberate refusals (each asserted as divergent so the list cannot go stale).
   The harness is mutation-tested: deliberately wrong codec variants are each caught.
2. **No input reaches a trap.** The name parser is run over every byte string of 0 to 6 bytes over a small alphabet that includes pointer bytes,
   label lengths 0, 1, 63, 64 and 0xC0; the message parser by a mutation fuzz over the corpus of gate 1, with the corpus kept in the repo.
3. **Memory is bounded.** After start nothing is allocated; a flood of distinct names larger than the arena never exceeds it, and evicts.
4. **Poisoning resistance.** A spoofing harness sends forged replies (wrong ID, wrong case, wrong question, extra records outside the chain,
   a late reply after timeout, a reply from a different source) at a resolver with a pending query: the cache must hold only the real answer.
   Each forgery class is a mutant of the matching code, and each must be caught by a test.
5. **Source-port entropy.** Ten thousand consecutive upstream sockets' ports are collected and tested (distinct count, range, serial
   correlation) and the result is reported, whichever way it points. If they are predictable the project says so and relies on 0x20 and the ID alone.
6. **Authority.** `cancho authority` on the built program is diffed against the ceiling file in section 7 in CI.

**Benchmark cells (task #14), pre-registered.** Same machine, `dnsperf` (DNS-OARC) as the load generator, resolvers pinned to one core, client on
other cores, a local stub authoritative server that answers instantly, five interleaved rounds, medians, configurations published. Each cell is
checked for being client-bound (the faster side re-run with a wider client; a cell more than 5% faster that way is reported *client-bound* with
no ratio), as in cancho-cache.

| cell | workload |
|---|---|
| A | UDP, cache hit, 50 clients |
| B | UDP, cache miss forwarded to the stub, 50 clients |
| C | TCP, cache hit, persistent connections |
| D | resident memory after caching 100,000 distinct names |
| E | 99th-percentile latency at half of each server's own cell-A maximum |

*Proposed* criterion: **at least 0.9 times Unbound** (one thread) in cells A, B and C, **no more than 0.5 times Unbound's resident memory** in
cell D, and E reported, not gated. dnsmasq, CoreDNS, Knot Resolver and PowerDNS Recursor (BIND if cheap) are measured and reported with the same
tables, not gated. A cell that misses is written up here, in place, with by how much. The baseline table is empty until it is measured.

### 8.1 How the benchmark will be run, against whom, on which metrics (expanded 2026-10-07, before any number exists)

**Against.** The gated comparison is **Unbound** (single thread, forwarding, cache on, DNSSEC validation off, prefetch off, rate limiting off), because it is the
reference small-footprint caching resolver. Reported, not gated: **dnsmasq** (the other resolver most people run as a forwarder), **CoreDNS** with the `forward` and `cache`
plugins, **Knot Resolver**, **PowerDNS Recursor**, and **BIND** if it can be set up cheaply. Every one is configured the same way: forward to the local stub authoritative, cache of the same
size, no validation, no logging to disk, no rate limiting, one worker pinned to one core, and the configuration files published with the numbers. A resolver that cannot be put into that
shape is reported with the difference named.

**Tools.** `dnsperf` for fixed-duration throughput and latency, `resperf` for the highest rate each resolver sustains without losses (the number a capacity plan wants), and a
local stub authoritative (a minimal one of our own, or NSD) that answers instantly so the upstream is never the limit. Load generator, resolver and stub run on separate cores of one
machine whose model, kernel and governor are written down; five interleaved rounds, medians and the spread reported. Each cell is re-run with a wider client to rule out a
client-bound result (the rule of section 8 stands).

**Metrics.**
1. *Throughput*: queries per second at a loss under 0.1% in cells A (UDP cache hit), B (miss forwarded), C (TCP hit, persistent connections). `resperf`'s sustained maximum is reported next to them.
2. *Latency*: p50, p99 and p99.9 at half of each server's own maximum (cell E), and the same at a fixed shared rate that all of them can meet, which is the comparison that is fair to the slowest.
3. *Memory*: resident set at start, after 100,000 distinct names cached (cell D), and after an hour of steady load, which is where a leak or fragmentation would show. Bytes per cached record is derived from it.
4. *CPU per query*: CPU seconds divided by queries answered, at the shared rate, because throughput on one core is the inverse of it but it also shows idle cost.
5. *Behaviour under stress, pass or fail and counted*: a cache-miss flood (distinct names, none repeated) next to a hot name that must keep being answered; an upstream that stops answering (time to `SERVFAIL`, whether other queries stall); a slow-loris TCP client set against the connection cap; a 1,000-connection burst.
6. *Correctness during the run*: every reply checked against the stub's known answer (wrong, missing or late-after-timeout answers counted). A faster resolver that answers wrongly under load does not win a cell.
7. *Footprint*: binary size, dependencies, time to start and to be ready, lines of source, and the authority report, which is the one thing here no competitor has.

**What the numbers can and cannot say.** This is one core on one machine with a loopback upstream: it measures the resolver's own work per query and its memory, not Internet behaviour (round-trip times, loss, upstream selection). It is a single-thread
comparison, so it does not speak for Unbound or CoreDNS at their usual multi-thread settings. The criterion of section 8 (0.9x Unbound in A, B, C and 0.5x its memory in D) is unchanged; a miss is written up in place with by how much.

## 9. Plan, each step with its own gate

| step | epic tasks | what | gate |
|---|---|---|---|
| D0 | #2, #3, #9 | scaffold; codec; the authority ceiling file and its CI diff | gates 1, 2, 6; the codec's refusals each have a fixture |
| D1 | #4 | UDP and TCP on one poller; truncation; EDNS size | `dig` behaviour matches on `+tcp`, `+bufsize`, TC cases; cell A against a stub cache |
| D2 | #5 | cache: TTLs, negative caching, eviction | gate 3; cell A and D recorded |
| D3 | #7, #6 | forwarding, health, the defences | gates 4 and 5; cells B and C |
| D4 | #8, #10, #12 | local records, agent contract, logs and metrics | `check`/`explain` golden tests; no file is opened for writing |
| D5 | #11, #13, #14 | conformance, hardening, the full benchmark | every cell reported; fuzz clean for a recorded run length |

## 10. What would make this project not worth continuing

* The codec needing an allocation per message to be correct.
* Cell A below 0.7 times Unbound, where both are syscall-bound and the language should not matter: the loop or the poller has a cost the
  cache-hit path hides.
* Source ports being predictable **and** 0x20 being unusable against real upstreams: the poisoning story would then rest on 16 bits.
* cancho never gaining a per-direction, set-valued `Net`: the project would still be a memory-safe resolver, but "a resolver you can audit"
  would mean a table in code, and the page would have to say so.

Any of these is written up here, in place, as the result.

## 11. Open questions for the maintainer

1. ~~Confirm section 3~~ **Confirmed.** (The cancho prerequisite of section 2 is filed: alpibrusl/cancho#362.)
2. ~~Confirm the proposed limits~~ **Confirmed** (sections 5, 6 and 8).
3. Is Unbound the right gated comparator, or should the gate be against the best of all five per cell?
4. What does `"bounded": true` mean in `cancho authority`'s JSON? It reads true for the empty bound.

## 12. D0, built and measured: the codec

`src/dns.cho` is the codec (`parse`, `name_end`, `name_expand`, `encode_query`, `encode_error`), `tests/dns_test.cho` its tests, `tests/driver.cho`
the codec behind a pipe, `tests/differential_codec.py` gate 1, `tests/mutate_harness.py` gate 1's own mutation test, `tests/authority_check.py` and
`authority/codec.ceiling` gate 6, and `.github/workflows/ci.yml` runs all of it on a compiler pinned by revision. Measured on cancho
`0567e72` with the debug build, and **re-run in CI on the pinned release build, where every step passes** (formatting, the 24 codec tests, the differential with
the same counts as below, the 19 wrong codecs, the authority gate and the gate shown able to fail). CI's first run failed on a path bug in
`mutate_harness.py` (a relative compiler path from a scratch directory), not in the codec; the steps before it, the differential included, had passed.

**Gate 2 (no input reaches a trap), as met.** `cancho test`: 24 tests. The name parser is run over **every byte string of 0 to 6 bytes over eight
symbols (299,593 of them)** after a header's worth of bytes (so pointers can land): each is refused or ends inside the message, and `name_expand`
agrees (accepted names expand to at most 255 bytes). `parse` is run over a real response with **every one-byte and every two-byte change to eight
symbols (66,240 parses)**: each answers a refusal or the message's length. Every proper prefix of a message is `dns-bad-header` or `dns-truncated`,
never another code.

**Mutation checks.** 26 deliberately wrong codec variants (a limit off by one, a check removed, the OPT rules, each record type's data check, the
encoder's flags) are each caught by the unit tests. **The first version caught 13 of 29**: the OPT rules, the per-type data checks and the exact
refusal code for a truncated message had no tests; they were written, and two checks that turned out to be dead code (the root's length check, which the
label check already bounds, and a label's early truncation check, which leaving the loop already answers) were removed. One more variant, a pointer
that points at itself, is **equivalent**: the hop limit refuses it with the same code, so it is not tested separately.

**Gate 1 (differential against dnspython 2.8.0), as met.** Seed 20261007: 19 constructed messages and 34,931 in the corpus (2,687 valid, built with
dnspython, and mutants of them). 9,082 are accepted by both with every compared field equal (header, question, every record's owner, type, class and
TTL, data length where dnspython's re-encoding preserves it, the OPT fields); 25,793 are refused by both; 54 we accept and dnspython refuses, every one
carrying data the codec does not look inside; 2 we refuse and dnspython accepts, both pointer rules. **The first run found two bugs in the codec**, now
fixed and pinned by unit tests: a TTL with the top bit set was passed through (RFC 2181 section 8 makes it zero; dnspython does), and `A` data of the
wrong length was refused in a class other than IN, where it is not an address. **And one class of leniency:** dnspython validates the contents of the
EDNS options it knows (a cookie of the wrong length), and the codec treats options as opaque on purpose, so a message with such an option is accepted by
us and refused by dnspython; the script allows exactly this and nothing else (`INTERPRETED_OPTIONS`).

**The deliberate divergences, each asserted by a constructed message so the list cannot go stale:** dnspython **accepts** and the codec **refuses** a
message with two questions or none (`dns-bad-counts`), with more than 64 answers, 16 authority or 32 additional records (`dns-too-many-records`), with a
compression pointer into the header, and with a chain of 17 pointers (`dns-bad-pointer`). Both refuse: an OPT in the answers, two OPTs, an OPT owned by
a pointer, options that do not tile, an `A` of 3 bytes, a trailing byte, a label type of 01, a forward pointer, a 256-byte name, an 11-byte message. Both
accept: a 255-byte name, 16 pointer hops.

**The harness can fail.** `tests/mutate_harness.py` builds 19 wrong codecs (flags read from the wrong bytes, a count from the wrong field, the question's
type and class swapped, the TTL read short, the top-bit rule removed, the OPT fields swapped, trailing bytes accepted, forward pointers, reserved label
types, a 256-byte name, a weak `A` check, two questions, 65 answers, 17 hops, a pointer into the header, an OPT in the answers) and the differential
catches **19 of 19**. (The first version had a variant that changed nothing and a pattern that no longer matched the formatted source; both were the
script's faults and are fixed.)

**Gate 6 (authority), as met for what exists.** The only program is the driver, and its row is `io_read`, `io_write`, bounded, with no foreign symbol.
`authority/codec.ceiling` says so; the check fails if the row grows, if the ceiling lists something nothing performs (a ceiling only comes down), or if the
report is unbounded, and CI runs it once with a ceiling that must be refused so that the gate is shown able to fail.

**Not done in D0, said so.**
* The encoder (`encode_query`, `encode_error`) is tested by parsing what it writes with this codec, **not yet by dnspython**.
* Record types whose data holds names beyond the ones the codec checks (NSEC, RRSIG's signer, KX, RP, and others) are opaque to it, as unknown types are.
* The differential has been run on the debug compiler only; the pinned release build runs it in CI.
* There is no benchmark: the baseline table of section 8 is still empty (the server is section 13, the cache section 14).

## 13. D1, built and measured: the UDP and TCP server

`src/server.cho` serves UDP and TCP on one port from one `Poller` (token 0 the listener, 1 the UDP socket, 2 and up the connections). `src/stub.cho` is the
**responder of this step, not a resolver**: it answers from the name (`n<k>.` gives k A records, `t<k>.` one TXT of k bytes) so truncation, EDNS sizing and
framing can be tested exactly; a forwarder replaces it in D3. Run: `server <port> [<idle seconds>]` (default 10).

What it does, each item tested black-box by `tests/server_test.py` with dnspython as the client (12 tests, run against the built binary):

* UDP: a reply over the client's advertised EDNS size, clamped to 512..1232 (512 with no EDNS), is replaced by a header-only TC reply; a malformed datagram
  gets FORMERR (id and RD echoed); a response, or fewer than 4 bytes, gets nothing; NOTIMP, REFUSED (non-IN class, AXFR/IXFR) and BADVERS as in the stub.
* TCP: 2-byte length framing; pipelined and byte-at-a-time messages are answered in order; a frame under 12 or over 4,096 bytes closes the connection; a
  connection silent for the idle time is closed; at most 128 connections, and the port serves again once they are gone. Replies are not truncated.
* UDP is drained in bursts of 64 per wakeup, so a flood on UDP cannot starve TCP (the starvation question of `udp.md`); this is by construction here, and
  **not yet measured under load**.

Gates: `authority/server.ceiling` (gate 6, diffed in CI) lists `args, clock, conn_accept, conn_read, conn_write, err_write, heap, net_in(""), poll, udp_recv,
udp_send`, bounded, no ffi, no processes, no files. The `net_in("")` label is the unnarrowed `Net` of section 3, so it proves no more than that section claims.
`tests/mutate_server.py` builds 5 mutants (short frame accepted, connection cap raised, idle timeout never fires, EDNS ceiling removed, UDP floor raised); all
5 are killed. One mutant is **explained, not killed**: removing `size > frame_max()` changes nothing observable, because the input buffer (4,098 bytes)
already closes a connection that cannot complete such a frame; the check is kept as the early, explicit refusal.

Not done in D1, said so.
* No load measurement and no comparison with another server: the baseline table of section 8 is still empty.
* No upstream, cache or source-port randomisation (D2 to D4).
* The server is tested on loopback only, and the differential test of the encoder against dnspython is still open from D0.

## 14. D2, the cache: design and gate, written before the code

*Status: built (section 14.1). Corrected in place if a claim below turns out false.*

**Reuse.** `src/store.cho` is cancho-cache's store (the arena, the open-addressing index with backward-shift deletion, sampled LRU, lazy expiry plus a bounded
sweep, incremental compaction), **vendored at cancho-cache `e196d5a` and not edited** (it is not a library yet; a vendored file with its origin in the
header is the honest form until it is). Nothing is allocated after `open`, which is what gate 3 needs.

**Key and value.** Key: the question name in lower-case wire form (RFC 4343 folding), then type and class, 2 bytes each. Value: the *answer chain* of
section 6 in a position-independent form: a 4-byte header (rcode, answer count, authority count, flags), the stored-at time, and for each record its
owner name, type, class, original TTL and rdata **with embedded names expanded** (no compression pointers, so a record can be written at any offset of a
later reply). Types whose rdata holds names are re-encoded for CNAME, NS, PTR, DNAME, MX, SRV and SOA; a record of any other type is stored opaque. A reply that
the re-encoder cannot fit is not cached (`uncacheable` is counted), never cached wrongly.

**What is kept** (section 6, now exact): starting at the question name, an answer record is kept if its owner equals the current name and it is a CNAME (the
current name becomes its target) or of the question's type; nothing else of the answer section, nothing of the additional section. A negative answer
(NXDOMAIN, or NOERROR with nothing kept) keeps the SOA of the authority section and caches for `min(SOA TTL, SOA MINIMUM)` (RFC 2308), clamped to
[10 s, 1 hour]; positive TTLs are clamped to [10 s, 1 day] and the entry lives for the smallest kept TTL. `SERVFAIL` is stored for 5 s. Only `NOERROR`,
`NXDOMAIN` and `SERVFAIL` are cached; a reply with TC set is never cached.

**On a hit** the reply is built from the entry and the query: the query's ID, its question as sent (its case), `QR RD RA`, each TTL reduced by the
seconds since it was stored (never below the clamp's floor reached at 0 remaining: an entry is gone when its smallest TTL is, so no TTL is written as 0
from a live entry except where the original was 0), and the OPT record of the client's EDNS if it sent one. The existing truncation applies to it.

**Until D3 the "upstream" is the stub**: a miss is answered by `stub.respond` and the reply goes through the same insertion code a forwarded reply will, so what
is exercised is the cache, not a stand-in for it. `n<k>.` and `t<k>.` are as in section 13; `ttl<k>.` gives one A record with TTL k, `nx` names give
NXDOMAIN with an SOA (TTL and MINIMUM 30). A CHAOS-class TXT query for `stats.bind.` returns the counters (hits, misses, stored, evicted, expired,
uncacheable, live, used bytes), so tests can see the cache from outside.

**Gate 3, fixed before the code.** *(Corrected in place, see 14.1: item 3 first said "the first 10,000 and the last differ by under 5%".)*
1. *Unit* (`tests/cache_test.cho`): TTLs are clamped and decremented; the smallest kept TTL ends the entry; negative caching uses SOA `MINIMUM` and the clamp;
   a CNAME chain is kept and a record planted outside it is dropped; a reply with TC, an unsupported rcode or an unfitting record is not cached; names
   differing only in case share an entry; an entry over its time is a miss; filling a small store with 10,000 distinct names never exceeds `max_keys` or the
   arena and evicts.
2. *Black-box, through the server* (`tests/cache_server_test.py`, dnspython): a repeated query is a hit (counters) and its TTL falls; with the clamp floor
   set to 1 s at start a 1-second record is a miss again after 2 s; an NXDOMAIN is served from cache; a hot name survives a flood.
3. *Memory bounded*: 100,000 distinct names through a server with a 1 MiB arena; `VmRSS` after the first 80,000 and after the last differ by under 1%,
   `evicted` is over 0, `live` never exceeds the key cap, and a name queried again every 100 queries throughout still hits. This runs in CI.
4. *The gate can fail*: mutants of the cache (TTL not decremented, clamp floor removed, SOA ignored for negatives, chain filter off, case-sensitive key,
   no eviction) are each killed by the tests above; any survivor is listed here with the reason.

Cell A (UDP cache hit, 50 clients) and cell D (memory after 100,000 distinct names) are *recorded* in D2 against `dnsperf` if it can be installed in CI,
and reported plainly whichever way they point; if not, the cell is reported as not measured, with the reason. No ratio is claimed from this step.

### 14.1 Built and measured

`src/cache.cho` over the vendored `src/store.cho`; `server` takes `<port> [<idle s> [<min ttl s> [<cache bytes> [<cache keys>]]]]` (10, 10, 16 MiB, 65,536). The
`stats.bind. CH TXT` query returns the counters. Seed of the store's hash is the constant 0 until D3 reads one at start (a client that can choose names could
aim collisions at the index; D3 closes that, and until then it is a known weakness).

* *Gate 3, part 1* (`tests/cache_test.cho`, 10 tests): TTL decrement and expiry to the second; floor and ceiling; the smallest kept TTL ends the entry; SOA
  `MINIMUM` and the clamp for negatives; the answer chain (out-of-order, off-chain, wrong-type, and additional records dropped); TC, REFUSED, a reply to
  another name or another type, and an SOA-less NXDOMAIN not cached; SERVFAIL kept 5 s; case-insensitive keys with the client's own case echoed; EDNS and
  the size limit on a hit; 10,000 names through a 100-key store.
* *Part 2* (`tests/cache_server_test.py`, 6 behaviour tests through the server with dnspython): hit counters and TTL running down and ending, case, negative
  answers from the cache, TCP served from the same cache, a cached big answer still truncated over UDP, refusals not cached.
* *Part 3, memory*: 100,000 distinct names through a 1 MiB, 2,048-key store: 97,953 evicted, `live` held at 2,048, `used` under `capacity`, no refusals for lack
  of room, a hot name asked every 100 names kept hitting (over 95% of its asks), and `VmRSS` 4,492 KiB after 80,000 names and 4,492 KiB after 100,000.
  **Correction made in place:** the gate first said "after the first 10,000 names and after the last, within 5%". Measured, RSS climbs about 312 KiB per
  10,000 names until 65,536 datagrams and is flat after, for any arena size (256 KiB, 1 MiB, 4 MiB all stop at the same name count). That is the UDP
  runtime's ring of 65,536 peer tickets (`docs/udp.md`) being written for the first time, about 32 bytes each, **not the cache**: this is inferred from the
  match with 65,536, not isolated by a run without the ring. The gate now reads RSS after that ring has been written round once.
* *Part 4*: `tests/mutate_cache.py`, 16 mutants of `src/cache.cho` (decrement, floor, ceiling, chain filter, type filter, case fold, eviction, TC, smallest TTL, SOA
  `MINIMUM`, SOA-less negative, size limit, id, question, question match, SERVFAIL TTL); **16 of 16 killed**. Two of them survived the first set of tests
  (type filter, mismatched type) and the tests were strengthened, not the mutants dropped; the TC test was also made to carry an answer, as a TC reply without one was never cacheable anyway.
* *Gate 6*: the server's authority ceiling is unchanged by the cache (same labels), diffed in CI.

Not done in D2, said so.
* **Cell A and cell D are not measured.** `dnsperf` was not run; no ratio is claimed. The only cache numbers here are the correctness and RSS ones above.
* The "upstream" is the stub: no real answer has gone through `insert` yet, so the re-encoder is tested on constructed replies only (CNAME, A, TXT, SOA); NS, PTR,
  MX, SRV and DNAME rdata go through the same code path but have no test of their own.
* No negative-cache aggressive use, no prefetch, no serve-stale; entry size is capped at 4,096 bytes (a larger answer is not cached).

## 15. D3, the forwarder: design and gates, written before the code

*Status: built (section 15.1). Corrected in place if a claim below turns out false.* The compiler is pinned at `alpibrusl/cancho@9dfc1ab`, which adds
`udp_detach`/`udp_attach` and `std.udps` (cancho#370): section 5 asked for one connected socket per query in flight, and the language had no way to hold many sockets. That was
found by reading this section's mechanism against the language before writing it.

**Mechanism.** A cache miss takes a slot in a bounded pending table (1,024). For each attempt the resolver draws a 16-bit ID and a 0x20 case pattern from a ChaCha20 DRBG seeded from
`/dev/urandom` (`src/rng.cho`; the key is replaced from the keystream after each refill, so a later state does not reveal earlier outputs), opens a **fresh connected socket**
(`udp_connect`, so a kernel-chosen source port and a kernel that drops every other source), keeps it in a `std.udps` table, and sends the query with the name's letters in the pattern's case,
`RD` set, and EDNS 1232. The socket is watched on the shared `Poller`. A reply is **accepted only if** it arrives on that socket; has QR set, opcode QUERY and the drawn ID; and its
question section is **byte-identical** to the one sent (so the case, the type and the class all match, which is the 0x20 check and the question check in one comparison). Anything else is dropped and
counted by rule tag (`dns-reply-id`, `dns-reply-question`, `dns-reply-not-response`). An accepted reply goes through `cache.insert` (section 6's answer-chain filter), and the client is served from the
entry; a reply the cache will not keep is answered `SERVFAIL`. The socket is closed when the query ends, by answer, drop of the pending slot, or timeout.

**Timeouts, retries, health.** An attempt times out after 2 s; a query gets two attempts, the second on a new socket, ID and case pattern, to the next healthy upstream; after the second, the client gets `SERVFAIL`, which the
cache keeps for 5 s. An upstream with three consecutive timeouts is marked down for 10 s and skipped; if all are down the client gets `SERVFAIL` at once. A TCP client has one query in flight at a time (its next buffered message
waits for the answer), so replies stay in order. A UDP reply from upstream with TC set is not cached and is passed to a UDP client as a truncated reply; to a TCP client it is `SERVFAIL`. **Upstream over TCP is not in D3**, said here
so it is not discovered later.

**The upstream table is compiled in** (section 3): `src/upstreams.cho` is generated by `tests/gen_upstreams.py` from `upstreams.conf` (`host port` per line, at most 8). The tests build with a table of their own pointing at a fake upstream on loopback.

**Gates, fixed now.**
4. *Poisoning resistance* (`tests/spoof_test.py`, with a fake upstream written to misbehave). Per forgery class, a forged reply is sent before the real one, or in place of it, and the test asserts that the client is never given the forgery, that the
   cache holds only the real answer (a later ask for the name the forgery tried to plant is a miss, via `stats.bind.`), and that the drop counter for that class moved. Classes: wrong ID; right ID, wrong case (0x20); wrong question name; wrong question type; QR clear; right everything but with extra
   records in the answer for another name (a CNAME to a planted name, an A for a name never asked) and in the additional section (glue); a reply from a different socket than the one the query went to (the kernel's job, asserted rather than assumed); a reply after the timeout; a
   reply that duplicates one already accepted. **Each class is a mutant of the matching code** (`tests/mutate_spoof.py`: ID not compared; case-insensitive question comparison; type not compared; QR not checked; chain filter off; reply accepted after the pending slot is gone), and **each must be killed by this test**; a survivor is listed with the reason.
5. *Source-port entropy*: 10,000 consecutive upstream queries are made and the fake upstream records each source port. Reported, whichever way it points: distinct count, minimum and maximum, the fraction in the kernel's ephemeral range, the lag-1 serial correlation of the sequence, and a chi-square over 16 equal bins. The README
   claims nothing about source ports beyond that report. If the ports are predictable the project says so here and relies on 0x20 and the ID alone.
   *Pre-registered reading*: a distinct count under 95% of the count expected for 10,000 independent draws from the range, or a lag-1 correlation over 0.05 in absolute value, is "predictable" and is written up as such.
3b. *Memory*: the pending table, the socket table and the query copies are fixed at start; the flood test of section 14 is repeated with every query a miss that is forwarded, and RSS after 80,000 and 100,000 of them must agree within 1%.
6. *Authority*: the ceiling gains `net_out("")` and `fs_read("/dev/urandom")` and nothing else.
Also fixed now, for what the DRBG must show: `tests/rng_test.cho` pins its first block to `std.chacha20.block` for the same key, shows that two seeds give different streams, that the key changes after a refill, and that 100,000 draws of `below(n)` for n = 3, 7, 1000 land in every bucket with no bucket more than 5% from the mean.

What D3 does not claim: that the upstream's answer is correct (there is no DNSSEC validation), that an on-path attacker is stopped (one who can see the query can match every field), or anything about TCP upstream or about IPv6.

### 15.1 Built and measured

`src/rng.cho` (the DRBG), `src/forward.cho` (the sans-io matching rule and the 0x20 randomiser), the pending table and socket table in `src/server.cho`, `src/upstreams.cho` (the compiled-in table; empty in the repository, in
which case the server answers from the stub as in D1 and D2) and `tests/gen_upstreams.py`. `server` is started as before; the cache hash seed is now drawn from the DRBG at start (section 14.1 named it a weakness; it is closed).

* *DRBG* (`tests/rng_test.cho`, 4 tests): the first output is the second half of the first ChaCha20 block of the seed and the next block is under the key the first made; two seeds differ and one seed repeats; `below(n)` for 3, 7 and 1,000 keeps every bucket of 100,000 draws within the stated band; every bit of a byte is set about half the time.
* *Matching* (`tests/forward_test.cho`, 3 tests): accepted exactly when id, QR, opcode and the whole question (bytes) agree; each other case has its own code: id, QR, opcode, case only, another name, another type, no or two questions, too short, a cut-off question; bytes after the question do not matter to this rule. The randomiser changes only letters, keeps length bytes, and changes about half of them.
* *Forwarding* (`tests/forward_server_test.py`, 9 tests against a fake upstream): a miss is forwarded and the next ask is a hit; the query carries RD, EDNS 1232 and a mixed-case name; a negative answer is forwarded and cached; a truncated upstream reply is TC to a UDP client and SERVFAIL to a TCP one and is not cached; 150 queries in flight at once are each answered to their own client in about the time of one; three pipelined TCP queries come back in order; a silent upstream gives SERVFAIL after two attempts (about 4 s), kept for 5 s, then answered at once, with the third timeout marking the upstream down so the next query takes one attempt and the one after sends nothing; a dropped first attempt is retried on a new socket with a new port and id; with one dead and one live upstream all 40 queries are answered and, once the dead one is marked down, it receives no more.
* *Gate 4* (`tests/spoof_test.py`, 7 tests): forged replies of five classes (wrong id; right id and wrong case; another name; another type; QR clear) are each dropped, counted under their own tag only, never given to the client, never cached (the real answer is, with its real TTL, not the forged 3,000 s); with nothing real behind them the client gets SERVFAIL; an accepted reply carrying a planted answer for another name, glue and an NS is cached as the answer chain only (the planted names are misses afterwards and the NS is not there); a CNAME chain is kept; a perfect forgery from another socket never arrives and moves no counter (the kernel's work); a second copy of the real reply changes nothing; a perfect forgery after the timeout is not cached. **`tests/mutate_spoof.py`: 7 of 7 mutants killed** (id not compared; QR and opcode not checked; question compared without regard to case; name not compared; type and class not compared; no reply judged; chain filter off).
* *Gate 5* (`tests/ports_test.py`), run here on Linux 6.18 in a Firecracker VM, 10,000 queries: **8,422 distinct ports, 8,420.9 expected from independent uniform draws (ratio 1.0001); range 32,768 to 60,996, all inside the kernel's ephemeral range; lag-1 serial correlation 0.0143; chi-square over 16 bins 13.14 (critical 37.7 at p = 0.001, df 15).** By the pre-registered reading the ports are not predictable. That is the range's 28,232 values, about 14.8 bits, not more; it is one kernel, and CI repeats the run on its own runner. Nothing is claimed for other kernels or for macOS, where this was not run.
* *Memory* (`tests/forward_memory_test.py`): 100,000 distinct names, every one forwarded to the upstream: `VmRSS` 5,064 KiB after 80,000 and after 100,000 (0.00%), 97,952 evicted, `live` held at 2,048, and the process's open descriptors the same at the end as at the start (6): every query's socket is closed.
* *Gate 6*: the ceiling gains exactly the two labels predicted, `net_out("")` and `fs_read("/dev/urandom")`.
* *Closed from D2*: the store's hash seed (above), and the rdata of NS, PTR, DNAME, MX and SRV is now tested through the cache (the data comes back with its name written out).

Not done in D3, said so.
* **No upstream over TCP**, so a client that is sent TC by an upstream cannot be served the whole answer. No IPv6, no EDNS cookies, no DNSSEC.
* **Response rate limiting and the client-prefix ACL of section 6 are not built.** The resolver answers anyone who can reach it, which is an open resolver.
* **The pending table is searched linearly** for a free slot and for timeouts (every 100 ms, 1,024 entries): its cost under load is unmeasured and is a likely first thing the benchmark of section 8.1 shows.
* Nothing here is a benchmark. The per-datagram cost of the socket table (two builtin calls and two table accesses per call) is not measured.
* An on-path attacker who can see the query can match every field; this is the protection against one who cannot.

## 16. D3b, who may ask: the access list and the rate limiter, design and gates before the code

*Status: built (section 16.1).* Section 15.1 ended with the resolver answering anyone who can reach it. Section 6 had a remedy on paper: a response-rate limiter per client /24 (4,096 buckets, 1,000 responses a second, burst 2,000) and a default that refuses clients outside configured prefixes. Both need the
client's address, and the language did not give it: a bound socket answers through a ticket, and `Accepted` has no peer. Found by reading this section's mechanism against the language; `conns.peer` for a TCP connection is cancho#367 (already merged) and `udp_peer` for a datagram's sender is cancho#399, whose form it follows (the 19 bytes `conn_peer` writes, read by `std.addr`). The compiler pin is #399's merge commit, `93e49cd`. (A first version of this prerequisite, cancho#376, chose another encoding for `conn_peer` while #367 was landing; it was closed, not merged.)

**Access list.** `access.conf` (`allow <ipv4>/<length>`, at most 16 lines) is compiled into `src/access.cho` by `tests/gen_access.py`, as the upstream table is. The repository's own file allows `127.0.0.0/8` and nothing else, so **the default is closed**: an operator opens it by listing the networks to serve.
A UDP query from an address outside every prefix is answered `REFUSED` (small, the size of the query, so no amplification) and counted `acl_refused`; a TCP connection from one is closed at accept without a byte read, and counted the same. The check comes after the rate limiter, so a flood of refused queries is limited too.

**Rate limiter.** Per client /24, a token bucket in 4,096 buckets chosen by a keyed hash (the key is drawn from the DRBG at start, so which networks share a bucket cannot be aimed at without it; **this is argued, not proven**). `rate` responses a second and a burst, both from the command line (defaults 1,000 and 2,000; a rate of 0 turns it off, and `explain` will say so).
Buckets are shared on a collision, not reset: a deliberate collision can make a victim's network share an attacker's bucket, but cannot make the attacker's own traffic escape the limit. A UDP query over its bucket is dropped, not answered, and counted `rrl_dropped`. TCP is not limited by this: a TCP client has completed a handshake and so cannot be a spoofed source.

**Gates, fixed now.**
7. *Access* (`tests/access_test.py`, a server built with a table that allows `127.0.0.1/32` and `127.0.1.0/24`, clients bound to other loopback addresses): an allowed client is served over UDP and TCP; a client at `127.0.0.2` gets `REFUSED` over UDP and its TCP connection is closed unread; both counted; the same query from an allowed address afterwards is served (a refusal does not poison the cache or the limiter). Mutants: the check inverted; the check removed for UDP; removed for TCP; a prefix length ignored (`/32` taken as `/24`).
8. *Rate* (`tests/rate_test.py`, rate 50 a second, burst 100): 2,000 queries sent as fast as possible from one address answer at most `burst + rate * seconds + 5` of them and at least `burst`; a second /24 asking at the same moment is answered in full; two hosts of one /24 share one bucket (together at most the same); after a pause of two seconds the bucket has refilled by about `2 * rate`; a rate of 0 answers all. Mutants: limiter off; bucket keyed by the full address rather than the /24; refill ignored; cost per response zero; burst ignored.
9. *Limiter unit tests* (`tests/limit_test.cho`): the bucket arithmetic at its edges, with a fixed key and time.
10. *Authority*: the ceiling does not change (`udp_peer` and `conn_peer` carry no label), and the diff in CI says so.
11. *The README* says "closed by default" and what an open resolver is, and the limits above, nothing about abuse it was not measured against.

What this does not do: stop a client inside an allowed prefix from sending many queries that each cost the upstream (the limiter is per /24 for responses, and a cache miss costs more than one); look at the content of the query; or defend against a spoofed source inside an allowed prefix (a datagram can name any source).

### 16.1 Built and measured

`src/limit.cho` (the token buckets), `src/access.cho` (generated by `tests/gen_access.py` from `access.conf`, which ships allowing `127.0.0.0/8` only), and the checks in `src/server.cho`. `server` takes two more arguments, `[<responses a second> [<burst>]]` (1,000 and 2,000; a rate of 0 is no limit).
The compiler pin is the merge commit of cancho#399 (`udp_peer`), `93e49cd`.

* *Limiter unit tests* (`tests/limit_test.cho`, 6): a burst then nothing until the bucket refills, to the millisecond; hosts of one /24 share a bucket and other networks do not; a rate of 0 limits nothing; buckets are spread over the table; the extremes of every input reach no trap.
  **A bug the black-box test found in the first version:** the bucket hash multiplied a 32-bit value by a 32-bit constant, which overflows a 64-bit integer for about one key in five, so the server **trapped on its first query** for those keys (the key is drawn at start). It showed as a test that failed about one run in ten, not as a deterministic failure. Fixed by taking the sum modulo 2^31 before the multiply, with a test at the extremes, and `elapsed * rate` is clamped likewise. Since then 15 runs of the rate test in a row pass.
* *Gate 7* (`tests/access_test.py`, 3 tests, a server built with `127.0.0.1/32` and `127.0.1.0/24`): the allowed addresses are served over UDP and TCP; `127.0.0.2`, `127.0.0.200` and `127.0.2.1` get `REFUSED` (no bigger than the query) and are counted; a refused address that sends garbage or a response gets nothing; a TCP connection from a refused address is closed without a byte read and counted; and the allowed client is served as before.
* *Gate 8* (`tests/rate_test.py`, 3 tests, rate 50 and burst 100): 2,000 queries from one address were answered 117 times in 0.36 s (ceiling 158) and 1,883 were counted dropped; two of three other networks, asking at the same moment, were answered in full; two hosts of one /24 shared a bucket (the second got at most 25 of 60); after a two-second pause the bucket had refilled (at least 70 of 300); a rate of 0 answered at least 990 of 1,000.
* *Mutants* (`tests/mutate_access.py`): **12 of 12 killed**: the UDP check inverted and removed, the TCP check inverted and removed, a prefix length ignored; the limiter off, buckets keyed by the full address, no refill, a response costing nothing, the bucket starting far over the burst (the unit test, because a first touch at any later time clamps the bucket and so hides it), the burst not a ceiling, and the server never asking the limiter.
* *Gate 10*: the authority ceiling is unchanged, as predicted.

Not done in D3b, said so.
* The limiter works on responses sent to UDP clients, not on the work a cache miss causes an upstream, and a client inside an allowed prefix can still send as many cache-missing queries as its bucket permits; a datagram can name any source, so a spoofed source inside an allowed prefix spends that network's bucket.
* The argument that a collision cannot be aimed at without the key is an argument; nothing here tests it.
* IPv6, as everywhere.
* The access list and the rate are start-up facts: a change is a rebuild or a restart, and `check`/`explain` (D4) do not exist yet to tell an operator what is in force.

## Reproduce (section 2)

```
# fact 1: narrow twice  -> error: `net` has already been consumed
let a = narrow(net, "127.0.0.1:53");  let b = narrow(net, "127.0.0.2:53");

# fact 3: a prefix, not an equality
fn probe(bound: Net("127.0.0.1:5353")) -> [] int {   // narrowed to exactly this
    borrow bound as &n in {
        match udp_connect(n, "127.0.0.10", 5353) {   // exit 0: not refused
            UdpOpened::Ok(u) => { udp_close(u); } UdpOpened::Failed(e) => { } } }
    release(bound); return 0;
}

# fact 2: one bound, both directions
Net("127.0.0.1:5353"): udp_bind traps      Net("5353"): udp_connect traps
unnarrowed Net(""):    both succeed        report: net_in(""), net_out("")
```
