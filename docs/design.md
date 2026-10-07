# cancho-dns: a forwarding and caching resolver in cancho

Status: **design (task #1 of the epic, [#18](https://github.com/alpibrusl/cancho-dns/issues/18)); D0, the codec (section 12), and D1, the UDP and TCP server (section 13), are built; the cache, forwarder and benchmark are not.** **Confirmed by the maintainer on
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
* There is no cache and no benchmark: the baseline table of section 8 is still empty (the server is section 13).

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

*Status: gate fixed, code not yet written. Corrected in place if a claim below turns out false.*

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

**Gate 3, fixed now.**
1. *Unit* (`tests/cache_test.cho`): TTLs are clamped and decremented; the smallest kept TTL ends the entry; negative caching uses SOA `MINIMUM` and the clamp;
   a CNAME chain is kept and a record planted outside it is dropped; a reply with TC, an unsupported rcode or an unfitting record is not cached; names
   differing only in case share an entry; an entry over its time is a miss; filling a small store with 10,000 distinct names never exceeds `max_keys` or the
   arena and evicts.
2. *Black-box, through the server* (`tests/cache_server_test.py`, dnspython): a repeated query is a hit (counters) and its TTL falls; with the clamp floor
   set to 1 s at start a 1-second record is a miss again after 2 s; an NXDOMAIN is served from cache; a hot name survives a flood.
3. *Memory bounded*: 100,000 distinct names through a server with a 1 MiB arena; `VmRSS` after the first 10,000 and after the last differ by under 5%,
   `evicted` is over 0, `live` never exceeds the key cap, and a name queried again every 100 queries throughout still hits. This runs in CI.
4. *The gate can fail*: mutants of the cache (TTL not decremented, clamp floor removed, SOA ignored for negatives, chain filter off, case-sensitive key,
   no eviction) are each killed by the tests above; any survivor is listed here with the reason.

Cell A (UDP cache hit, 50 clients) and cell D (memory after 100,000 distinct names) are *recorded* in D2 against `dnsperf` if it can be installed in CI,
and reported plainly whichever way they point; if not, the cell is reported as not measured, with the reason. No ratio is claimed from this step.

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
