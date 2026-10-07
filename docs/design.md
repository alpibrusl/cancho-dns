# cancho-dns: a forwarding and caching resolver in cancho

Status: **design (task #1 of the epic, [#18](https://github.com/alpibrusl/cancho-dns/issues/18)); nothing is built.** Every number in
section 8 that is not a measurement is marked *proposed*; the maintainer confirms or changes them before any code is written, because a gate
is fixed before the code it judges. The measurements in section 2 were taken on cancho at `alpibrusl/cancho@0567e72` (after its UDP work,
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
| datagram / TCP message | 512 bytes plain, 1232 with EDNS (the 2020 flag-day size); TCP 65,535 | `dns-message-too-long` | `FORMERR` / close |
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

1. Confirm section 3: ship v1 on an unnarrowed `Net` with the compiled-in table? (The cancho prerequisite of section 2 is filed: alpibrusl/cancho#362.)
2. Confirm the proposed limits (section 5), the cache clamps and RRL values (section 6), and the benchmark criterion (section 8).
3. Is Unbound the right gated comparator, or should the gate be against the best of all five per cell?
4. What does `"bounded": true` mean in `cancho authority`'s JSON? It reads true for the empty bound.

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
