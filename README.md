<p align="center"><img src="docs/assets/cancho-dns-logo-256.png" alt="cancho-dns" width="200"></p>

# cancho-dns

**A DNS resolver you can audit.** A forwarding and caching resolver written in [cancho](https://github.com/alpibrusl/cancho): a bounded parser, a cache in a fixed arena, no `Ffi` and no `unsafe`, and an authority report that shows it has no foreign code, no processes and no file but its entropy source. A bug in the packet parser is a bounds trap, not a memory-safety hole. **Corrected from the first draft:** the report was meant to name the exact upstreams the program can reach, and cancho cannot prove that today (measured in [`docs/design.md`](docs/design.md) §2), so in v1 the upstream set is a compiled-in table enforced and checked in code, and the compiler-checked claim waits on language work.

**Status: v1 is built and gated.** The codec (D0), a UDP and TCP server on one poller (D1), an answer cache in a fixed arena (D2), a forwarder with a compiled-in upstream table and the poisoning defences (D3), an access list closed by default with a per-/24 response-rate limiter (D3b), local records, overrides and blocklists (D4), the operator surface -- `introspect`, `skill`, `check`, `explain`, `diff` -- with errors as data and a published JSON Schema (D6, D13, D14), a bounded query log on standard error and a latency histogram at `histogram.bind` (D7), a conformance and interoperability suite with an RFC coverage table (D8), the hardening gates -- a 20,000-datagram whole-server fuzz with no trap, every limit at its edge, amplification bounded (D9), and the benchmark cells measured (D10, ours; the incumbents' comparison runs where they are installed, and no ratio is claimed that was not measured) -- all built, all gated, all green in CI. Every number lives in [`docs/design.md`](docs/design.md) and [`docs/numbers-d10.md`](docs/numbers-d10.md) with its run; claims are corrected in place when a gate finds them false. The plan and its tasks are in the epic, [cancho-dns#18](https://github.com/alpibrusl/cancho-dns/issues/18). The first deliverable, `docs/design.md`, is drafted: scope, the authority row, the cache and security policy, the gates and the benchmark cells, written before any code, with its proposed numbers waiting for the maintainer.

## Why

A resolver parses untrusted packets from the network all day and keeps a cache that an attacker would like to poison. Its popular implementations are written in C and have a long record of memory-safety bugs in exactly that parser. This project is the same job with bounds that are checked and an authority that is derived by the compiler (for the network, only as far as cancho's `Net` can say: see below).

The model is [`cancho-cache`](https://github.com/alpibrusl/cancho-cache): one thread, one poller, memory sized at start, every input bounded with its own refusal, and measurements against the incumbents fixed before the code.

## Intended scope (v1)

A forwarding cache:

- DNS over UDP and TCP, with EDNS0 and truncation;
- a cache with TTLs, negative caching and LRU eviction, in a fixed arena;
- forwarding to a fixed set of upstream resolvers (a compiled-in table in v1), with timeouts and health;
- local records, overrides and blocklists from a small bounded file (a compiled-in table in v1: `local.conf`, at most 512 directives, every bound a generation-time refusal naming file and line; a match answers with TTL 30, is never cached and never forwarded);
- the defences that matter: random transaction IDs and source ports, 0x20 case randomisation, bailiwick checks, response rate limiting;
- bounded JSON logs and metrics, with no files written: one line per query on standard error, off by default (a name is personal data), and a latency histogram answered at `histogram.bind`;
- operable by an agent: `introspect`, `skill`, `check`, `explain` and `diff` before it binds (all byte-stable, all validated against a published schema, the authority report embedded at a fixed point), errors as data with rule tags and repairs, and `stats.bind` / `histogram.bind` for the counters while it runs;

Not in v1: iterating from the root servers, DNSSEC validation (stage 2; cancho has RSA, ECDSA and Ed25519), DNS over TLS and HTTPS (TLS needs foreign code today, which would make the authority report unbounded), zone transfers, dynamic update, views and clustering.

## The question that decided the headline, answered

The epic asked how an upstream set could become a literal the compiler can check. Measured on cancho, the answer is that it cannot yet, for any layout: a `Net` is narrowed once; its one bound string is read as `host:port` outbound and as a port inbound, so a program that both listens and dials cannot carry a narrowed `Net` at all; and the host half is a plain prefix (a bound of `127.0.0.1` admitted `127.0.0.10`). The design therefore ships v1 on an unnarrowed `Net` with the upstream set in a compiled-in table, says so in the report, and files the language prerequisite: separate inbound and outbound bounds, set-valued bounds, and exact host matching. Until that lands, "names the exact upstreams" is a target, not a claim. Details and the reproduction are in [`docs/design.md`](docs/design.md) §2 and §3.

## What we expect, stated before measuring

A DNS packet is tiny, so throughput is limited by the kernel as much as by us. The honest aim is parity per core with much lower memory, and a security story the others cannot tell. **Measured on ours, on one loopback host with a cranelift build** ([`docs/numbers-d10.md`](docs/numbers-d10.md)): ~146,000 queries/s answered on the cache-hit path, ~5,500/s forwarded to an instant local stub, ~24,000/s over one persistent TCP connection, p50 0.06 ms on loopback, a 228 KB binary ready in ~8 ms, memory flat at the arena's size once warm (the first-touch phase measured to the end: +0 KiB over four consecutive 150,000-query rounds). The comparison against Unbound, dnsmasq, CoreDNS and Knot Resolver runs where they are installed (CI installs them), with the cells pre-registered in the design, and **no ratio is claimed here because none was measured on this host**. A big speed win is not the claim; losses will be reported as plainly as wins.

## Project page

[alpibrusl.github.io/cancho-dns](https://alpibrusl.github.io/cancho-dns/) (served from `docs/` once GitHub Pages is switched on for this repository).

## Contributing

Design before code, in `docs/design.md`, with claims measured; a gate is fixed before the code it judges and must be able to fail; a claim that turns out false is corrected in place. See the epic for the working rules.

## Licence

[EUPL-1.2](LICENSE).
