<p align="center"><img src="docs/assets/cancho-dns-logo-256.png" alt="cancho-dns" width="200"></p>

# cancho-dns

**A DNS resolver you can audit.** A forwarding and caching resolver written in [cancho](https://github.com/alpibrusl/cancho): a bounded parser, a cache in a fixed arena, no `Ffi` and no `unsafe`, and an authority report that shows it has no foreign code, no processes and no file but its entropy source. A bug in the packet parser is a bounds trap, not a memory-safety hole. **Corrected from the first draft:** the report was meant to name the exact upstreams the program can reach, and cancho cannot prove that today (measured in [`docs/design.md`](docs/design.md) §2), so in v1 the upstream set is a compiled-in table enforced and checked in code, and the compiler-checked claim waits on language work.

**Status: design stage; the codec (D0) and a UDP and TCP server (D1), an answer cache (D2) a forwarder with a compiled-in upstream table (D3) and a compiled-in access list with a per-/24 response-rate limiter (D3b) are built; there is no benchmark and no `check`/`explain` yet.** There is no benchmark and no claim beyond what is written here. The plan and its tasks are in the epic, [cancho-dns#18](https://github.com/alpibrusl/cancho-dns/issues/18). The first deliverable, `docs/design.md`, is drafted: scope, the authority row, the cache and security policy, the gates and the benchmark cells, written before any code, with its proposed numbers waiting for the maintainer.

## Why

A resolver parses untrusted packets from the network all day and keeps a cache that an attacker would like to poison. Its popular implementations are written in C and have a long record of memory-safety bugs in exactly that parser. This project is the same job with bounds that are checked and an authority that is derived by the compiler (for the network, only as far as cancho's `Net` can say: see below).

The model is [`cancho-cache`](https://github.com/alpibrusl/cancho-cache): one thread, one poller, memory sized at start, every input bounded with its own refusal, and measurements against the incumbents fixed before the code.

## Intended scope (v1)

A forwarding cache:

- DNS over UDP and TCP, with EDNS0 and truncation;
- a cache with TTLs, negative caching and LRU eviction, in a fixed arena;
- forwarding to a fixed set of upstream resolvers (a compiled-in table in v1), with timeouts and health;
- local records from a small bounded file, and overrides;
- the defences that matter: random transaction IDs and source ports, 0x20 case randomisation, bailiwick checks, response rate limiting;
- bounded JSON logs and metrics, with no files written;
- operable by an agent: `introspect` and `skill`, errors as data with rule tags and repairs, and `check` and `explain` commands that say what a configuration or a query would do without sending anything.

Not in v1: iterating from the root servers, DNSSEC validation (stage 2; cancho has RSA, ECDSA and Ed25519), DNS over TLS and HTTPS (TLS needs foreign code today, which would make the authority report unbounded), zone transfers, dynamic update, views and clustering.

## The question that decided the headline, answered

The epic asked how an upstream set could become a literal the compiler can check. Measured on cancho, the answer is that it cannot yet, for any layout: a `Net` is narrowed once; its one bound string is read as `host:port` outbound and as a port inbound, so a program that both listens and dials cannot carry a narrowed `Net` at all; and the host half is a plain prefix (a bound of `127.0.0.1` admitted `127.0.0.10`). The design therefore ships v1 on an unnarrowed `Net` with the upstream set in a compiled-in table, says so in the report, and files the language prerequisite: separate inbound and outbound bounds, set-valued bounds, and exact host matching. Until that lands, "names the exact upstreams" is a target, not a claim. Details and the reproduction are in [`docs/design.md`](docs/design.md) §2 and §3.

## What we expect, stated before measuring

A DNS packet is tiny, so throughput is limited by the kernel as much as by us. The honest aim is parity per core with much lower memory, and a security story the others cannot tell. We will measure against Unbound, dnsmasq, CoreDNS and Knot Resolver, with the cells fixed before the code, and report losses as plainly as wins. A big speed win is not the claim.

## Project page

[alpibrusl.github.io/cancho-dns](https://alpibrusl.github.io/cancho-dns/) (served from `docs/` once GitHub Pages is switched on for this repository).

## Contributing

Design before code, in `docs/design.md`, with claims measured; a gate is fixed before the code it judges and must be able to fail; a claim that turns out false is corrected in place. See the epic for the working rules.

## Licence

[EUPL-1.2](LICENSE).
