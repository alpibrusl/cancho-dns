<p align="center"><img src="docs/assets/cancho-dns-logo-256.png" alt="cancho-dns" width="200"></p>

# cancho-dns

**A DNS resolver you can audit.** A forwarding and caching resolver written in [cancho](https://github.com/alpibrusl/cancho): a bounded parser, a cache in a fixed arena, no `Ffi` and no `unsafe`, and an authority report that is meant to name the upstreams it can reach and nothing else. A bug in the packet parser cannot turn it into a way to reach arbitrary hosts.

**Status: design stage. Nothing is built.** There is no code, no benchmark and no claim beyond what is written here. The plan and its tasks are in the epic, [cancho-dns#17](https://github.com/alpibrusl/cancho-dns/issues/17). The first deliverable is `docs/design.md`: scope, the authority row, the cache and security policy, the gates and the benchmark cells, written before any code.

## Why

A resolver parses untrusted packets from the network all day and keeps a cache that an attacker would like to poison. Its popular implementations are written in C and have a long record of memory-safety bugs in exactly that parser. This project is the same job with bounds that are checked and an authority that is proven by the compiler.

The model is [`cancho-cache`](https://github.com/alpibrusl/cancho-cache): one thread, one poller, memory sized at start, every input bounded with its own refusal, and measurements against the incumbents fixed before the code.

## Intended scope (v1)

A forwarding cache:

- DNS over UDP and TCP, with EDNS0 and truncation;
- a cache with TTLs, negative caching and LRU eviction, in a fixed arena;
- forwarding to a fixed set of upstream resolvers, with timeouts and health;
- local records from a small bounded file, and overrides;
- the defences that matter: random transaction IDs and source ports, 0x20 case randomisation, bailiwick checks, response rate limiting;
- bounded JSON logs and metrics, with no files written;
- operable by an agent: `introspect` and `skill`, errors as data with rule tags and repairs, and `check` and `explain` commands that say what a configuration or a query would do without sending anything.

Not in v1: iterating from the root servers, DNSSEC validation (stage 2; cancho has RSA, ECDSA and Ed25519), DNS over TLS and HTTPS (TLS needs foreign code today, which would make the authority report unbounded), zone transfers, dynamic update, views and clustering.

## An open question that decides the headline

The compiler narrows a capability to a **literal**, so an upstream list read from a file at run time cannot be proven by the authority report. The design has to choose between a generated, compiled-in upstream set (an exact proof, one binary per deployment), a coarser label enforced in code (which gives up the headline), or a mix. The claim above is conditional on that answer.

## What we expect, stated before measuring

A DNS packet is tiny, so throughput is limited by the kernel as much as by us. The honest aim is parity per core with much lower memory, and a security story the others cannot tell. We will measure against Unbound, dnsmasq, CoreDNS and Knot Resolver, with the cells fixed before the code, and report losses as plainly as wins. A big speed win is not the claim.

## Project page

[alpibrusl.github.io/cancho-dns](https://alpibrusl.github.io/cancho-dns/) (served from `docs/` once GitHub Pages is switched on for this repository).

## Contributing

Design before code, in `docs/design.md`, with claims measured; a gate is fixed before the code it judges and must be able to fail; a claim that turns out false is corrected in place. See the epic for the working rules.

## Licence

[EUPL-1.2](LICENSE).
