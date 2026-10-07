#!/usr/bin/env python3
"""Gate 1 of docs/design.md section 8: the codec against dnspython.

    python3 tests/differential_codec.py build/driver [--seed N] [--valid N] [--mutants N]

A corpus of real messages (built with dnspython: queries with and without EDNS, responses with every record type the
codec looks inside, compressed names) and a larger one made by mutating them, is parsed by `tests/driver.cho` (the
codec behind a pipe) and by `dns.message.from_wire`. For each message:

* both accept: the header, the question, every record's owner name, type, class and TTL, the data length where
  dnspython's re-encoding preserves it, and the OPT fields must agree;
* both refuse: agreement, whatever the reasons;
* we refuse and dnspython accepts: allowed only for the codes in DELIBERATE, the refusals this codec makes on
  purpose (docs/design.md section 5). Each has a constructed message below that must show exactly that
  divergence, so the list cannot go stale: if dnspython starts refusing it, or the codec stops, this fails;
* we accept and dnspython refuses: allowed only when the message carries data the codec does not look inside and
  dnspython does: a record of a type outside CHECKED, or an EDNS option dnspython interprets.

Anything else is a failure, with the message in hex. Exit status 0 only if there is none.
"""

import argparse
import random
import struct
import subprocess
import sys

import dns.edns
import dns.exception
import dns.message
import dns.name
import dns.rrset

# The refusals the codec makes that dnspython does not (and the only ones). Everything else is a refusal both make.
DELIBERATE = {"dns-bad-counts", "dns-too-many-records", "dns-bad-pointer"}

# The record types the codec looks inside; the data of any other is opaque to it.
CHECKED = {1, 2, 5, 6, 12, 15, 28, 33, 39, 41}

# Types whose data dnspython re-encodes without compression to the same length it had on the wire.
STABLE_LENGTH = {1, 28, 16}

# EDNS option codes dnspython interprets (and validates) when it parses: DAU, DHU, N3U, ECS, EXPIRE, COOKIE, KEEPALIVE,
# PADDING, CHAIN, KEY TAG, EDE. The codec leaves option data alone (docs/design.md section 5).
INTERPRETED_OPTIONS = set(range(5, 17))


def hdr(id=0x1234, flags=0x0100, qd=1, an=0, ns=0, ar=0):
    return struct.pack(">HHHHHH", id, flags, qd, an, ns, ar)


QUESTION = b"\x07example\x03com\x00\x00\x01\x00\x01"


def rr(owner, rtype, rclass, ttl, rdata):
    return owner + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def hop_chain(hops):
    message = hdr(an=hops) + QUESTION
    previous, body = 12, b""
    for _ in range(hops):
        here = len(message) + len(body)
        body += struct.pack(">H", 0xC000 | previous) + struct.pack(">HHIH", 10, 1, 0, 0)
        previous = here
    return message + body


def labels(count, size, last=None):
    out = (bytes([size]) + b"a" * size) * count
    if last is not None:
        out += bytes([last]) + b"a" * last
    return out + b"\x00"


def named(name_wire):
    return hdr() + name_wire + b"\x00\x01\x00\x01"


ADDRESS = b"\1\2\3\4"

# Constructed cases: (name, wire, our tag or None for accepted, whether dnspython accepts).
CASES = [
    # The codec refuses on purpose what dnspython accepts.
    ("two questions", hdr(qd=2) + QUESTION + QUESTION, "dns-bad-counts", True),
    ("zero questions", hdr(qd=0), "dns-bad-counts", True),
    ("65 answers", hdr(an=65) + QUESTION + rr(b"\xc0\x0c", 1, 1, 30, ADDRESS) * 65, "dns-too-many-records", True),
    ("17 authority", hdr(ns=17) + QUESTION + rr(b"\xc0\x0c", 1, 1, 30, ADDRESS) * 17, "dns-too-many-records", True),
    ("33 additional", hdr(ar=33) + QUESTION + rr(b"\xc0\x0c", 1, 1, 30, ADDRESS) * 33, "dns-too-many-records", True),
    # A pointer to byte 0, where id 0x0161 and flags 0x0000 read as the name "a.": legal for dnspython.
    (
        "pointer into the header",
        struct.pack(">HHHHHH", 0x0161, 0, 1, 1, 0, 0) + QUESTION + rr(b"\xc0\x00", 1, 1, 30, ADDRESS),
        "dns-bad-pointer",
        True,
    ),
    ("17 pointer hops", hop_chain(17), "dns-bad-pointer", True),
    # Both refuse.
    ("OPT in the answers", hdr(an=1) + QUESTION + rr(b"\x00", 41, 1232, 0, b""), "dns-bad-edns", False),
    ("two OPTs", hdr(ar=2) + QUESTION + rr(b"\x00", 41, 1232, 0, b"") * 2, "dns-bad-edns", False),
    ("OPT owned by a pointer", hdr(ar=1) + QUESTION + rr(b"\xc0\x0c", 41, 1232, 0, b""), "dns-bad-edns", False),
    (
        "OPT options not tiled",
        hdr(ar=1) + QUESTION + rr(b"\x00", 41, 1232, 0, b"\x00\x0a\x00\x05\x01"),
        "dns-bad-edns",
        False,
    ),
    ("A of 3 bytes", hdr(an=1) + QUESTION + rr(b"\xc0\x0c", 1, 1, 30, b"\1\2\3"), "dns-bad-rdata", False),
    ("a trailing byte", hdr() + QUESTION + b"\x00", "dns-trailing-bytes", False),
    ("label type 01", hdr() + b"\x47" + b"a" * 7 + b"\x00\x00\x01\x00\x01", "dns-label-too-long", False),
    ("pointer forwards", hdr(an=1) + QUESTION + rr(b"\xc0\x40", 1, 1, 30, ADDRESS), "dns-bad-pointer", False),
    ("a 256-byte name", named(labels(3, 63, 62)), "dns-name-too-long", False),
    ("a message of 11 bytes", b"\x00" * 11, "dns-bad-header", False),
    # Both accept.
    ("a 255-byte name", named(labels(3, 63, 61)), None, True),
    ("16 pointer hops", hop_chain(16), None, True),
]


def random_label(rng):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 20)))


def random_name(rng, minimum=1):
    return dns.name.from_text(".".join(random_label(rng) for _ in range(rng.randint(minimum, 5))) + ".")


def random_rrset(rng, owner):
    kind = rng.choice(["A", "AAAA", "NS", "CNAME", "PTR", "DNAME", "MX", "SOA", "TXT", "SRV", "UNKNOWN"])
    ttl = rng.choice([0, 1, 30, 300, 86400, 2**31 - 1])
    other = random_name(rng).to_text()
    if kind == "A":
        text = ".".join(str(rng.randint(0, 255)) for _ in range(4))
    elif kind == "AAAA":
        text = ":".join("%x" % rng.randint(0, 65535) for _ in range(8))
    elif kind in ("NS", "CNAME", "PTR", "DNAME"):
        text = other
    elif kind == "MX":
        text = "%d %s" % (rng.randint(0, 65535), other)
    elif kind == "SOA":
        text = "%s %s %d %d %d %d %d" % (other, random_name(rng).to_text(), *[rng.randint(0, 2**31) for _ in range(5)])
    elif kind == "TXT":
        text = " ".join('"%s"' % random_label(rng) for _ in range(rng.randint(1, 3)))
    elif kind == "SRV":
        text = "%d %d %d %s" % (rng.randint(0, 65535), rng.randint(0, 65535), rng.randint(0, 65535), other)
    else:
        return dns.rrset.from_text(owner, ttl, "IN", "TYPE65280", "\\# 4 deadbeef")
    return dns.rrset.from_text(owner, ttl, "IN", kind, text)


def random_options(rng):
    def noise(low, high):
        return bytes(rng.randrange(256) for _ in range(rng.randint(low, high)))

    return [
        rng.choice(
            [
                dns.edns.GenericOption(3, noise(0, 12)),
                dns.edns.GenericOption(65001, noise(0, 12)),
                dns.edns.CookieOption(noise(8, 8), b""),
                dns.edns.ECSOption("192.0.2.0", rng.choice([0, 8, 24]), 0),
            ]
        )
    ]


def valid_messages(rng, count):
    out = []
    for _ in range(count):
        qname = random_name(rng)
        rdtype = rng.choice([1, 28, 2, 5, 15, 16, 6, 12, 33, 255, 65280])
        edns = rng.choice([-1, 0, 0])
        options = random_options(rng) if edns >= 0 and rng.random() < 0.5 else []
        query = dns.message.make_query(
            qname,
            rdtype,
            use_edns=edns,
            payload=rng.choice([512, 1232, 4096]),
            want_dnssec=rng.random() < 0.3,
            options=options,
        )
        query.id = rng.randrange(65536)
        out.append(query.to_wire(max_size=65535))
        if rng.random() < 0.8:
            response = dns.message.make_response(query)
            for section in (response.answer, response.authority, response.additional):
                for _ in range(rng.randint(0, 4 if section is response.answer else 2)):
                    owner = rng.choice([qname, random_name(rng), qname.parent() if len(qname) > 2 else qname])
                    section.append(random_rrset(rng, owner))
            if rng.random() < 0.2:
                response.set_rcode(rng.choice([0, 2, 3, 5]))
            out.append(response.to_wire(max_size=65535))
    return out


INTERESTING = [0, 1, 2, 3, 12, 63, 64, 127, 128, 191, 192, 193, 255]


def mutate(rng, wire):
    data = bytearray(wire)
    kind = rng.randrange(7)
    if kind == 0 and data:
        for _ in range(rng.randint(1, 3)):
            data[rng.randrange(len(data))] = rng.choice(INTERESTING + [rng.randrange(256)])
    elif kind == 1 and data:
        del data[rng.randrange(len(data)) :]
    elif kind == 2:
        data += bytes(rng.randrange(256) for _ in range(rng.randint(1, 4)))
    elif kind == 3 and data:
        del data[rng.randrange(len(data))]
    elif kind == 4:
        data.insert(rng.randrange(len(data) + 1), rng.choice(INTERESTING))
    elif kind == 5 and len(data) >= 12:
        data[4 + 2 * rng.randrange(4) + 1] = rng.randrange(256)  # a count
    elif kind == 6 and len(data) > 12:
        # A compression pointer written over two bytes of the body.
        i = rng.randrange(12, len(data) - 1)
        data[i] = 0xC0 | rng.randrange(64)
        data[i + 1] = rng.randrange(min(256, max(1, i + 3)))
    return bytes(data)


def run_driver(driver, wires):
    text = "".join(w.hex() + "\n" for w in wires)
    done = subprocess.run([driver], input=text, capture_output=True, text=True, timeout=600)
    if done.returncode != 0:
        sys.exit("the driver exited %d: %s" % (done.returncode, done.stderr[-400:]))
    lines = done.stdout.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) != len(wires):
        sys.exit("the driver answered %d lines for %d messages" % (len(lines), len(wires)))
    return lines


def parse_ours(line):
    if line.startswith("ERR"):
        _, code, tag = line.split()
        return {"ok": False, "code": int(code), "tag": tag}
    head, *records = line.split(" |")
    fields = head.split()
    assert fields[0] == "OK", line
    values = [int(x) for x in fields[1:7]]
    qtype, qclass = int(fields[7]), int(fields[8])
    qname = bytes.fromhex(fields[9])
    opt, size, ext, version, eflags = (int(x) for x in fields[10:15])
    recs = []
    for r in records:
        t, c, ttl, rdlen, offset, owner = r.split()
        recs.append(
            {"type": int(t), "class": int(c), "ttl": int(ttl), "rdlen": int(rdlen), "offset": int(offset), "owner": bytes.fromhex(owner)}
        )
    return {
        "ok": True,
        "id": values[0],
        "flags": values[1],
        "counts": values[2:6],
        "qtype": qtype,
        "qclass": qclass,
        "qname": qname,
        "opt": opt,
        "udp": size,
        "ext": ext,
        "version": version,
        "eflags": eflags,
        "records": recs,
    }


def reference(wire):
    try:
        return dns.message.from_wire(wire, one_rr_per_rrset=True), None
    except Exception as e:  # dnspython raises many types; any of them is a refusal
        return None, type(e).__name__


def compare(wire, ours, ref):
    """Why `ours` and `ref` (an accepted message) disagree, or None."""
    if (ours["id"], ours["flags"]) != struct.unpack(">HH", wire[:4]):
        return "header id or flags"
    if ours["counts"] != list(struct.unpack(">HHHH", wire[4:12])):
        return "header counts"
    q = ref.question[0]
    if (ours["qtype"], ours["qclass"], ours["qname"]) != (q.rdtype, q.rdclass, q.name.to_wire()):
        return "question"
    theirs = []
    for section in (ref.answer, ref.authority, ref.additional):
        for rrset in section:
            rdlen = len(rrset[0].to_wire()) if rrset.rdtype in STABLE_LENGTH else None
            theirs.append((rrset.rdtype, rrset.rdclass, rrset.ttl, rdlen, rrset.name.to_wire()))
    mine = [r for r in ours["records"] if r["type"] != 41]
    if len(mine) != len(theirs):
        return "record count %d vs %d" % (len(mine), len(theirs))
    for a, b in zip(mine, theirs):
        if (a["type"], a["class"], a["ttl"], a["owner"]) != (b[0], b[1], b[2], b[4]):
            return "record %r vs %r" % (a, b)
        if b[3] is not None and a["rdlen"] != b[3]:
            return "record data length %r vs %r" % (a, b)
    if ref.edns >= 0:
        if ours["opt"] < 0:
            return "OPT missing"
        flags = ref.ednsflags
        if (ours["udp"], ours["ext"], ours["version"], ours["eflags"]) != (
            ref.payload,
            flags >> 24 & 0xFF,
            flags >> 16 & 0xFF,
            flags & 0xFFFF,
        ):
            return "OPT fields"
    elif ours["opt"] >= 0:
        return "OPT present"
    return None


def interprets_options(wire, ours):
    """Does an OPT record carry an option whose data dnspython checks and the codec does not?"""
    for r in ours["records"]:
        if r["type"] != 41:
            continue
        at, end = r["offset"], r["offset"] + r["rdlen"]
        while at + 4 <= end:
            code, size = struct.unpack(">HH", wire[at : at + 4])
            if code in INTERPRETED_OPTIONS:
                return True
            at += 4 + size
    return False


def opaque(wire, ours):
    """Is there data the codec does not look inside, which dnspython does?"""
    return any(r["type"] not in CHECKED for r in ours["records"]) or interprets_options(wire, ours)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("driver")
    ap.add_argument("--seed", type=int, default=20261007)
    ap.add_argument("--valid", type=int, default=1500)
    ap.add_argument("--mutants", type=int, default=12)
    args = ap.parse_args()
    rng = random.Random(args.seed)

    failures = []
    # 1. The constructed cases: each divergence, and each agreement, shown exactly.
    wires = [w for _, w, _, _ in CASES]
    for (name, wire, tag, ref_accepts), line in zip(CASES, run_driver(args.driver, wires)):
        ours = parse_ours(line)
        ref, why = reference(wire)
        got_tag = None if ours["ok"] else ours["tag"]
        if got_tag != tag:
            failures.append((name, "we answered %s, expected %s" % (got_tag, tag), wire))
        if (ref is not None) != ref_accepts:
            failures.append(
                (
                    name,
                    "dnspython %s, expected %s: the divergence list is stale"
                    % ("accepts" if ref is not None else "refuses (%s)" % why, "accept" if ref_accepts else "refuse"),
                    wire,
                )
            )
        if ours["ok"] and ref is not None:
            problem = compare(wire, ours, ref)
            if problem:
                failures.append((name, problem, wire))

    # 2. The corpus and its mutants.
    valid = valid_messages(rng, args.valid)
    corpus = list(valid)
    for w in valid:
        corpus.extend(mutate(rng, w) for _ in range(args.mutants))
    stats = {"both accept": 0, "both refuse": 0, "opaque-data leniency": 0}
    deliberate = {}
    for wire, line in zip(corpus, run_driver(args.driver, corpus)):
        ours = parse_ours(line)
        ref, why = reference(wire)
        if ours["ok"] and ref is not None:
            problem = compare(wire, ours, ref)
            if problem:
                failures.append(("corpus", problem, wire))
            else:
                stats["both accept"] += 1
        elif not ours["ok"] and ref is None:
            stats["both refuse"] += 1
        elif not ours["ok"]:
            if ours["tag"] in DELIBERATE:
                deliberate[ours["tag"]] = deliberate.get(ours["tag"], 0) + 1
            else:
                failures.append(("corpus", "we refuse (%s) and dnspython accepts" % ours["tag"], wire))
        else:
            if opaque(wire, ours):
                stats["opaque-data leniency"] += 1
            else:
                failures.append(("corpus", "we accept and dnspython refuses (%s)" % why, wire))

    print("cases: %d constructed, %d in the corpus (%d valid, seed %d)" % (len(CASES), len(corpus), len(valid), args.seed))
    for k, v in stats.items():
        print("  %-24s %d" % (k, v))
    for k, v in sorted(deliberate.items()):
        print("  deliberate refusal %-22s %d" % (k, v))
    # A corpus that exercised none of this proved nothing.
    if stats["both accept"] < len(valid) * 0.9:
        failures.append(
            ("corpus", "fewer than 90%% of the valid messages were accepted by both (%d of %d)" % (stats["both accept"], len(valid)), b"")
        )
    if stats["both refuse"] < len(valid):
        failures.append(("corpus", "the mutants refused too rarely to test the refusals (%d)" % stats["both refuse"], b""))
    if failures:
        print("\n%d FAILURES" % len(failures))
        for where, why, wire in failures[:20]:
            print("  [%s] %s\n    %s" % (where, why, wire.hex()))
        sys.exit(1)
    print("ok")


if __name__ == "__main__":
    main()
