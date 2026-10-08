"""Gate 13 of docs/design.md section 17: differential matching. A plain-Python reference (longest suffix, wildcard,
tie = error) over generated tables and queries, against the server's answers.

usage: differential_local.py <cancho>
"""
import os, random, socket, subprocess, sys, tempfile, time, unittest

import dns.exception, dns.message, dns.query, dns.rcode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

CANCHO = os.path.abspath(sys.argv.pop(1))
WORK = tempfile.mkdtemp(prefix="differential-local-")
PORT = None
BINARY = None


def wire(name):
    """A name to its lowercase label tuple; `*.` keeps the star as a label."""
    return tuple(l.lower() for l in name.rstrip(".").split("."))


def reference(table, qname, qtype):
    """The reference matcher: the directive with the longest concrete suffix that matches, or None.
    Returns (kind, rtype, rdata) where kind is 'record', 'override', 'block' or 'block_a'."""
    labels = wire(qname)
    t = {"A": 1, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}[qtype]
    best = None
    for kind, name, rtype, rdata in table:
        pat = wire(name)
        if pat[0] == "*":
            if len(pat) - 1 > len(labels) or tuple(labels[len(labels) - len(pat) + 1:]) != pat[1:]:
                continue
            concrete = len(pat) - 1
        else:
            if tuple(labels[len(labels) - len(pat):]) != pat:
                continue
            concrete = len(pat)
        if rtype != 0 and rtype != t:
            continue
        if best is None or concrete > best[0]:
            best = (concrete, kind, t if kind == "block_a" else rtype, rdata)
    return None if best is None else best[1:]


def make_table(seed):
    """A generated table: records, overrides, blocks and wildcards of every kind, no ties."""
    rng = random.Random(seed)
    zones = ["example", "test", "corp"]
    table = []
    used = set()

    def unique(name, pattern):
        # The generator refuses a tie: two directives of the same shape (both exact, or both wildcards) whose
        # patterns can match one name, at overlapping types (a block overlaps every type). So the pattern is the
        # key, and a block excludes every other directive of the same shape for the same name.
        for (u, ublock) in used:
            if u != pattern:
                continue
            return False
        used.add((pattern, pattern.startswith("*.")))
        return True

    for i in range(rng.randint(30, 120)):
        zone = rng.choice(zones)
        host = "h%d" % i
        name = rng.choice([host, "*." + host, zone])
        full = name if name == zone else "%s.%s" % (name, zone)
        kind = rng.choices(["record", "override", "block", "block_a"], [5, 2, 2, 1])[0]
        if kind in ("record", "override"):
            if not unique(full, full):
                continue
            qtype, rdata = rng.choice([
                ("A", "10.1.%d.%d" % (i % 256, i % 97)),
                ("AAAA", "2001:db8::%d" % i),
                ("TXT", '"t%d"' % i),
                ("CNAME", "h%d.%s." % (i, zone)),
                ("MX", "10 h%d.%s." % (i, zone)),
                ("SRV", "0 0 %d h%d.%s." % (i % 65536, i, zone)),
                ("PTR", "h%d.%s." % (i, zone)),
            ])
            table.append((kind, full, qtype, rdata))
        else:
            if not unique(full, full):
                continue
            if kind == "block_a":
                table.append(("block_a", full, "A", "10.9.9.%d" % (i % 254 + 1)))
            else:
                table.append(("block", full, "*", None))
    return table


def conf_of(table):
    out = []
    for kind, name, t, rdata in table:
        if kind in ("record", "override"):
            out.append("%s %s %s %s" % (kind, name, t, rdata))
        elif kind == "block_a":
            out.append("block %s %s" % (name, rdata))
        else:
            out.append("block %s" % name)
    return "\n".join(out) + "\n"


class Differential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global PORT, BINARY
        cls.tables = [(seed, make_table(seed)) for seed in range(6)]
        # One server per table would be slow; the reference is pure Python, so ask one server per table in turn.
        cls.servers = []
        for seed, table in cls.tables:
            conf = conf_of(table)
            work = tempfile.mkdtemp(prefix="diffbuild-")
            conf_file = os.path.join(work, "local.conf")
            open(conf_file, "w").write(conf)
            tab = os.path.join(work, "localtab.cho")
            subprocess.run([sys.executable, os.path.join(h.ROOT, "tests", "gen_local.py"), conf_file, tab], check=True)
            binary = os.path.join(work, "server")
            h.build(CANCHO, [], binary, local_tab=tab)
            cls.servers.append((table, h.Server(binary)))

    @classmethod
    def tearDownClass(cls):
        for _t, server in cls.servers:
            server.stop()

    def ask(self, server, name, qtype):
        q = dns.message.make_query(name, qtype)
        return dns.query.udp(q, "127.0.0.1", port=server.port, timeout=2)

    def test_the_server_agrees_with_the_reference(self):
        rng = random.Random(12345)
        checked = 0
        for (seed, table), server in [(self.tables[i], self.servers[i][1]) for i in range(len(self.tables))]:
            names = set()
            for kind, name, t, rdata in table:
                names.add(name)
                if name.startswith("*."):
                    names.add("x." + name[2:])
                    names.add("y.z." + name[2:])
                base = name[2:] if name.startswith("*.") else name
                names.add("unmatched." + base)
                names.add(base.upper())
            for name in sorted(names):
                for qtype in ("A", "TXT", "MX"):
                    r = self.ask(server, name, qtype)
                    want = reference(table, name, qtype)
                    if want is None:
                        # No directive matches: the answer comes from the stub (NOERROR with records, or NXDOMAIN
                        # for the names the stub says do not exist). Only the reply's existence is checked here;
                        # the stub's own gates (tests/stub_test.cho) cover its answers.
                        self.assertIn(r.rcode(), (0, 3), (name, qtype))
                    else:
                        kind, t, rdata = want
                        if kind in ("block",) or (kind == "block_a" and qtype != "A"):
                            self.assertEqual(r.rcode(), 3, (name, qtype, kind))
                        else:
                            self.assertEqual(r.rcode(), 0, (name, qtype, kind))
                            if kind == "block_a":
                                self.assertEqual([str(x[0]) for x in r.answer], [rdata])
                            else:
                                self.assertEqual([str(x[0]) for x in r.answer], [rdata],
                                                 (name, qtype, rdata, [str(x[0]) for x in r.answer]))
                    checked += 1
        self.assertGreater(checked, 200)


if __name__ == "__main__":
    unittest.main()
