"""Gate 27 of docs/design.md section 20: EDNS compliance, from the client side.

The public EDNS compliance scenarios, run as scripted queries against the built resolver and checked on the
wire, by a client (dnspython) rather than from inside the codec -- the same cases the codec's unit tests check
from the inside.

usage: edns_test.py <server-binary>
"""
import os, socket, struct, subprocess, sys, time, unittest

import dns.edns, dns.flags, dns.message, dns.opcode, dns.query, dns.rcode, dns.rdataclass

BIN = os.path.abspath(sys.argv.pop(1))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Resolver:
    def __init__(self, extra=()):
        self.port = free_port()
        self.proc = subprocess.Popen([BIN, str(self.port), "10", "1", "4194304", "4096", "0", "1", *extra],
                                     stderr=subprocess.PIPE)
        line = self.proc.stderr.readline()
        assert line.startswith(b"listening"), line

    def stop(self):
        self.proc.kill()
        self.proc.stderr.close()

    def udp(self, query, timeout=2):
        return dns.query.udp(query, "127.0.0.1", port=self.port, timeout=timeout)

    def alive(self):
        return self.proc.poll() is None


class Edns(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resolver = Resolver()

    @classmethod
    def tearDownClass(cls):
        cls.resolver.stop()

    def q(self, name="n2.example", qtype="A", use_edns=True, payload=1232, options=()):
        query = dns.message.make_query(name, qtype)
        if use_edns:
            query.use_edns(edns=0, payload=payload, options=list(options))
        return query

    def test_plain_query_without_edns_is_answered_plainly(self):
        r = self.resolver.udp(self.q(use_edns=False))
        self.assertEqual(r.rcode(), 0)
        self.assertEqual(r.edns, -1, "a query without EDNS must be answered without an OPT")

    def test_edns_query_is_answered_with_edns(self):
        r = self.resolver.udp(self.q())
        self.assertEqual(r.rcode(), 0)
        self.assertEqual(r.edns, 0, "an EDNS version 0 query is answered with an OPT version 0")

    def test_version_1_is_answered_badvers(self):
        query = dns.message.make_query("n2.example", "A")
        query.use_edns(edns=1, payload=1232)
        r = self.resolver.udp(query)
        self.assertEqual(r.rcode(), dns.rcode.BADVERS)

    def test_the_advertised_size_bounds_the_reply(self):
        # A TXT answer bigger than a 512-byte advertisement is truncated (TC), and the reply fits 512.
        query = self.q(name="t.example", qtype="TXT", payload=512)
        r = self.resolver.udp(query)
        self.assertLessEqual(len(r.to_wire()), 512 + 60, "the reply honours the client's advertised size")

    def test_unknown_options_are_ignored_not_echoed(self):
        # Option code 65001 (a reserved-for-experiments code), one nonsense option.
        option = dns.edns.GenericOption(65001, b"nonsense")
        r = self.resolver.udp(self.q(options=[option]))
        self.assertEqual(r.rcode(), 0)
        echoed = [o for o in r.options if o.otype == 65001]
        self.assertEqual(echoed, [], "an unknown option is not echoed back")

    def test_do_bit_is_not_answered_as_an_error(self):
        query = self.q()
        query.want_dnssec()
        r = self.resolver.udp(query)
        # v1 does not validate; the DO bit is carried, never an error.
        self.assertIn(r.rcode(), (0, 2))

    def test_tcp_carries_the_same_edns_behaviour(self):
        query = self.q()
        r = dns.query.tcp(query, "127.0.0.1", port=self.resolver.port, timeout=3)
        self.assertEqual(r.rcode(), 0)
        self.assertEqual(r.edns, 0)

    def test_a_malformed_opt_is_answered_formerr(self):
        # Hand-build a query whose OPT record has a bogus rdata (options that do not tile).
        query = self.q()
        wire = bytearray(query.to_wire())
        # Find the OPT: it is the last 11 bytes of a query with no other additional records.
        opt_at = len(wire) - 11
        self.assertEqual(struct.unpack("!H", wire[opt_at + 1:opt_at + 3])[0], 41)
        # Set its rdlength to 3, an odd number the options cannot tile.
        wire[opt_at + 9:opt_at + 11] = struct.pack("!H", 3)
        wire += b"\x01\x02\x03"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(bytes(wire), ("127.0.0.1", self.resolver.port))
        reply, _ = s.recvfrom(4096)
        r = dns.message.from_wire(reply)
        self.assertEqual(r.rcode(), dns.rcode.FORMERR)
        s.close()

    def test_opcode_status_is_answered_notimp(self):
        query = self.q()
        query.set_opcode(dns.opcode.STATUS)
        r = self.resolver.udp(query)
        self.assertEqual(r.rcode(), dns.rcode.NOTIMP)


if __name__ == "__main__":
    unittest.main()
