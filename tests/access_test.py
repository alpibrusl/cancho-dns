"""Gate 7 of docs/design.md section 16: who may ask. The server is built with an access list of 127.0.0.1/32 and 127.0.1.0/24 and
asked from other loopback addresses (Linux treats all of 127/8 as local, so a client can bind 127.0.0.2).

usage: access_test.py <cancho> [<binary>]
"""
import os, socket, struct, sys, tempfile, time, unittest

import dns.flags, dns.message, dns.rcode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

CANCHO = os.path.abspath(sys.argv.pop(1))
BINARY = os.path.abspath(sys.argv.pop(1)) if len(sys.argv) > 1 else None
CONF = "allow 127.0.0.1/32\nallow 127.0.1.0/24\n"
WORK = tempfile.mkdtemp(prefix="accesstest-")


def udp_from(source, port, wire, wait=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((source, 0)); s.settimeout(wait)
    s.sendto(wire, ("127.0.0.1", port))
    try:
        return s.recvfrom(4096)[0]
    except socket.timeout:
        return None
    finally:
        s.close()


class Access(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = BINARY or os.path.join(WORK, "access")
        if not BINARY:
            h.build(CANCHO, [], cls.binary, access_conf=CONF)
        cls.server = h.Server(cls.binary)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def q(self, name="n2.example."):
        return dns.message.make_query(name, "A").to_wire()

    def test_an_allowed_address_is_served_and_others_are_refused(self):
        s = self.server
        before = s.stats()
        r = udp_from("127.0.0.1", s.port, self.q())
        self.assertEqual(dns.message.from_wire(r).rcode(), 0)
        r = dns.message.from_wire(udp_from("127.0.1.77", s.port, self.q()))
        self.assertEqual(r.rcode(), 0); self.assertEqual(len(r.answer[0]), 2)
        for source in ("127.0.0.2", "127.0.2.1", "127.0.0.200"):
            wire = udp_from(source, s.port, self.q())
            self.assertIsNotNone(wire, source)
            r = dns.message.from_wire(wire)
            self.assertEqual(r.rcode(), 5, source)
            self.assertEqual(r.answer, [], source)
            # A refusal is no bigger than the query that earned it (plus an OPT it did not ask for: none).
            self.assertLessEqual(len(wire), len(self.q()))
        after = s.stats()
        self.assertEqual(after["acl_refused"] - before["acl_refused"], 3)
        # A refusal poisons nothing: the allowed client is served again, and the name was never asked of the cache as a refused one.
        r = dns.message.from_wire(udp_from("127.0.0.1", s.port, self.q()))
        self.assertEqual(r.rcode(), 0); self.assertEqual(len(r.answer[0]), 2)

    def test_garbage_and_responses_from_a_refused_address_get_nothing(self):
        s = self.server
        self.assertIsNone(udp_from("127.0.0.2", s.port, b"\x00\x01\x02", wait=0.5))
        resp = dns.message.make_query("n2.example.", "A"); resp.flags |= dns.flags.QR
        self.assertIsNone(udp_from("127.0.0.2", s.port, resp.to_wire(), wait=0.5))
        self.assertIsNone(udp_from("127.0.0.2", s.port, b"\x12\x34\x01\x00" + b"\xff" * 20, wait=0.5))

    def test_tcp_from_a_refused_address_is_closed_unread_and_from_an_allowed_one_is_served(self):
        s = self.server
        before = s.stats()
        c = socket.socket(); c.bind(("127.0.0.2", 0)); c.settimeout(3)
        c.connect(("127.0.0.1", s.port))
        wire = self.q()
        try:
            c.sendall(struct.pack(">H", len(wire)) + wire)
            data = c.recv(4096)
        except (ConnectionResetError, BrokenPipeError):
            data = b""
        self.assertEqual(data, b"")
        c.close()
        self.assertEqual(s.stats()["acl_refused"] - before["acl_refused"], 1)
        r = s.ask_tcp("n3.example.")
        self.assertEqual(len(r.answer[0]), 3)


if __name__ == "__main__":
    unittest.main(verbosity=1)
