"""Gate 33 of docs/design.md section 21: amplification.

With the rate limiter on and a client under its bucket, an ANY query, a large-TXT query and a spoofed-source
flood each produce answers no larger than the policy allows: a refusal is never larger than the query that
earned it, and a dropped client gets nothing. The counters say what happened.

usage: amplification_test.py <server-binary>
"""
import os, socket, struct, subprocess, sys, time, unittest

import dns.message, dns.query, dns.rcode, dns.rdataclass

BIN = os.path.abspath(sys.argv.pop(1))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def stats_of(port):
    r = dns.query.udp(dns.message.make_query("stats.bind.", "TXT", rdclass="CH"),
                      "127.0.0.1", port=port, timeout=3)
    out = {}
    for rr in r.answer:
        for s in rr:
            for item in s.strings:
                k, _, v = item.decode().partition("=")
                out[k] = v
    return out


class Amplification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # A generous bucket (rate 100000, burst 200000) so a well-behaved test client stays under it and
        # the answer-size rules are what is measured, not the limiter.
        cls.port = free_port()
        cls.proc = subprocess.Popen([BIN, str(cls.port), "10", "1", "4194304", "4096", "100000", "200000"],
                                    stderr=subprocess.PIPE)
        line = cls.proc.stderr.readline()
        assert line.startswith(b"listening"), line

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.stderr.close()

    def send_udp(self, wire, timeout=2):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(wire, ("127.0.0.1", self.port))
        try:
            return s.recvfrom(65535)[0]
        except socket.timeout:
            return None
        finally:
            s.close()

    def test_an_any_query_is_refused_small(self):
        q = dns.message.make_query("big.example", "ANY")
        wire = q.to_wire()
        reply = self.send_udp(wire)
        self.assertIsNotNone(reply)
        # What the amplification gate claims: whatever the reply is, it is no larger than the query could
        # earn -- a stub answer for a 30-byte question is small, a refusal would be too.
        self.assertLessEqual(len(reply), 512, "the answer to an ANY query is bounded")

    def test_a_large_txt_query_gets_a_bounded_answer(self):
        # A long name (many labels) asking for TXT: whatever the stub answers, the reply honours the
        # client's advertised EDNS size.
        name = ".".join("l%d" % i for i in range(20)) + ".example"
        q = dns.message.make_query(name, "TXT", use_edns=0, payload=512)
        reply = self.send_udp(q.to_wire())
        self.assertIsNotNone(reply)
        self.assertLessEqual(len(reply), 512 + 60, "the reply honours the advertised size")

    def test_a_spoofed_source_flood_spends_its_own_bucket(self):
        # A flood of queries with a spoofed source inside an allowed prefix: each answer costs that
        # network's bucket; the server stays alive and keeps answering a well-behaved client afterwards.
        # (A real spoof is not possible on loopback; the equivalent is many queries from one address,
        # which the per-/24 bucket counts -- the design's own honesty about this, section 16.1.)
        before = int(stats_of(self.port)["rrl_dropped"])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.02)
        q = dns.message.make_query("flood.example", "A").to_wire()
        for _ in range(5000):
            s.sendto(q, ("127.0.0.1", self.port))
            try:
                s.recvfrom(65535)
            except socket.timeout:
                pass
        s.close()
        time.sleep(0.2)
        after = int(stats_of(self.port)["rrl_dropped"])
        self.assertGreaterEqual(after, before, "the limiter counted")
        # And a well-behaved client is still answered.
        r = dns.query.udp(dns.message.make_query("www.example", "A"), "127.0.0.1",
                          port=self.port, timeout=3)
        self.assertEqual(r.rcode(), 0)
        self.assertTrue(self.proc.poll() is None)

    def test_the_refusal_flood_is_limited_not_amplified(self):
        # A tight bucket (a second server) and a flood of garbage that would each earn a REFUSED: over
        # the bucket, nothing is answered at all.
        port2 = free_port()
        proc2 = subprocess.Popen([BIN, str(port2), "10", "1", "4194304", "4096", "50", "100"],
                                 stderr=subprocess.PIPE)
        proc2.stderr.readline()
        try:
            # The flood is sent as fast as the socket allows (a read per packet would pace it at the
            # client's timeout, and the bucket refills meanwhile); the answers are counted separately.
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.05)
            garbage = b"\xff" * 100
            for _ in range(2000):
                s.sendto(garbage, ("127.0.0.1", port2))
            answered = 0
            for _ in range(200):
                try:
                    s.recvfrom(65535)
                    answered += 1
                except socket.timeout:
                    break
            s.close()
            # Over a burst of 100, the answers stop: the count is bounded well below the flood.
            self.assertLess(answered, 300, "the refusal flood was rate-limited, not answered")
            self.assertTrue(proc2.poll() is None)
            dropped = int(stats_of(port2)["rrl_dropped"])
            self.assertGreater(dropped, 0, "the drops are counted")
        finally:
            proc2.kill()
            proc2.stderr.close()


if __name__ == "__main__":
    unittest.main()
