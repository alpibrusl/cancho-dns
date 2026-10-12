"""Gate 12 of docs/design.md section 17: local records, overrides and blocklists. The server is built with a local
table of records, overrides and blocks and asked over UDP; a fake upstream asserts which queries arrive (it never
answers, so a forwarded query is a dnspython timeout).

usage: local_test.py <cancho> [<server-binary>]
"""
import os, socket, subprocess, sys, tempfile, time, unittest

import dns.exception, dns.flags, dns.message, dns.query, dns.rcode, dns.rdataclass, dns.rdatatype

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

CANCHO = os.path.abspath(sys.argv.pop(1))
BINARY = os.path.abspath(sys.argv.pop(1)) if len(sys.argv) > 1 else None
CONF = """\
record www.example A 192.0.2.1
override api.example A 192.0.2.2
block ads.example
block tracker.example 192.0.2.254
record *.corp A 192.0.2.3
record example TXT "hello"
record alias.example CNAME www.example
record mail.example MX 10 mx.example
record service.example SRV 0 0 8080 a.example
record www.example AAAA 2001:db8::1
record 1.0.2.192.in-addr.arpa PTR www.example
"""
WORK = tempfile.mkdtemp(prefix="localtest-")


class Upstream:
    """A fake upstream that records every query it receives and never answers."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.seen = []
        self.sock.settimeout(0.05)

    def drain(self):
        while True:
            try:
                wire, _ = self.sock.recvfrom(4096)
            except (socket.timeout, BlockingIOError):
                return
            self.seen.append(dns.message.from_wire(wire))


def build(out, conf=CONF, upstream=None):
    """Build a server with this local table (and an upstream, when given)."""
    import shutil
    work = tempfile.mkdtemp(prefix="localbuild-")
    conf_file = os.path.join(work, "local.conf")
    with open(conf_file, "w") as f:
        f.write(conf)
    tab = os.path.join(work, "localtab.cho")
    subprocess.run([sys.executable, os.path.join(h.ROOT, "tests", "gen_local.py"), conf_file, tab], check=True)
    ports = [upstream.port] if upstream else []
    h.build(CANCHO, ports, out, local_tab=tab)


class Local(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.upstream = Upstream()
        cls.binary = BINARY or os.path.join(WORK, "local-server")
        if not BINARY:
            build(cls.binary, CONF, cls.upstream)
        cls.server = h.Server(cls.binary)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.upstream.sock.close()

    def ask(self, name, qtype, timeout=2):
        q = dns.message.make_query(name, qtype)
        return dns.query.udp(q, "127.0.0.1", port=self.server.port, timeout=timeout)

    def rdata(self, name, qtype):
        return [str(x[0]) for x in self.ask(name, qtype).answer]

    def test_each_record_type_answers_with_the_right_wire_bytes(self):
        self.assertEqual(self.rdata("www.example", "A"), ["192.0.2.1"])
        self.assertEqual(self.rdata("www.example", "AAAA"), ["2001:db8::1"])
        self.assertEqual(self.rdata("example", "TXT"), ['"\\"hello\\""'])
        self.assertEqual(self.rdata("alias.example", "CNAME"), ["www.example."])
        self.assertEqual(self.rdata("mail.example", "MX"), ["10 mx.example."])
        self.assertEqual(self.rdata("service.example", "SRV"), ["0 0 8080 a.example."])
        self.assertEqual(self.rdata("1.0.2.192.in-addr.arpa", "PTR"), ["www.example."])
        self.assertEqual(self.ask("www.example", "A").answer[0].ttl, 30)

    def test_case_and_the_trailing_dot_do_not_matter(self):
        self.assertEqual(self.rdata("WWW.ExAmPlE", "A"), ["192.0.2.1"])
        self.assertEqual(self.rdata("www.example.", "A"), ["192.0.2.1"])

    def test_a_wildcard_matches_one_label_and_only_one(self):
        self.assertEqual(self.rdata("host.corp", "A"), ["192.0.2.3"])
        # The star is one label: `two.labels.corp` does not match, and the fake upstream never answers.
        with self.assertRaises(dns.exception.Timeout):
            self.ask("two.labels.corp", "A")

    def test_a_block_answers_nxdomain_and_never_reaches_the_upstream(self):
        self.upstream.drain()
        r = self.ask("ads.example", "A")
        self.assertEqual(r.rcode(), 3)
        self.assertEqual(r.answer, [])
        self.assertGreaterEqual(len(r.authority), 1)
        r = self.ask("tracker.example", "A")
        self.assertEqual(r.rcode(), 0)
        self.assertEqual([str(x[0]) for x in r.answer], ["192.0.2.254"])
        r = self.ask("tracker.example", "MX")
        self.assertEqual(r.rcode(), 3)
        time.sleep(0.1)
        self.upstream.drain()
        self.assertEqual([q.question[0].to_text() for q in self.upstream.seen], [])

    def test_a_record_is_not_cached(self):
        self.assertEqual(self.rdata("www.example", "A"), ["192.0.2.1"])
        first = int(self.stats()["local_answered"])
        self.assertGreaterEqual(first, 1)
        self.assertEqual(self.rdata("www.example", "A"), ["192.0.2.1"])
        self.assertEqual(int(self.stats()["local_answered"]), first + 1)

    def test_an_override_wins_even_against_a_cached_answer(self):
        self.upstream.drain()
        self.assertEqual(self.rdata("api.example", "A"), ["192.0.2.2"])
        self.assertEqual(self.rdata("api.example", "A"), ["192.0.2.2"])
        time.sleep(0.1)
        self.upstream.drain()
        for q in self.upstream.seen:
            self.assertNotIn("api.example", q.question[0].to_text())

    def test_a_query_that_matches_nothing_is_forwarded_as_before(self):
        self.upstream.drain()
        with self.assertRaises(dns.exception.Timeout):
            self.ask("unmatched.example", "A")
        time.sleep(0.1)
        self.upstream.drain()
        # The case is randomised (0x20) and the query retried, so compare the name folded.
        self.assertEqual([q.question[0].to_text().split()[0].lower() for q in self.upstream.seen],
                         ["unmatched.example.", "unmatched.example."])

    def stats(self):
        r = dns.query.udp(dns.message.make_query("stats.bind.", "TXT", rdclass="CH"), "127.0.0.1",
                          port=self.server.port, timeout=3)
        out = {}
        for rr in r.answer:
            for s in rr:
                for item in s.strings:
                    k, _, v = item.decode().partition("=")
                    out[k] = v
        return out


if __name__ == "__main__":
    unittest.main()
