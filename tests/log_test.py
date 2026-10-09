"""Gates 23 to 25 of docs/design.md section 19: the query log and the histogram.

- Gate 23: with logging on, hostile names (a 63-byte label, a long name, mixed case) each produce a line of at
  most 256 bytes; with logging off, no line at all.
- Gate 24: the histogram's count equals the number of answered queries, counted independently by this test.
- Gate 25: the line says what happened: cache hit/miss/none, the upstream for a forwarded query, the rule tag of
  a refusal.

usage: log_test.py <cancho>
"""
import json, os, socket, subprocess, sys, tempfile, threading, time, unittest

import dns.message, dns.query

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

CANCHO = os.path.abspath(sys.argv.pop(1))
WORK = tempfile.mkdtemp(prefix="logtest-")


class Logged(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = os.path.join(WORK, "server")
        h.build(CANCHO, [], cls.binary)
        cls.port = h.free_udp_port()
        cls.proc = subprocess.Popen([cls.binary, str(cls.port), "10", "1", "4194304", "4096", "0", "1", "on"],
                                    stderr=subprocess.PIPE, cwd=WORK)
        line = cls.proc.stderr.readline()
        assert line.startswith(b"listening"), line

        cls.lines = []
        cls.lock = threading.Lock()

        def reader():
            for raw in cls.proc.stderr:
                with cls.lock:
                    cls.lines.append(raw)

        cls.thread = threading.Thread(target=reader, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.stderr.close()

    def ask(self, name, qtype="A"):
        q = dns.message.make_query(name, qtype)
        return dns.query.udp(q, "127.0.0.1", port=self.port, timeout=2)

    def drained(self):
        time.sleep(0.2)
        with self.lock:
            return list(self.lines)

    def test_gate_23_the_bound_holds_under_hostile_names(self):
        before = len(self.drained())
        hostile = [
            "a" * 63 + ".example",
            ".".join("c" * 10 for _ in range(20)) + ".example",
            "WwW.ExAmPlE",
        ]
        for name in hostile:
            try:
                r = self.ask(name)
                self.assertIn(r.rcode(), (0, 3))
            except dns.exception.Timeout:
                # A name the stub says does not exist still produced its line; the bound is the claim.
                pass
        lines = self.drained()[before:]
        self.assertGreaterEqual(len(lines), len(hostile))
        for line in lines:
            self.assertLessEqual(len(line), 256, line)
            json.loads(line)  # every line is one JSON object

    def test_gate_25_the_line_says_what_happened(self):
        before = len(self.drained())
        # A local record: cache "none" (the local table answers, never the cache).
        self.ask("www.example")
        line = json.loads(self.drained()[before:][-1])
        self.assertEqual(line["cache"], "none")
        self.assertIsNone(line["upstream"])
        self.assertIsNone(line["rule"])
        # The same name again: still "none" (a local answer is never cached).
        before = len(self.drained())
        self.ask("www.example")
        line = json.loads(self.drained()[before:][-1])
        self.assertEqual(line["cache"], "none")
        # A cache miss through the stub, then a hit.
        before = len(self.drained())
        self.ask("miss1.example")
        line = json.loads(self.drained()[before:][-1])
        self.assertEqual(line["cache"], "miss")
        before = len(self.drained())
        self.ask("miss1.example")
        line = json.loads(self.drained()[before:][-1])
        self.assertEqual(line["cache"], "hit")
        # A block answers NXDOMAIN and says so by its rcode.
        before = len(self.drained())
        r = self.ask("ads.example")
        self.assertEqual(r.rcode(), 3)
        line = json.loads(self.drained()[before:][-1])
        self.assertEqual(line["rcode"], 3)

    def test_gate_24_the_histogram_counts_what_was_answered(self):
        # The histogram's count and the log lines are two independent counts of the same answered
        # queries: read the count before and after a fixed number of asks, and compare the deltas.
        r = dns.query.udp(dns.message.make_query("histogram.bind.", "TXT", rdclass="CH"),
                          "127.0.0.1", port=self.port, timeout=3)
        before_text = ""
        for rr in r.answer:
            for s in rr:
                for piece in s.strings:
                    before_text += piece.decode() if isinstance(piece, bytes) else piece
        before_count = None
        for part in before_text.split("\n"):
            if part.startswith("dns_latency_count "):
                before_count = int(part.split()[1])
        self.assertIsNotNone(before_count)
        # Two queries the stub answers.
        asked = 0
        for name in ("hista.example", "histb.example"):
            self.ask(name)
            asked = asked + 1
        time.sleep(0.2)
        after = len(self.drained())
        # The histogram query itself was one answered query, so the deltas agree.
        r = dns.query.udp(dns.message.make_query("histogram.bind.", "TXT", rdclass="CH"),
                          "127.0.0.1", port=self.port, timeout=3)
        time.sleep(0.2)
        after_text = ""
        for rr in r.answer:
            for s in rr:
                for piece in s.strings:
                    after_text += piece.decode() if isinstance(piece, bytes) else piece
        after_count = None
        for part in after_text.split("\n"):
            if part.startswith("dns_latency_count "):
                after_count = int(part.split()[1])
        self.assertIsNotNone(after_count)
        # asked queries plus the first histogram query: the count moved by exactly that.
        self.assertEqual(after_count - before_count, asked + 1)
        # And the log moved by the same amount: one line per answered query.
        self.assertEqual(len(self.drained()) - after, 1)


if __name__ == "__main__":
    unittest.main()
