"""Black-box tests of forwarding in build/server (D3): the server is built with an upstream table pointing at a fake upstream.

usage: forward_server_test.py <cancho> [<tmpdir>]
"""
import os, sys, tempfile, threading, time, unittest

import dns.flags, dns.message, dns.rcode, dns.rdatatype

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

CANCHO = os.path.abspath(sys.argv.pop(1))
WORK = tempfile.mkdtemp(prefix="fwdtest-")


class Base(unittest.TestCase):
    PORTS = 1

    @classmethod
    def setUpClass(cls):
        cls.ports = [h.free_udp_port() for _ in range(cls.PORTS)]
        cls.binary = os.path.join(WORK, cls.__name__)
        h.build(CANCHO, cls.ports, cls.binary)
        cls.server = h.Server(cls.binary)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()


class Honest(Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.up = h.Upstream(cls.ports[0], cls.handler)

    @classmethod
    def tearDownClass(cls):
        cls.up.stop()
        super().tearDownClass()

    @staticmethod
    def handler(q, addr, sock):
        name = q.question[0].name.to_text().lower()
        if name.startswith("nx"):
            return [h.nxdomain(q).to_wire()]
        if name.startswith("tc"):
            r = h.answer(q); r.flags |= dns.flags.TC; r.answer = []
            return [r.to_wire()]
        if name.startswith("slow"):
            threading.Timer(0.6, sock.sendto, (h.answer(q).to_wire(), addr)).start()
            return None
        return [h.answer(q).to_wire()]

    def test_a_miss_is_forwarded_and_the_next_ask_is_a_hit(self):
        s = self.server
        before = s.stats()
        r = s.ask("one.example.")
        self.assertEqual(r.rcode(), 0)
        self.assertEqual(str(r.answer[0][0]), "192.0.2.7")
        self.assertEqual(r.question[0].name.to_text(), "one.example.")
        r2 = s.ask("one.example.")
        self.assertEqual(str(r2.answer[0][0]), "192.0.2.7")
        after = s.stats()
        self.assertEqual(after["fwd_sent"] - before["fwd_sent"], 1)
        self.assertEqual(after["hits"] - before["hits"], 1)

    def test_the_query_goes_out_with_rd_edns_and_a_mixed_case_name(self):
        s = self.server
        start = self.up.count()
        for i in range(30):
            s.ask("caseprobe%d.example." % i)
        qs = [q for _, _, q in self.up.seen[start:]]
        self.assertEqual(len(qs), 30)
        cases = set()
        for q in qs:
            self.assertTrue(q.flags & dns.flags.RD)
            self.assertIsNotNone(q.edns)
            self.assertEqual(q.edns, 0)
            self.assertEqual(q.payload, 1232)
            n = q.question[0].name.to_text()
            self.assertEqual(n.lower(), n.lower())
            cases.add(n)
        # Thirty names of ten letters each, in random case: not one of them is all lower case, by luck 2^-300.
        self.assertTrue(all(n != n.lower() for n in cases))

    def test_a_negative_answer_is_forwarded_and_cached(self):
        s = self.server
        before = s.stats()
        r = s.ask("nx-forwarded.example.")
        self.assertEqual(r.rcode(), 3); self.assertEqual(len(r.authority), 1)
        r = s.ask("nx-forwarded.example.")
        self.assertEqual(r.rcode(), 3)
        after = s.stats()
        self.assertEqual(after["fwd_sent"] - before["fwd_sent"], 1)

    def test_a_truncated_upstream_reply_is_truncated_to_a_udp_client_and_servfail_to_a_tcp_one(self):
        s = self.server
        r = s.ask("tc-one.example.")
        self.assertTrue(r.flags & dns.flags.TC)
        r = s.ask_tcp("tc-two.example.")
        self.assertEqual(r.rcode(), 2)
        # Neither was cached as an answer.
        before = s.stats()["fwd_sent"]
        s.ask("tc-one.example.")
        self.assertEqual(s.stats()["fwd_sent"] - before, 1)

    def test_many_queries_in_flight_are_each_answered_to_their_own_client(self):
        s = self.server
        results = {}

        def one(i):
            r = s.ask("slow%d.example." % i)
            results[i] = (r.rcode(), r.question[0].name.to_text())

        threads = [threading.Thread(target=one, args=(i,)) for i in range(150)]
        t0 = time.time()
        for t in threads: t.start()
        for t in threads: t.join()
        elapsed = time.time() - t0
        self.assertEqual(len(results), 150)
        for i, (rc, name) in results.items():
            self.assertEqual(rc, 0); self.assertEqual(name, "slow%d.example." % i)
        # All 150 waited for the 0.6 s upstream together, not one after another.
        self.assertLess(elapsed, 5)

    def test_tcp_replies_come_back_in_order_and_one_query_waits_for_the_one_before(self):
        s = self.server
        import socket, struct
        sock = socket.create_connection(("127.0.0.1", s.port), timeout=8)
        names = ["slowa.example.", "fast-b.example.", "slowc.example."]
        wire = b"".join(struct.pack(">H", len(w)) + w for w in (dns.message.make_query(n, "A").to_wire() for n in names))
        sock.sendall(wire)
        got = []
        for _ in names:
            n = struct.unpack(">H", sock.recv(2))[0]
            buf = b""
            while len(buf) < n:
                buf += sock.recv(n - len(buf))
            got.append(dns.message.from_wire(buf).question[0].name.to_text())
        self.assertEqual(got, names)
        sock.close()


class Dead(Base):
    """An upstream that never answers."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.up = h.Upstream(cls.ports[0], lambda q, a, s: None)

    @classmethod
    def tearDownClass(cls):
        cls.up.stop()
        super().tearDownClass()

    def test_servfail_after_two_attempts_and_then_from_the_cache(self):
        s = self.server
        t0 = time.time()
        r = s.ask("silent.example.", timeout=10)
        took = time.time() - t0
        self.assertEqual(r.rcode(), 2)
        self.assertGreater(took, 3.5); self.assertLess(took, 6)
        st = s.stats()
        self.assertEqual(st["fwd_sent"], 2); self.assertEqual(st["fwd_timeout"], 2); self.assertEqual(st["fwd_servfail"], 1)
        # Asked again within the 5 s the cache keeps SERVFAIL: answered at once, nothing more sent.
        t0 = time.time()
        r = s.ask("silent.example.")
        self.assertEqual(r.rcode(), 2); self.assertLess(time.time() - t0, 0.5)
        self.assertEqual(s.stats()["fwd_sent"], 2)
        self.assertEqual(self.up.count(), 2)
        # Two timeouts so far. A third, on another name, marks the only upstream down for ten seconds, so there is no second attempt: the
        # client waits one attempt (2 s) and not two. And then, with every upstream down, a miss is SERVFAIL at once and sends nothing.
        t0 = time.time()
        r = s.ask("silent-two.example.", timeout=10)
        took = time.time() - t0
        self.assertEqual(r.rcode(), 2)
        self.assertGreater(took, 1.8); self.assertLess(took, 3.2)
        self.assertEqual(self.up.count(), 3)
        t0 = time.time()
        r = s.ask("silent-three.example.", timeout=10)
        self.assertEqual(r.rcode(), 2); self.assertLess(time.time() - t0, 0.5)
        self.assertEqual(self.up.count(), 3)


class Flaky(Base):
    """An upstream that drops the first query of each name and answers the second."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.seen_names = {}
        cls.up = h.Upstream(cls.ports[0], cls.handler)

    @classmethod
    def tearDownClass(cls):
        cls.up.stop()
        super().tearDownClass()

    @classmethod
    def handler(cls, q, addr, sock):
        n = q.question[0].name.to_text().lower()
        cls.seen_names[n] = cls.seen_names.get(n, 0) + 1
        if cls.seen_names[n] == 1:
            return None
        return [h.answer(q).to_wire()]

    def test_the_second_attempt_gets_an_answer_on_a_new_socket(self):
        s = self.server
        t0 = time.time()
        r = s.ask("retry.example.", timeout=10)
        took = time.time() - t0
        self.assertEqual(r.rcode(), 0); self.assertEqual(str(r.answer[0][0]), "192.0.2.7")
        self.assertGreater(took, 1.8); self.assertLess(took, 4)
        ports = [p for _, p, _ in self.up.seen]
        self.assertEqual(len(ports), 2)
        self.assertNotEqual(ports[0], ports[1])
        ids = [q.id for _, _, q in self.up.seen]
        self.assertNotEqual(ids[0], ids[1])


class TwoUpstreams(Base):
    PORTS = 2

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.dead = h.Upstream(cls.ports[0], lambda q, a, s: None)
        cls.live = h.Upstream(cls.ports[1], lambda q, a, s: [h.answer(q).to_wire()])

    @classmethod
    def tearDownClass(cls):
        cls.dead.stop(); cls.live.stop()
        super().tearDownClass()

    def test_a_dead_upstream_is_retried_around_and_then_left_alone(self):
        s = self.server
        results = []

        def one(i):
            results.append(s.ask("both%d.example." % i, timeout=10).rcode())

        threads = [threading.Thread(target=one, args=(i,)) for i in range(40)]
        for t in threads: t.start()
        for t in threads: t.join()
        # Every query was answered: the ones that went to the dead upstream first were sent again, to the live one.
        self.assertEqual(results.count(0), 40)
        asked_dead = self.dead.count()
        self.assertGreater(asked_dead, 0)
        # Three timeouts in a row marked it down, and a marked-down upstream gets nothing for 10 s: new queries go to the live one only.
        for i in range(40, 80):
            self.assertEqual(s.ask("both%d.example." % i, timeout=10).rcode(), 0)
        self.assertEqual(self.dead.count(), asked_dead)


if __name__ == "__main__":
    unittest.main(verbosity=1)
