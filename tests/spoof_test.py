"""Gate 4 of docs/design.md section 15: a spoofing harness against the forwarding code.

usage: spoof_test.py <cancho> [<binary> <upstream port>]

A fake upstream sends forged replies to a resolver that has a query pending, and the test asserts that the forgery is never given to
the client, never reaches the cache, and moves the counter of its own class. With a binary and the port its upstream table
names, the server under test is that binary (the mutation script builds mutants and passes them here); with only the compiler, the test builds
the server itself.
"""
import os, socket, sys, tempfile, threading, time, unittest

import dns.flags, dns.message, dns.name, dns.rcode, dns.rdatatype, dns.rrset

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

CANCHO = os.path.abspath(sys.argv.pop(1))
BINARY = os.path.abspath(sys.argv.pop(1)) if len(sys.argv) > 2 else None
PORT = int(sys.argv.pop(1)) if BINARY else None
WORK = tempfile.mkdtemp(prefix="spooftest-")
FORGED = "6.6.6.6"
REAL = "192.0.2.7"


def swapcase(name):
    return dns.name.from_text(name.to_text().swapcase())


def forge(kind, q):
    """A reply to `q` that is wrong in the way `kind` says (its address is FORGED, so a client that is given it is plain to see)."""
    r = h.answer(q, FORGED, ttl=3000)
    if kind == "id":
        r.id = q.id ^ 0x0101
    elif kind == "case":
        r.question[0].name = swapcase(q.question[0].name)
        r.answer[0].name = r.question[0].name
    elif kind == "name":
        other = dns.name.from_text("other." + q.question[0].name.to_text().split(".", 1)[1])
        r.question[0].name = other
        r.answer[0].name = other
    elif kind == "type":
        r.question[0].rdtype = dns.rdatatype.AAAA
    elif kind == "qr":
        r.flags &= ~dns.flags.QR
    else:
        raise ValueError(kind)
    return r


CLASSES = {"id": "drop_id", "case": "drop_case", "name": "drop_question", "type": "drop_question", "qr": "drop_not_response"}


class Forger(h.Upstream):
    def __init__(self, port):
        self.other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.other.bind(("127.0.0.1", 0))
        super().__init__(port, self.behave)

    def behave(self, q, addr, sock):
        n = q.question[0].name.to_text().lower()
        mode, rest = n[0], n[1:].split(".")[0]
        kind = rest.rstrip("0123456789")
        real = h.answer(q, REAL).to_wire()
        if kind in CLASSES:
            out = [forge(kind, q).to_wire()]
            return out + [real] if mode == "r" else out
        if kind == "extra":
            # A reply the matching accepts, carrying records for names that were never asked: a CNAME to a planted name with its
            # address, an A for another name, and glue in the additional section.
            r = h.answer(q, REAL)
            victim = dns.name.from_text("victim" + rest[5:] + ".example.")
            r.answer.append(dns.rrset.from_text(victim, 3000, "IN", "A", FORGED))
            r.additional.append(dns.rrset.from_text("glue" + rest[5:] + ".example.", 3000, "IN", "A", FORGED))
            r.authority.append(dns.rrset.from_text("example.", 3000, "IN", "NS", "evil.example."))
            return [r.to_wire()]
        if kind == "chain":
            # A CNAME that is part of the chain, then the address of its target: legitimate, and cached whole.
            r = h.answer(q, REAL)
            target = dns.name.from_text("target" + rest[5:] + ".example.")
            r.answer = [dns.rrset.from_text(q.question[0].name, 300, "IN", "CNAME", target.to_text()), dns.rrset.from_text(target, 300, "IN", "A", REAL)]
            return [r.to_wire()]
        if kind == "otherport":
            # A perfect forgery (right id, case, question) from a socket the query was not sent to; then the real reply.
            f = h.answer(q, FORGED, ttl=3000).to_wire()
            self.other.sendto(f, addr)
            time.sleep(0.2)
            return [real]
        if kind == "dup":
            return [real, real]
        if kind == "late":
            # The first attempt is answered after it has timed out, with a forgery that is perfect in every field; the second never.
            first = rest not in self.late_seen
            self.late_seen.add(rest)
            if first:
                threading.Timer(2.6, sock.sendto, (h.answer(q, FORGED, ttl=3000).to_wire(), addr)).start()
            return None
        return [real]

    late_seen = set()


FIX = {}


def setUpModule():
    port = PORT or h.free_udp_port()
    FIX["binary"] = BINARY or os.path.join(WORK, "spoof")
    if not BINARY:
        h.build(CANCHO, [port], FIX["binary"])
    FIX["up"] = Forger(port)


def tearDownModule():
    FIX["up"].stop()


class Base(unittest.TestCase):
    """Each class has a server of its own: a test that makes the upstream time out marks it down for ten seconds, which must not
    leak into the next test."""

    @classmethod
    def setUpClass(cls):
        cls.server = h.Server(FIX["binary"])
        cls.up = FIX["up"]

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
    def drops(self):
        s = self.server.stats()
        return {k: v for k, v in s.items() if k.startswith("drop_")}


class Answered(Base):
    def test_each_forgery_class_is_dropped_counted_and_never_cached(self):
        s = self.server
        for kind, counter in sorted(CLASSES.items()):
            before = self.drops()
            r = s.ask("r%s1.example." % kind)
            self.assertEqual(r.rcode(), 0, kind)
            self.assertEqual(str(r.answer[0][0]), REAL, "the client was given the forgery (%s)" % kind)
            after = self.drops()
            moved = {k: after[k] - before[k] for k in after if after[k] != before[k]}
            self.assertEqual(moved, {counter: 1}, kind)
            # Cached as the real answer, with the real TTL, not the forged 3000 s.
            again = s.ask("r%s1.example." % kind)
            self.assertEqual(str(again.answer[0][0]), REAL, kind)
            self.assertLessEqual(again.answer[0].ttl, 30)

    def test_records_outside_the_answer_chain_are_not_cached(self):
        s = self.server
        r = s.ask("xextra1.example.")
        self.assertEqual([str(x) for rr in r.answer for x in rr], [REAL])
        before = s.stats()["fwd_sent"]
        # Neither the planted answer nor the glue, nor the NS, made it into the cache: asking for them goes upstream and gets the
        # honest answer from the upstream (REAL), not 6.6.6.6.
        for name in ("victim1.example.", "glue1.example."):
            r = s.ask(name)
            self.assertEqual([str(x) for rr in r.answer for x in rr], [REAL], name)
        self.assertEqual(s.stats()["fwd_sent"] - before, 2)
        self.assertEqual(s.ask("example.", "NS").answer, [])

    def test_a_cname_chain_in_the_answer_is_kept(self):
        s = self.server
        r = s.ask("xchain1.example.")
        self.assertEqual([rr.rdtype for rr in r.answer], [dns.rdatatype.CNAME, dns.rdatatype.A])
        before = s.stats()
        r = s.ask("xchain1.example.")
        self.assertEqual(len(r.answer), 2)
        self.assertEqual(s.stats()["hits"] - before["hits"], 1)

    def test_a_perfect_forgery_from_another_socket_never_arrives(self):
        s = self.server
        before = self.drops()
        r = s.ask("xotherport1.example.")
        self.assertEqual(str(r.answer[0][0]), REAL)
        # The kernel dropped it: no counter of ours moved either.
        self.assertEqual(self.drops(), before)

    def test_a_second_copy_of_the_real_reply_changes_nothing(self):
        s = self.server
        before = s.stats()
        r = s.ask("xdup1.example.")
        time.sleep(0.2)
        self.assertEqual(str(r.answer[0][0]), REAL)
        after = s.stats()
        self.assertEqual(after["stored"] - before["stored"], 1)
        self.assertEqual({k: after[k] - before[k] for k in after if k.startswith("drop_") and after[k] != before[k]}, {})


class OnlyForgeries(Base):
    def test_a_forgery_with_nothing_real_behind_it_gets_the_client_servfail_not_the_forgery(self):
        s = self.server
        results = {}

        def one(kind):
            r = s.ask("f%s1.example." % kind, timeout=12)
            results[kind] = (r.rcode(), [str(x) for rr in r.answer for x in rr])

        threads = [threading.Thread(target=one, args=(k,)) for k in CLASSES]
        for t in threads: t.start()
        for t in threads: t.join()
        for kind, (rc, answers) in results.items():
            self.assertEqual(rc, 2, kind)
            self.assertNotIn(FORGED, answers, kind)


class AfterTheTimeout(Base):
    def test_a_perfect_forgery_after_the_timeout_is_not_cached(self):
        s = self.server
        before = s.stats()
        r = s.ask("xlate1.example.", timeout=12)
        # Attempt 1 timed out at 2 s and its socket was closed; the forgery sent at 2.6 s hit a closed port. Attempt 2 got no answer.
        self.assertEqual(r.rcode(), 2)
        time.sleep(3)
        self.assertEqual(s.stats()["stored"] - before["stored"], 1)  # the SERVFAIL, nothing else
        # After the SERVFAIL's 5 seconds the name is a miss again, not the forgery.
        time.sleep(3)
        r = s.ask("xlate1.example.", timeout=12)
        self.assertNotIn(FORGED, [str(x) for rr in r.answer for x in rr])


if __name__ == "__main__":
    unittest.main(verbosity=1)
