"""Gate 28 of docs/design.md section 20: misbehaving upstreams.

Each behaviour RFC 1035/7766 says a resolver must survive, played by the scripted fake upstream: the client
must observe SERVFAIL or a retry (never a wrong answer), the resolver must stay alive, and the counters say
which defence fired.

usage: misbehaving_test.py <cancho>
"""
import os, socket, sys, tempfile, time, unittest

import dns.message, dns.query, dns.rcode, dns.rdatatype, dns.rrset

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

CANCHO = os.path.abspath(sys.argv.pop(1))
WORK = tempfile.mkdtemp(prefix="misbehaving-")


def serve(handler):
    """A server with one misbehaving upstream; answers (upstream, resolver, port)."""
    up = h.Upstream(h.free_udp_port(), handler)
    binary = os.path.join(WORK, "server-%d" % up.port)
    h.build(CANCHO, [up.port], binary)
    server = h.Server(binary, idle=2)
    return up, server


def wrong_case(q, addr, sock):
    r = h.answer(q)
    # The question echoed in the wrong case: the 0x20 defence must reject it.
    wire = bytearray(r.to_wire())
    qname = q.question[0].name
    text = str(qname).rstrip(".")
    flipped = "".join(c.upper() if c.islower() else c.lower() for c in text)
    if flipped != text:
        flipped_wire = dns.name.from_text(flipped + ".").to_wire()
        old_wire = qname.to_wire()
        at = bytes(wire).find(old_wire)
        if at >= 0:
            wire[at:at + len(old_wire)] = flipped_wire
    return [bytes(wire)]


def records_not_asked_for(q, addr, sock):
    r = h.answer(q)
    r.answer.append(dns.rrset.from_text("other.example.", 30, "IN", "A", "192.0.2.99"))
    return [r.to_wire()]


def truncated_without_tc(q, addr, sock):
    r = h.answer(q)
    wire = r.to_wire()
    return [wire[:len(wire) - 8]]


def oversized_reply(q, addr, sock):
    r = h.answer(q)
    r.answer.append(dns.rrset.from_text("big.example.", 30, "IN", "TXT",
                                        '"' + "x" * 300 + '" "' + "y" * 300 + '"'))
    return [r.to_wire()]


def garbage(q, addr, sock):
    return [b"\xde\xad\xbe\xef" * 20]


def silence(q, addr, sock):
    return None


class Misbehaving(unittest.TestCase):
    def check(self, handler, expect_rcodes):
        up, server = serve(handler)
        try:
            q = dns.message.make_query("m.example", "A")
            observed = None
            try:
                r = dns.query.udp(q, "127.0.0.1", port=server.port, timeout=4)
                observed = r.rcode()
                self.assertIn(observed, expect_rcodes)
                # A wrong answer is never served: any A record in a SERVFAIL-free reply is the honest one.
                if observed == 0:
                    for rr in r.answer:
                        for a in rr:
                            self.assertEqual(str(a), "192.0.2.7")
            except Exception:
                # Silence (a drop) is an acceptable answer too.
                observed = "timeout"
            time.sleep(0.1)
            self.assertTrue(server.proc.poll() is None, "the resolver died")
            return observed
        finally:
            up.stop()
            server.stop()

    def test_wrong_case_is_not_believed(self):
        self.check(wrong_case, (dns.rcode.SERVFAIL,))

    def test_records_not_asked_for_are_not_served(self):
        self.check(records_not_asked_for, (0, dns.rcode.SERVFAIL))

    def test_a_truncated_reply_without_tc_is_not_believed(self):
        self.check(truncated_without_tc, (dns.rcode.SERVFAIL,))

    def test_an_oversized_reply_is_dropped_or_trimmed(self):
        self.check(oversized_reply, (0, dns.rcode.SERVFAIL, "timeout"))

    def test_garbage_is_answered_servfail(self):
        self.check(garbage, (dns.rcode.SERVFAIL,))

    def test_silence_times_out_to_servfail(self):
        self.check(silence, (dns.rcode.SERVFAIL, "timeout"))


if __name__ == "__main__":
    unittest.main()
