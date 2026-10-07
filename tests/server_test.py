"""Black-box tests of build/server (D1), with dnspython as the client.

usage: server_test.py <server-binary>
"""
import os, socket, struct, subprocess, sys, time, unittest
import dns.flags, dns.message, dns.query, dns.rcode, dns.opcode

BIN = os.path.abspath(sys.argv.pop(1)) if len(sys.argv) > 1 else None
IDLE = 2


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.proc = subprocess.Popen([BIN, str(cls.port), str(IDLE)], stderr=subprocess.PIPE)
        cls.proc.stderr.readline()  # "listening on <port>"

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill(); cls.proc.wait(); cls.proc.stderr.close()

    def udp(self, q, timeout=3):
        return dns.query.udp(q, "127.0.0.1", port=self.port, timeout=timeout)

    def tcp_sock(self):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=3); return s

    def raw_udp(self, data, wait=True):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
        s.sendto(data, ("127.0.0.1", self.port))
        try:
            return s.recvfrom(4096)[0]
        except socket.timeout:
            return None
        finally:
            s.close()

    def recv_frame(self, s):
        def n(k):
            b = b""
            while len(b) < k:
                c = s.recv(k - len(b))
                if not c: return None
                b += c
            return b
        h = n(2)
        if h is None: return None
        return n(struct.unpack(">H", h)[0])

    # --- UDP
    def test_udp_answer(self):
        r = self.udp(dns.message.make_query("n3.example.", "A"))
        self.assertEqual(r.rcode(), 0); self.assertEqual(len(r.answer[0]), 3)

    def test_udp_truncates_without_edns(self):
        r = self.udp(dns.message.make_query("n40.example.", "A"))
        self.assertTrue(r.flags & dns.flags.TC); self.assertEqual(r.answer, [])

    def test_edns_size_is_honoured_and_clamped(self):
        q = dns.message.make_query("n40.example.", "A", use_edns=0, payload=1232)
        self.assertEqual(len(self.udp(q).answer[0]), 40)  # 40 A records fit in 1232
        q = dns.message.make_query("n64.example.", "A", use_edns=0, payload=65000)
        r = self.udp(q)  # clamped to 1232: 64 records (~1.1 KB) still fit or truncate
        self.assertLessEqual(len(r.to_wire()), 1232)
        q = dns.message.make_query("t1500.example.", "TXT", use_edns=0, payload=65000)
        self.assertTrue(self.udp(q).flags & dns.flags.TC)

    def test_tc_then_tcp(self):
        q = dns.message.make_query("t1500.example.", "TXT")
        self.assertTrue(self.udp(q).flags & dns.flags.TC)
        r = dns.query.tcp(q, "127.0.0.1", port=self.port, timeout=3)
        self.assertEqual(r.rcode(), 0); self.assertTrue(r.answer)

    def test_malformed_datagram_gets_formerr(self):
        r = self.raw_udp(b"\x12\x34\x01\x00" + b"\xff" * 20)
        self.assertIsNotNone(r); self.assertEqual(r[:2], b"\x12\x34")
        self.assertEqual(r[3] & 15, 1); self.assertTrue(r[2] & 0x80)

    def test_tiny_datagram_and_responses_are_dropped(self):
        self.assertIsNone(self.raw_udp(b"\x00\x01\x02"))
        q = dns.message.make_query("n1.example.", "A"); q.flags |= dns.flags.QR
        self.assertIsNone(self.raw_udp(q.to_wire()))

    def test_status_codes(self):
        q = dns.message.make_query("n1.example.", "A"); q.set_opcode(dns.opcode.STATUS)
        self.assertEqual(self.udp(q).rcode(), 4)
        q = dns.message.make_query("n1.example.", "A", rdclass="CH")
        self.assertEqual(self.udp(q).rcode(), 5)
        q = dns.message.make_query("n1.example.", "AXFR")
        self.assertEqual(self.udp(q).rcode(), 5)
        q = dns.message.make_query("n1.example.", "A", use_edns=1)
        self.assertEqual(self.udp(q).rcode(), 16)  # dnspython joins the OPT extension bits

    # --- TCP
    def frame(self, q):
        w = q.to_wire(); return struct.pack(">H", len(w)) + w

    def test_tcp_pipelined_in_order(self):
        s = self.tcp_sock()
        qs = [dns.message.make_query(f"n{i}.example.", "A") for i in (1, 2, 3, 4)]
        s.sendall(b"".join(self.frame(q) for q in qs))
        for i, q in zip((1, 2, 3, 4), qs):
            r = dns.message.from_wire(self.recv_frame(s))
            self.assertEqual(r.id, q.id); self.assertEqual(len(r.answer[0]), i)
        s.close()

    def test_tcp_split_message(self):
        s = self.tcp_sock(); b = self.frame(dns.message.make_query("n2.example.", "A"))
        for i in range(len(b)):
            s.sendall(b[i:i + 1]); time.sleep(0.002)
        r = dns.message.from_wire(self.recv_frame(s)); self.assertEqual(len(r.answer[0]), 2)
        s.close()

    def test_tcp_bad_frames_close(self):
        # (frame header, body): a short frame, then frames one byte and far over the 4,096-byte limit
        for n, body in ((5, b"x" * 5), (4097, b"\0" * 4097), (5000, b"\0" * 5000)):
            s = self.tcp_sock(); s.sendall(struct.pack(">H", n) + body)
            try:
                got = self.recv_frame(s)
            except ConnectionResetError:
                got = None
            self.assertIsNone(got, n); s.close()

    def test_tcp_idle_timeout(self):
        s = self.tcp_sock(); s.settimeout(IDLE + 4); t = time.time()
        self.assertEqual(s.recv(1), b""); self.assertLess(time.time() - t, IDLE + 3)
        s.close()

    def test_connection_cap_and_recovery(self):
        socks = [self.tcp_sock() for _ in range(140)]
        time.sleep(0.5)
        alive = 0
        for s in socks:
            s.settimeout(0.5)
            try:
                s.sendall(self.frame(dns.message.make_query("n1.example.", "A")))
                if self.recv_frame(s): alive += 1
            except OSError:
                pass
        self.assertLessEqual(alive, 128); self.assertGreaterEqual(alive, 100)
        for s in socks: s.close()
        time.sleep(0.5)
        r = dns.query.tcp(dns.message.make_query("n1.example.", "A"), "127.0.0.1", port=self.port, timeout=3)
        self.assertEqual(r.rcode(), 0)
        self.assertEqual(len(self.udp(dns.message.make_query("n2.example.", "A")).answer[0]), 2)


if __name__ == "__main__":
    unittest.main()
