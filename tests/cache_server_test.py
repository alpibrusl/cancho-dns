"""Black-box tests of the cache in build/server (D2, gate 3 parts 2 and 3).

usage: cache_server_test.py <server-binary>
"""
import os, socket, struct, subprocess, sys, time, unittest
import dns.flags, dns.message, dns.query, dns.rcode, dns.rdataclass, dns.rdatatype

BIN = os.path.abspath(sys.argv.pop(1)) if len(sys.argv) > 1 else None


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Running:
    def __init__(self, min_ttl, memory, keys):
        self.port = free_port()
        self.proc = subprocess.Popen([BIN, str(self.port), "10", str(min_ttl), str(memory), str(keys)], stderr=subprocess.PIPE)
        self.proc.stderr.readline()

    def stop(self):
        self.proc.kill(); self.proc.wait(); self.proc.stderr.close()

    def ask(self, name, rtype="A", **kw):
        return dns.query.udp(dns.message.make_query(name, rtype, **kw), "127.0.0.1", port=self.port, timeout=3)

    def stats(self):
        r = self.ask("stats.bind.", "TXT", rdclass=dns.rdataclass.CH) if False else dns.query.udp(
            dns.message.make_query("stats.bind.", "TXT", rdclass="CH"), "127.0.0.1", port=self.port, timeout=3)
        out = {}
        for rd in r.answer[0]:
            for s in rd.strings:
                k, v = s.decode().split("=")
                out[k] = int(v)
        return out

    def rss_kb(self):
        for line in open("/proc/%d/status" % self.proc.pid):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])


class Behaviour(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = Running(1, 4 * 1048576, 4096)

    @classmethod
    def tearDownClass(cls):
        cls.s.stop()

    def test_repeat_is_a_hit_and_the_ttl_runs_down_and_ends(self):
        s = self.s
        before = s.stats()
        r1 = s.ask("ttl3.hit.example.")
        self.assertEqual(r1.answer[0].ttl, 3)
        time.sleep(1.2)
        r2 = s.ask("ttl3.hit.example.")
        self.assertIn(r2.answer[0].ttl, (1, 2))
        mid = s.stats()
        self.assertEqual(mid["hits"] - before["hits"], 1)
        self.assertEqual(mid["misses"] - before["misses"], 1)
        time.sleep(2.2)
        r3 = s.ask("ttl3.hit.example.")
        self.assertEqual(r3.answer[0].ttl, 3)
        after = s.stats()
        self.assertEqual(after["misses"] - mid["misses"], 1)

    def test_case_is_not_part_of_the_key_and_the_client_sees_its_own(self):
        s = self.s
        s.ask("ttl50.case.example.")
        h = s.stats()["hits"]
        r = s.ask("TTL50.CaSe.example.")
        self.assertEqual(s.stats()["hits"], h + 1)
        self.assertEqual(r.question[0].name.to_text(), "TTL50.CaSe.example.")

    def test_negative_answer_is_served_from_the_cache(self):
        s = self.s
        r1 = s.ask("nx-one.example.")
        self.assertEqual(r1.rcode(), 3); self.assertEqual(len(r1.authority), 1)
        h = s.stats()["hits"]
        r2 = s.ask("nx-one.example.")
        self.assertEqual(r2.rcode(), 3)
        self.assertEqual(s.stats()["hits"], h + 1)
        self.assertTrue(r2.authority[0].ttl <= 30)

    def test_tcp_is_served_from_the_same_cache(self):
        s = self.s
        s.ask("n5.tcp.example.")
        h = s.stats()["hits"]
        r = dns.query.tcp(dns.message.make_query("n5.tcp.example.", "A"), "127.0.0.1", port=s.port, timeout=3)
        self.assertEqual(len(r.answer[0]), 5)
        self.assertEqual(s.stats()["hits"], h + 1)

    def test_a_cached_big_answer_is_still_truncated_over_udp(self):
        s = self.s
        s.ask("n40.big.example.", use_edns=0, payload=4096)
        r = s.ask("n40.big.example.")
        self.assertTrue(r.flags & dns.flags.TC)

    def test_refusals_are_not_cached(self):
        s = self.s
        u = s.stats()["uncacheable"]
        r = dns.query.udp(dns.message.make_query("x.example.", "A", rdclass="CH"), "127.0.0.1", port=s.port, timeout=3)
        self.assertEqual(r.rcode(), 5)
        self.assertEqual(s.stats()["uncacheable"], u)


def raw_query(n, tag):
    name = ("h%d" % n).encode()
    q = struct.pack(">HHHHHH", n & 0xFFFF, 0x0100, 1, 0, 0, 0)
    q += bytes([len(name)]) + name + bytes([len(tag)]) + tag + b"\x00" + struct.pack(">HH", 1, 1)
    return q


class Memory(unittest.TestCase):
    def test_a_flood_of_names_stays_inside_the_store(self):
        s = Running(10, 1048576, 2048)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.settimeout(2)
            sock.connect(("127.0.0.1", s.port))
            total, batch, hot_every = 100000, 100, 100
            hot = dns.message.make_query("n2.hot.example.", "A")
            hot_wire = hot.to_wire()
            s.ask("n2.hot.example.")
            # The first 65,536 datagrams touch the runtime's ring of 65,536 peer tickets (about 32 bytes each) for the first time, so RSS
            # climbs by about 2 MB over them whatever the cache does; the bound is read after that ring has been written round once.
            rss = {}
            hot_hits = 0
            for start in range(0, total, batch):
                for n in range(start, start + batch):
                    sock.send(raw_query(n, b"flood"))
                got = 0
                while got < batch:
                    sock.recv(4096); got += 1
                sock.send(hot_wire)
                r = dns.message.from_wire(sock.recv(4096))
                hot_hits += len(r.answer) == 1
                if start + batch == 80000:
                    rss["early"] = s.rss_kb()
            rss["late"] = s.rss_kb()
            st = s.stats()
            self.assertGreater(st["evicted"], 0)
            self.assertLessEqual(st["live"], 2048)
            self.assertLessEqual(st["used"], st["capacity"])
            self.assertEqual(st["no_room"], 0)
            growth = (rss["late"] - rss["early"]) / rss["early"]
            print("\nRSS after 80,000 names: %d KiB; after 100,000: %d KiB; growth %.2f%%; evicted %d; live %d" % (
                rss["early"], rss["late"], growth * 100, st["evicted"], st["live"]))
            self.assertLess(growth, 0.01)
            # The hot name (asked every 100 names) kept being served from the cache: nearly every ask was a hit.
            self.assertGreaterEqual(st["hits"], total // hot_every * 0.95)
            self.assertEqual(hot_hits, total // batch)
        finally:
            s.stop()


if __name__ == "__main__":
    unittest.main()
