"""Gate 8 of docs/design.md section 16: the response-rate limiter, black-box.

usage: rate_test.py <cancho> [<binary>]

Rate 50 a second, burst 100, so the arithmetic is visible in a second or two. Clients are different loopback addresses (127.0.N.M is
network N of the limiter's /24 buckets).
"""
import os, socket, sys, tempfile, time, unittest

import dns.message

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

CANCHO = os.path.abspath(sys.argv.pop(1))
BINARY = os.path.abspath(sys.argv.pop(1)) if len(sys.argv) > 1 else None
WORK = tempfile.mkdtemp(prefix="ratetest-")
RATE, BURST = 50, 100


def blast(source, port, count, group=25, pause=0.002, settle=0.6):
    """Send `count` distinct queries from `source` in groups, as fast as the pause allows, and count the answers that come back."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((source, 0)); s.setblocking(False)
    t0 = time.time()
    got = 0
    for i in range(count):
        s.sendto(dns.message.make_query("r%s-%d.example." % (source.replace(".", "-"), i), "A").to_wire(), ("127.0.0.1", port))
        if i % group == group - 1:
            time.sleep(pause)
            got += drain(s)
    elapsed = time.time() - t0
    end = time.time() + settle
    while time.time() < end:
        got += drain(s)
        time.sleep(0.02)
    s.close()
    return got, elapsed


def drain(s):
    n = 0
    while True:
        try:
            s.recvfrom(4096); n += 1
        except BlockingIOError:
            return n


class Rate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = BINARY or os.path.join(WORK, "rate")
        if not BINARY:
            h.build(CANCHO, [], cls.binary)
        cls.server = h.Server(cls.binary, rate=RATE, burst=BURST)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_one_network_is_held_to_its_burst_and_rate_and_others_are_not(self):
        s = self.server
        before = s.stats()
        got, elapsed = blast("127.0.0.1", s.port, 2000)
        ceiling = BURST + RATE * (elapsed + 0.7) + 5
        self.assertGreaterEqual(got, BURST - 5, "fewer than the burst was answered")
        self.assertLessEqual(got, ceiling, "more than burst + rate * time was answered")
        dropped = s.stats()["rrl_dropped"] - before["rrl_dropped"]
        self.assertGreater(dropped, 1500)
        # Other networks, at the same moment, are answered in full (two of three: a keyed hash may, rarely, put two networks in one bucket).
        full = sum(1 for n in (1, 2, 3) if blast("127.0.%d.5" % n, s.port, 40)[0] == 40)
        self.assertGreaterEqual(full, 2)
        print("\none network: %d answered of 2000 in %.2f s (ceiling %.0f); %d dropped" % (got, elapsed, ceiling, dropped))

    def test_two_hosts_of_one_slash_24_share_a_bucket_and_it_refills(self):
        s = self.server
        a, _ = blast("127.0.8.2", s.port, 100, group=10, pause=0.0, settle=0.1)
        self.assertGreaterEqual(a, BURST - 8)
        b, _ = blast("127.0.8.3", s.port, 60, group=10, pause=0.0, settle=0.1)
        # The bucket was empty a moment ago and gains 50 a second: well under the 60 that a bucket of its own would answer.
        self.assertLessEqual(b, 25, "a second host of the /24 got a bucket of its own")
        time.sleep(2.0)
        c, elapsed = blast("127.0.8.4", s.port, 300, group=10, pause=0.002)
        # About two seconds of refill, 2 * 50 = 100, plus what 0.5 s more brings.
        self.assertGreaterEqual(c, 70)
        self.assertLessEqual(c, 100 + RATE * (elapsed + 0.7) + 5)


class Unlimited(unittest.TestCase):
    def test_a_rate_of_zero_answers_everything(self):
        binary = BINARY or os.path.join(WORK, "rate")
        server = h.Server(binary, rate=0, burst=1)
        try:
            got, _ = blast("127.0.0.1", server.port, 1000, group=10, pause=0.002)
            self.assertGreaterEqual(got, 990)
            self.assertEqual(server.stats()["rrl_dropped"], 0)
        finally:
            server.stop()


if __name__ == "__main__":
    unittest.main(verbosity=1)
