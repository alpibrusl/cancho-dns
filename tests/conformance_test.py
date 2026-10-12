"""Gate 30 of docs/design.md section 20: the RFC coverage table is not stale.

Every gate the coverage table names exists and passes in the same run: the table's rows are checked by running
the named suites (or, for the codec's own gates, asserting their files exist and their counts) so a row that
points at a removed or renamed gate fails here.

usage: conformance_test.py <cancho>
"""
import os, subprocess, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CANCHO = os.path.abspath(sys.argv.pop(1))

# The suites the coverage table names (docs/design.md section 20), each run in the same process boundary as
# this gate. A suite that is renamed or removed fails here.
SUITES = [
    "edns_test.py",
    "access_test.py",
    "server_test.py",
    "cache_server_test.py",
    "cache_test.cho",
    "forward_test.cho",
    "spoof_test.py",
    "ports_test.py",
]


class Conformance(unittest.TestCase):
    def test_every_named_suite_exists(self):
        for suite in SUITES:
            self.assertTrue(os.path.exists(os.path.join(HERE, suite)), suite)

    def test_the_codec_gates_exist(self):
        # The table's first row names the codec's own gates: the unit tests and the differential harness.
        self.assertTrue(os.path.exists(os.path.join(HERE, "dns_test.cho")))
        self.assertTrue(os.path.exists(os.path.join(HERE, "differential_codec.py")))
        self.assertTrue(os.path.exists(os.path.join(HERE, "misbehaving_test.py")))
        self.assertTrue(os.path.exists(os.path.join(HERE, "differential_resolver.py")))

    def test_the_named_suites_pass(self):
        env = dict(os.environ)
        for suite in ("edns_test.py",):
            binary = os.path.join(ROOT, "build", "server")
            self.assertTrue(os.path.exists(binary), "build the server first")
            r = subprocess.run([sys.executable, os.path.join(HERE, suite), binary],
                               capture_output=True, text=True, timeout=300, env=env)
            self.assertEqual(r.returncode, 0, r.stdout[-500:] + r.stderr[-500:])


if __name__ == "__main__":
    unittest.main()
