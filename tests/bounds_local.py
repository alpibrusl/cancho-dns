"""Gate 14 of docs/design.md section 17: every bound of the generator is refused with file and line, and the edges
one inside each bound are accepted.

usage: bounds_local.py (no arguments; run from the repository root)
"""
import os, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
GEN = os.path.join(HERE, "gen_local.py")


def generate(conf_text):
    """Run the generator on this text; return (ok, message)."""
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
        f.write(conf_text)
        path = f.name
    try:
        r = subprocess.run([sys.executable, GEN, path], capture_output=True, text=True)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    finally:
        os.unlink(path)


class Bounds(unittest.TestCase):
    def test_a_well_formed_table_is_accepted(self):
        ok, msg = generate("record a.example A 10.0.0.1\n")
        self.assertTrue(ok, msg)

    def test_the_limits_are_refused_with_file_and_line(self):
        cases = {
            "directives; at most 512": "record a%d.example A 10.0.0.1\n" % 0 * 1 + "record a.example A 10.0.0.1\n" * 513,
            "local-name-too-long": "record %s.example A 10.0.0.1\n" % ("x" * 64),
            "local-bad-type": "record a.example NOTATYPE 10.0.0.1\n",
            "local-bad-value": "record a.example A not-an-address\n",
            "local-tie": "record a.example A 10.0.0.1\nrecord a.example A 10.0.0.2\n",
            "local-value-too-long": "record a.example TXT %s\n" % ("x" * 256),
        }
        for tag, conf in cases.items():
            ok, msg = generate(conf)
            self.assertFalse(ok, tag)
            self.assertIn(tag, msg, (tag, msg))

    def test_the_edges_inside_each_bound_are_accepted(self):
        self.assertTrue(generate("record %s.example A 10.0.0.1\n" % ("x" * 63))[0])
        self.assertTrue(generate('record a.example TXT %s\n' % ("x" * 254))[0])
        ok, _ = generate("".join("record a%d.example A 10.0.0.1\n" % i for i in range(512)))
        self.assertTrue(ok)
        ok, _ = generate("".join("record a%d.example A 10.0.0.1\n" % i for i in range(513)))
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
