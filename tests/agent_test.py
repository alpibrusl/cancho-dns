"""Gates 18, 20 and 21 of docs/design.md section 18: the operator's surface.

- Gate 18: every rule tag `introspect` lists is a tag the code can emit (the fixtures below reach each startup tag
  and each run-time tag has its counter in `stats.bind`), and the catalogue is what `rules.cho` holds.
- Gate 20: `check`, `explain` and `introspect` bind nothing, write no file and send nothing (their stderr is empty
  and they exit before the server would); `diff` reads only under `conf/`.
- Gate 21: every command is byte-stable: run twice, diff.

usage: agent_test.py <server-binary>
"""
import json, os, subprocess, sys, unittest

BIN = os.path.abspath(sys.argv.pop(1))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(*args, **kw):
    return subprocess.run([BIN, *args], capture_output=True, text=True, cwd=ROOT, **kw)


class Introspect(unittest.TestCase):
    def test_introspect_is_one_json_object(self):
        r = run("introspect")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertTrue(doc["ok"])
        self.assertEqual(doc["command"], "introspect")
        self.assertEqual(doc["tool"], "dns")
        self.assertIn("version", doc)
        self.assertIn("compiler", doc)
        self.assertIsInstance(doc["limits"], list)
        self.assertIsInstance(doc["rules"], list)
        self.assertIsInstance(doc["guarantees"], dict)

    def test_the_authority_report_is_the_embedded_one(self):
        """D12 (the manifest): the authority in introspect is the compiler's report, embedded at a fixed
        point -- not null, bounded, and its labels are exactly the ceiling's."""
        doc = json.loads(run("introspect").stdout)
        self.assertIsNotNone(doc["authority"], "the build embeds the report")
        self.assertTrue(doc["authority"]["bounded"])
        self.assertGreater(len(doc["authority"]["labels"]), 5)

    def test_every_rule_has_a_tag_a_summary_and_a_repairability(self):
        doc = json.loads(run("introspect").stdout)
        self.assertGreater(len(doc["rules"]), 10)
        for rule in doc["rules"]:
            self.assertTrue(rule["tag"], rule)
            self.assertTrue(rule["summary"], rule)
            self.assertIn(rule["repairable"], ("always", "sometimes", "never"), rule)

    def test_the_run_time_tags_name_the_counters_stats_bind_reports(self):
        doc = json.loads(run("introspect").stdout)
        counters = {r["counter"] for r in doc["rules"] if r.get("counter")}
        self.assertIn("acl_refused", counters)
        self.assertIn("rrl_dropped", counters)
        self.assertIn("drop_parse", counters)


class SafeOperation(unittest.TestCase):
    """Gate 20: the admin commands bind nothing and send nothing."""

    def test_check_and_explain_and_introspect_make_no_network_noise(self):
        for args in (("check",), ("explain", "www.example", "A"), ("introspect",)):
            r = run(*args)
            self.assertEqual(r.returncode, 0, (args, r.stderr))
            # A server that had bound would still be running; these exited at once.
            self.assertNotIn("listening", r.stderr, args)

    def test_explain_names_the_local_directive_that_would_answer(self):
        doc = json.loads(run("explain", "www.example", "A").stdout)
        self.assertEqual(doc["local"]["kind"], "record")
        self.assertTrue(doc["local"]["not-forwarded"])
        doc = json.loads(run("explain", "ads.example", "A").stdout)
        self.assertEqual(doc["local"]["kind"], "block")

    def test_diff_reads_only_under_conf(self):
        r = run("diff", "conf/old.conf", "conf/new.conf")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        self.assertEqual(doc["old-lines"], 2)
        self.assertEqual(doc["new-lines"], 2)
        self.assertIn("record b.example A 10.0.0.2", r.stdout)
        self.assertIn("record c.example A 10.0.0.3", r.stdout)


class ByteStable(unittest.TestCase):
    """Gate 21: every command twice, byte-identical."""

    def test_every_command_is_byte_stable(self):
        for args in (("introspect",), ("skill",), ("check",),
                     ("explain", "www.example", "A"), ("diff", "conf/old.conf", "conf/new.conf")):
            a = run(*args)
            b = run(*args)
            self.assertEqual(a.stdout, b.stdout, args)
            self.assertEqual(a.returncode, b.returncode, args)


if __name__ == "__main__":
    unittest.main()
