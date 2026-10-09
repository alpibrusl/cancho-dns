"""Gate 19 of docs/design.md section 18: every output validates against `schemas/dns.v1.json` over a corpus
of commands, and a document with a wrong shape is refused by the schema (the schema is not vacuous).

usage: schema_test.py <server-binary>
"""
import json, os, subprocess, sys, unittest

import jsonschema

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BIN = os.path.abspath(sys.argv.pop(1))
SCHEMA = json.loads(open(os.path.join(ROOT, "schemas", "dns.v1.json")).read())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)


def run(*args):
    r = subprocess.run([BIN, *args], capture_output=True, text=True, cwd=ROOT)
    return r


class Schema(unittest.TestCase):
    def validate(self, doc, what):
        errors = sorted(VALIDATOR.iter_errors(doc), key=lambda e: e.path)
        self.assertEqual(errors, [], "%s: %s" % (what, errors[:3]))

    def test_introspect_validates(self):
        r = run("introspect")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.validate(json.loads(r.stdout), "introspect")

    def test_check_validates(self):
        r = run("check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.validate(json.loads(r.stdout), "check")

    def test_explain_validates_over_a_corpus(self):
        corpus = [
            ("www.example", "A"),          # a local record: the full local arm
            ("ads.example", "A"),          # a block
            ("tracker.example", "A"),       # a block with an address
            ("nothing.example", "A"),      # no match
            ("www.example", "SRV"),        # another type
            ("www.example", "NOTATYPE"),   # a type we do not take: the reason arm
        ]
        for name, qtype in corpus:
            r = run("explain", name, qtype)
            self.assertEqual(r.returncode, 0, (name, qtype, r.stderr))
            self.validate(json.loads(r.stdout), "explain %s %s" % (name, qtype))

    def test_diff_validates(self):
        r = run("diff", "conf/old.conf", "conf/new.conf")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.validate(json.loads(r.stdout), "diff")

    def test_the_schema_is_not_vacuous(self):
        # A document with a wrong shape is refused: the schema pins the command, the tool, and the arms.
        bad_documents = [
            {"ok": True, "command": "nonsense", "tool": "dns", "version": "0.1.0", "compiler": "0" * 40},
            {"ok": "yes", "command": "introspect", "tool": "dns", "version": "0.1.0", "compiler": "0" * 40},
            {"ok": True, "command": "introspect", "tool": "not-dns", "version": "0.1.0", "compiler": "0" * 40},
            # introspect without the sections its arm requires
            {"ok": True, "command": "introspect", "tool": "dns", "version": "0.1.0", "compiler": "0" * 40,
             "summary": "s", "limits": [], "upstreams": [], "rules": [], "guarantees": {}},
            # an explain whose local arm carries both `kind` and `match`
            {"ok": True, "command": "explain", "tool": "dns", "version": "0.1.0", "compiler": "0" * 40,
             "name": "a", "type": "A",
             "local": {"kind": "record", "not-cached": True, "not-forwarded": True, "match": False},
             "cache": {"answer": "x"}, "forward": {"upstreams": 0, "answers-from": "stub"},
             "policy": {"ttl-clamp": "a", "case": "b", "ports": "c", "truncation": "d"}},
        ]
        for i, doc in enumerate(bad_documents):
            with self.assertRaises(jsonschema.ValidationError, msg="document %d was accepted" % i):
                VALIDATOR.validate(doc)


if __name__ == "__main__":
    unittest.main()
