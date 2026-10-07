#!/usr/bin/env python3
"""Gate 6 of docs/design.md section 8: the authority row, diffed against a ceiling file.

    python3 tests/authority_check.py <cancho> <ceiling file> <source files...>

Runs `cancho authority --std --output json` over the sources and compares the labels it reports with the ceiling,
one label per line (`io_write`, or `fs_read("/dev/urandom")` for a label with an argument). It fails if the program
performs a label the ceiling does not list (authority grew: the ceiling is edited in the same change, in review), if
the ceiling lists a label the program no longer performs (a ceiling only comes down, so a stale one is a failure
too), or if the report is not bounded, names a foreign symbol, or could not be produced. `--expect-failure` inverts
the exit status, which is how CI shows that the gate can fail (it is run once with a ceiling that must be refused).
"""

import json
import subprocess
import sys


def labels(report):
    out = set()
    for label in report["labels"]:
        out.add(label["name"] if label["argument"] is None else '%s("%s")' % (label["name"], label["argument"]))
    return out


def main():
    args = sys.argv[1:]
    expect_failure = "--expect-failure" in args
    args = [a for a in args if a != "--expect-failure"]
    cancho, ceiling_file, sources = args[0], args[1], args[2:]
    done = subprocess.run([cancho, "authority", "--std", "--output", "json", *sources], capture_output=True, text=True)
    problems = []
    if done.returncode != 0:
        problems.append("`cancho authority` failed: " + done.stderr.strip()[-300:])
    else:
        report = json.loads(done.stdout)
        ceiling = {line.strip() for line in open(ceiling_file) if line.strip() and not line.startswith("#")}
        performed = labels(report)
        for label in sorted(performed - ceiling):
            problems.append("performs %s, which the ceiling does not allow" % label)
        for label in sorted(ceiling - performed):
            problems.append("the ceiling allows %s, which nothing performs (a ceiling only comes down)" % label)
        if not report["bounded"]:
            problems.append("the report is not bounded: " + ", ".join(report["unbounded_by"]))
        if report["foreign_symbols"]:
            problems.append("foreign symbols are reachable: " + ", ".join(report["foreign_symbols"]))
    for p in problems:
        print("authority: " + p)
    failed = bool(problems)
    if expect_failure:
        print("authority: the gate refused, as it was meant to" if failed else "authority: the gate did NOT refuse a ceiling it should have")
        sys.exit(0 if failed else 1)
    if not failed:
        print("authority: ok (%s)" % ", ".join(sorted(performed)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
