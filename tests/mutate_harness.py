#!/usr/bin/env python3
"""Is the differential harness able to fail? (docs/design.md section 8, gate 1: "the harness is mutation-tested".)

    python3 tests/mutate_harness.py <cancho> [<python with dnspython>]

Each variant below is a plausible bug in `src/dns.cho`. It is built into a driver in a scratch directory (the real
sources are never touched), and `tests/differential_codec.py` is run against it with a smaller corpus: it must exit
non-zero. A variant it lets through means the harness cannot see that kind of bug, and this script exits 1.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# (name, old text in src/dns.cho, replacement)
VARIANTS = [
    ("flags read from the id", "table[1] = u16_at(data, 2);", "table[1] = u16_at(data, 0);"),
    ("ancount read from nscount", "let an = u16_at(data, 6);", "let an = u16_at(data, 8);"),
    ("qtype and qclass swapped", "table[7] = u16_at(data, question_end);\n    table[8] = u16_at(data, question_end + 2);",
     "table[8] = u16_at(data, question_end);\n    table[7] = u16_at(data, question_end + 2);"),
    ("ttl read as 16 bits", "let ttl = u32_at(data, named + 4);", "let ttl = u16_at(data, named + 6);"),
    ("ttl top bit passed through", "if ttl >= 2147483648 {", "if ttl >= 4294967296 {"),
    ("class read from the type", "let class = u16_at(data, named + 2);", "let class = u16_at(data, named);"),
    ("rdlength read one byte early", "let size = u16_at(data, named + 8);", "let size = u16_at(data, named + 7);"),
    ("OPT udp size is the ttl", "table[10] = class;", "table[10] = ttl % 65536;"),
    ("OPT version and ext rcode swapped", "table[11] = ttl / 16777216;\n            table[12] = ttl / 65536 % 256;",
     "table[12] = ttl / 16777216;\n            table[11] = ttl / 65536 % 256;"),
    ("trailing bytes accepted", "if pos != len(data) {\n        return error_trailing_bytes();\n    }", ""),
    ("forward pointers allowed", "if target >= pos || target < header_size() {", "if target < header_size() {"),
    ("reserved label types read as labels", "let kind = c / 64;", "let kind = c / 64 % 3;"),
    ("names may be 256 bytes", "if expanded >= max_name() {", "if expanded > max_name() {"),
    ("A data length not checked", "return size == 4;", "return size >= 3;"),
    ("two questions accepted", "if qd != 1 {", "if qd > 2 {"),
    ("65 answers accepted", "an > max_answers()", "an > max_answers() + 1"),
    ("17 pointer hops allowed", "if hops > max_hops() {", "if hops > max_hops() + 1 {"),
    ("pointer into the header allowed", "|| target < header_size()", ""),
    ("OPT in the answers allowed", "if i < an + ns || table[9] >= 0 {", "if table[9] >= 0 {"),
]


def main():
    # Absolute, because each variant is built from a scratch directory, where a relative path means something else.
    cancho = os.path.abspath(sys.argv[1])
    python = shutil.which(sys.argv[2]) if len(sys.argv) > 2 else sys.executable
    source = open(os.path.join(ROOT, "src", "dns.cho")).read()
    survivors, invalid = [], []
    work = tempfile.mkdtemp(prefix="mutharness-")
    try:
        os.makedirs(os.path.join(work, "src"))
        os.makedirs(os.path.join(work, "tests"))
        shutil.copy(os.path.join(HERE, "driver.cho"), os.path.join(work, "tests", "driver.cho"))
        for name, old, new in VARIANTS:
            if source.count(old) != 1:
                invalid.append("%s (the text to change occurs %d times)" % (name, source.count(old)))
                continue
            open(os.path.join(work, "src", "dns.cho"), "w").write(source.replace(old, new))
            built = subprocess.run(
                [cancho, "build", "--std"] + (["--backend", os.environ["CANCHO_BACKEND"]] if os.environ.get("CANCHO_BACKEND") else []) + ["tests/driver.cho", "src/dns.cho", "-o", "driver"],
                cwd=work, capture_output=True, text=True, timeout=120,
            )
            if built.returncode != 0:
                invalid.append("%s (does not build: %s)" % (name, built.stderr.strip().splitlines()[-1] if built.stderr else ""))
                continue
            try:
                ran = subprocess.run(
                    [python, os.path.join(HERE, "differential_codec.py"), os.path.join(work, "driver"), "--valid", "300", "--mutants", "8"],
                    capture_output=True, text=True, timeout=120,
                )
                caught = ran.returncode != 0
                if not caught and name == "17 pointer hops allowed":
                    # The differential corpus no longer carries a 17-hop chain (a dnspython release
                    # began refusing it and moved the case between the columns); the unit tests do.
                    unit = subprocess.run(
                        [cancho, "test"] + (["--backend", os.environ["CANCHO_BACKEND"]] if os.environ.get("CANCHO_BACKEND") else []) + [os.path.join(HERE, "dns_test.cho"), os.path.join(work, "src", "dns.cho"), "--std"],
                        capture_output=True, text=True, timeout=240,
                    )
                    caught = unit.returncode != 0
            except subprocess.TimeoutExpired:
                caught = True  # a hang is a failure the harness would report
            print(("caught:   " if caught else "MISSED:   ") + name, flush=True)
            if not caught:
                survivors.append(name)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for name in invalid:
        print("INVALID:  " + name)
    print("%d of %d variants caught" % (len(VARIANTS) - len(survivors) - len(invalid), len(VARIANTS)))
    sys.exit(1 if survivors or invalid else 0)


if __name__ == "__main__":
    main()
