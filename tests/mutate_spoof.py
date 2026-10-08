"""Mutants of the matching code: tests/spoof_test.py must fail on each (docs/design.md section 15, gate 4).

usage: mutate_spoof.py <cancho>
"""
import os, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

cancho = os.path.abspath(sys.argv[1])
here = os.path.dirname(os.path.abspath(__file__))
MUTANTS = [
    ("src/forward.cho", "    if dns.u16_at(reply, 0) != id {", "    if false {", "the id is not compared"),
    ("src/forward.cho", "    if int_of(reply[2]) < 128 || int_of(reply[2]) / 8 % 16 != 0 {", "    if false {", "QR and the opcode are not checked"),
    ("src/forward.cho", "    if folded {\n        return dropped_case();\n    }", "    if folded {\n        return accepted();\n    }", "the question is compared without regard to case (no 0x20)"),
    ("src/forward.cho", "        if a != b {\n            exact = false;", "        if a != b && i >= sent_name {\n            exact = false;", "the name in the question is not compared"),
    ("src/forward.cho", "        if a != b {\n            exact = false;", "        if a != b && i < sent_name {\n            exact = false;", "the type and class in the question are not compared"),
    ("src/server.cho", "    if verdict != forward.accepted() {", "    if false {", "no reply is judged: whatever arrives is the answer"),
    ("src/cache.cho", "dns.names_equal(cur[0..cn], tmp[0..n]) && ", "", "records outside the answer chain are cached"),
]
killed = 0
for path, old, new, why in MUTANTS:
    port = h.free_udp_port()
    out = tempfile.mktemp(prefix="mutant-")
    try:
        h.build(cancho, [port], out, mutate=(path, old, new))
    except RuntimeError as e:
        print("BUILD FAILED (mutant invalid):", why, str(e)[-300:]); sys.exit(2)
    try:
        r = subprocess.run([sys.executable, os.path.join(here, "spoof_test.py"), cancho, out, str(port)], capture_output=True, timeout=240)
        dead = r.returncode != 0
    except subprocess.TimeoutExpired:
        dead = True
    finally:
        if os.path.exists(out):
            os.remove(out)
    print(("killed  " if dead else "SURVIVED"), why, flush=True)
    killed += dead
print("%d of %d mutants killed" % (killed, len(MUTANTS)))
sys.exit(0 if killed == len(MUTANTS) else 1)
