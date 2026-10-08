"""Mutants of the access list and the rate limiter: tests/access_test.py and tests/rate_test.py must fail on each (docs/design.md
section 16, gates 7 and 8).

usage: mutate_access.py <cancho>
"""
import os, subprocess, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

cancho = os.path.abspath(sys.argv[1])
here = os.path.dirname(os.path.abspath(__file__))
CONF = "allow 127.0.0.1/32\nallow 127.0.1.0/24\n"
# (file, old, new, what, which test judges it)
MUTANTS = [
    ("src/server.cho", "} else if address < 0 || !access.allowed(address) {", "} else if address < 0 || access.allowed(address) {", "the UDP check is inverted", "access"),
    ("src/server.cho", "} else if address < 0 || !access.allowed(address) {", "} else if false {", "the UDP check is removed", "access"),
    ("src/server.cho", "                            if address < 0 || !access.allowed(address) {\n", "                            if false {\n", "the TCP check is removed", "access"),
    ("src/server.cho", "                            if address < 0 || !access.allowed(address) {\n", "                            if address < 0 || access.allowed(address) {\n", "the TCP check is inverted", "access"),
    ("access.cho", "        if address & mask(i) == network(i) {", "        if address & 4294967040 == network(i) & 4294967040 {", "a prefix length is ignored (every prefix is a /24)", "access"),
    ("src/limit.cho", "    if p[0] <= 0 {\n        return true;\n    }", "    if true {\n        return true;\n    }", "the limiter is off", "rate"),
    ("src/limit.cho", "bucket_of(address / 256, p[2])", "bucket_of(address, p[2])", "buckets are keyed by the full address, not the /24", "rate"),
    ("src/limit.cho", "        tokens = tokens + elapsed * p[0];", "        tokens = tokens + 0;", "a bucket never refills", "rate"),
    ("src/limit.cho", "    cells[b] = tokens - 1000;\n    return true;", "    cells[b] = tokens;\n    return true;", "a response costs nothing", "rate"),
    ("src/limit.cho", "            cells[2 * i] = burst * 1000;", "            cells[2 * i] = burst * 100000;", "the bucket starts far over the burst", "unit"),
    ("src/limit.cho", "        if tokens > p[1] * 1000 {\n            tokens = p[1] * 1000;\n        }", "", "the burst is not a ceiling", "rate"),
    ("src/server.cho", "                if !limit.allow(core.limiter, network, now) {", "                if false && !limit.allow(core.limiter, network, now) {", "the server never asks the limiter", "rate"),
]
killed = 0
for path, old, new, why, which in MUTANTS:
    if which == "unit":
        # Only a clock at 0 shows this one (any later first touch clamps the bucket to the burst), so the judge is the unit test, which
        # asks at time 0.
        import shutil
        work = tempfile.mkdtemp(prefix="mutant-unit-")
        try:
            shutil.copytree(os.path.join(os.path.dirname(here), "src"), os.path.join(work, "src"))
            shutil.copytree(here, os.path.join(work, "tests"), ignore=shutil.ignore_patterns("__pycache__"))
            f = os.path.join(work, path); text = open(f).read()
            assert old in text, why
            open(f, "w").write(text.replace(old, new, 1))
            r = subprocess.run([cancho, "test", "tests/limit_test.cho", "src/limit.cho", "src/access.cho", "--std"], cwd=work, capture_output=True, text=True, timeout=240)
            dead = r.returncode != 0
        finally:
            shutil.rmtree(work, ignore_errors=True)
        print(("killed  " if dead else "SURVIVED"), why, "[unit]", flush=True)
        killed += dead
        continue
    out = tempfile.mktemp(prefix="mutant-")
    try:
        h.build(cancho, [], out, mutate=(path, old, new), access_conf=CONF if which == "access" else None)
    except (RuntimeError, AssertionError) as e:
        print("BUILD FAILED (mutant invalid):", why, str(e)[-300:]); sys.exit(2)
    try:
        r = subprocess.run([sys.executable, os.path.join(here, which + "_test.py"), cancho, out], capture_output=True, timeout=240)
        dead = r.returncode != 0
    except subprocess.TimeoutExpired:
        dead = True
    finally:
        if os.path.exists(out):
            os.remove(out)
    print(("killed  " if dead else "SURVIVED"), why, "[%s]" % which, flush=True)
    killed += dead
print("%d of %d mutants killed" % (killed, len(MUTANTS)))
sys.exit(0 if killed == len(MUTANTS) else 1)
