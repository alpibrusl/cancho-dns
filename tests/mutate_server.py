"""Mutants of src/server.cho and src/stub.cho: tests/server_test.py must fail on each.

usage: mutate_server.py <cancho> <python>
Each mutant is built in a scratch copy with a timeout; a mutant that hangs the test run counts as killed.
"""
import os, shutil, subprocess, sys, tempfile

cancho = os.path.abspath(shutil.which(sys.argv[1]) or sys.argv[1])
here = os.path.dirname(os.path.abspath(__file__)); root = os.path.dirname(here)
MUTANTS = [
    # Not listed: `size > frame_max()` -> never. The 4,098-byte input buffer already closes a connection that
    # cannot complete such a frame, so the mutant behaves identically (an explained equivalent, design.md section 13).
    ("src/server.cho", "size < dns.header_size() ||", "false ||", "short frame accepted"),
    ("src/server.cho", "held >= max_connections()", "held > max_connections() + 40", "connection cap raised"),
    ("src/server.cho", "now - st[p + 5] > idle", "now - st[p + 5] > idle * 1000", "idle timeout never fires"),
    ("src/stub.cho", "return 1232;", "return 65535;", "EDNS ceiling removed"),
    ("src/stub.cho", "return 512;", "return 4096;", "UDP floor raised"),
]
killed = 0
for path, old, new, why in MUTANTS:
    with tempfile.TemporaryDirectory() as d:
        shutil.copytree(os.path.join(root, "src"), os.path.join(d, "src"))
        f = os.path.join(d, path); text = open(f).read()
        assert text.count(old) >= 1, (path, old)
        open(f, "w").write(text.replace(old, new, 1))
        backend = os.environ.get("CANCHO_BACKEND")
        cmd = [cancho, "build", "--std"]
        if backend:
            cmd += ["--backend", backend]
        b = subprocess.run(cmd + ["src/server.cho", "src/dns.cho", "src/stub.cho", "src/cache.cho", "src/store.cho", "src/rng.cho", "src/forward.cho", "src/upstreams.cho", "src/limit.cho", "src/access.cho", "src/local.cho", "src/localtab.cho", "src/cli.cho", "src/rules.cho", "src/log.cho", "-o", "server"],
                           cwd=d, capture_output=True, text=True)
        if b.returncode != 0:
            print("BUILD FAILED (mutant invalid):", why, b.stderr[-200:]); sys.exit(1)
        try:
            t = subprocess.run([sys.argv[2], os.path.join(here, "server_test.py"), os.path.join(d, "server")],
                               capture_output=True, timeout=90)
            dead = t.returncode != 0
        except subprocess.TimeoutExpired:
            dead = True
    print(("killed  " if dead else "SURVIVED"), why)
    killed += dead
print("%d of %d mutants killed" % (killed, len(MUTANTS)))
sys.exit(0 if killed == len(MUTANTS) else 1)
