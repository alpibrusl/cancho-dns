"""Mutants of the local-data path: tests/local_test.py must fail on each (docs/design.md section 17, gate 12).

usage: mutate_local.py <cancho> <python3>
"""
import os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

SRC = ["src/server.cho", "src/dns.cho", "src/stub.cho", "src/cache.cho", "src/store.cho", "src/rng.cho",
       "src/forward.cho", "src/limit.cho", "src/local.cho", "src/access.cho", "src/upstreams.cho"]

# (file, old, new, what the mutant gets wrong)
MUTANTS = [
    ("src/server.cho", "if table[1] / 2048 % 16 == 0 && table[8] == 1 {", "if false {", "matching off entirely"),
    ("src/server.cho", "let found = local.find_query(locals, data, table, scratch);", "let found = 0 - 1;",
     "matching removed"),
    ("src/local.cho", "if kind == block_nx() {", "if false {", "a plain block answers from the stub"),
    ("src/local.cho", "atype = 1;", "atype = 28;", "a block with an address answers AAAA rdata as A"),
    ("src/local.cho", "if dns.fold(int_of(names[noff + np + 1 + k])) != dns.fold(int_of(name[qp + 1 + k])) {",
     "if int_of(names[noff + np + 1 + k]) != int_of(name[qp + 1 + k]) {", "case-sensitive matching"),
    ("src/local.cho", "p = dns.put32(out, p, ttl());", "p = dns.put32(out, p, 0);", "TTL zero"),
    ("src/local.cho", "if kind == block_a() {", "if false {", "a block with an address NXDOMAINs A queries"),
]

# The same table tests/local_test.py builds for itself, so the gate asks the mutant the same questions.
CONF = """\
record www.example A 192.0.2.1
override api.example A 192.0.2.2
block ads.example
block tracker.example 192.0.2.254
record *.corp A 192.0.2.3
record example TXT "hello"
record alias.example CNAME www.example
record mail.example MX 10 mx.example
record service.example SRV 0 0 8080 a.example
record www.example AAAA 2001:db8::1
record 1.0.2.192.in-addr.arpa PTR www.example
"""


def main():
    cancho, runner = sys.argv[1], sys.argv[2]
    backend = os.environ.get("CANCHO_BACKEND")
    killed = 0
    for path, old, new, why in MUTANTS:
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(os.path.join(ROOT, "src"), os.path.join(d, "src"))
            f = os.path.join(d, path)
            text = open(f).read()
            assert old in text, (path, old)
            open(f, "w").write(text.replace(old, new, 1))
            conf = os.path.join(d, "local.conf")
            open(conf, "w").write(CONF)
            tab = os.path.join(d, "localtab.cho")
            subprocess.run([sys.executable, os.path.join(HERE, "gen_local.py"), conf, tab], check=True)
            os.remove(os.path.join(d, "src", "localtab.cho"))
            binary = os.path.join(d, "server")
            build = [cancho, "build", "--std"]
            if backend:
                build += ["--backend", backend]
            b = subprocess.run(build + [os.path.join(d, s) for s in SRC] + [tab, "-o", binary],
                               cwd=d, capture_output=True, text=True)
            if b.returncode != 0:
                print("BUILD FAILED (mutant invalid):", why, b.stderr[-200:])
                sys.exit(1)
            t = subprocess.run([runner, os.path.join(HERE, "local_test.py"), cancho, binary],
                               capture_output=True, text=True)
            if t.returncode != 0:
                killed = killed + 1
                print("killed  ", why)
            else:
                print("SURVIVED", why)
    print("%d of %d mutants killed" % (killed, len(MUTANTS)))
    sys.exit(0 if killed == len(MUTANTS) else 1)


if __name__ == "__main__":
    sys.exit(main())
