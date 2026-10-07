"""Mutants of src/cache.cho: tests/cache_test.cho must fail on each (docs/design.md section 14, gate 3 part 4).

usage: mutate_cache.py <cancho>
Each mutant is a scratch copy of src/ with one change, built and run under a timeout; a hang counts as killed.
"""
import os, shutil, subprocess, sys, tempfile

cancho = os.path.abspath(shutil.which(sys.argv[1]) or sys.argv[1])
here = os.path.dirname(os.path.abspath(__file__)); root = os.path.dirname(here)
MUTANTS = [
    ("dns.put32(out, p + 4, ttl - elapsed);", "dns.put32(out, p + 4, ttl);", "TTLs are not decremented on a hit"),
    ("    if ttl < lo {\n        return lo;", "    if ttl < lo {\n        return ttl;", "the TTL floor is gone"),
    ("    if ttl > hi {\n        return hi;", "    if ttl > hi {\n        return ttl;", "the TTL ceiling is gone"),
    ("dns.names_equal(cur[0..cn], tmp[0..n]) && ", "", "records outside the answer chain are kept"),
    ("(rt[b + 1] == 5 || rt[b + 1] == rt[7])", "true", "any type is kept for the chain name"),
    ("key[i] = byte_of(dns.fold(int_of(key[i])));", "key[i] = key[i];", "keys are case-sensitive"),
    ("store.evict_lru()", "store.evict_none()", "no eviction"),
    ("flags / 512 % 2 == 1 || ", "", "a truncated reply is cached"),
    ("life = smaller(life, ttl);", "life = ttl;", "the entry lives for the last TTL, not the smallest"),
    ("smaller(rt[b + 3], minimum)", "rt[b + 3]", "a negative answer ignores the SOA MINIMUM"),
    ("        if !found {\n            bump(cache, 3);\n            return 1;\n        }", "", "a negative answer with no SOA is cached"),
    ("    if limit > 0 && p + extra > limit {", "    if false {", "a hit ignores the client's size limit"),
    ("    dns.put16(out, 0, table[0]);\n    dns.put16(out, 2,", "    dns.put16(out, 2,", "the client's id is not put on a hit"),
    ("        out[i] = query[i];\n        i = i + 1;\n    }\n    let records", "        i = i + 1;\n    }\n    let records", "the client's question is not put on a hit"),
    ("    if rt[7] != qt[7] || rt[8] != qt[8] {", "    if false {", "a reply to another question is cached"),
    ("        life = lim[4];", "        life = lim[1];", "SERVFAIL is kept for a day"),
]
killed = 0
for old, new, why in MUTANTS:
    with tempfile.TemporaryDirectory() as d:
        shutil.copytree(os.path.join(root, "src"), os.path.join(d, "src"))
        shutil.copytree(here, os.path.join(d, "tests"), ignore=shutil.ignore_patterns("__pycache__"))
        f = os.path.join(d, "src", "cache.cho"); text = open(f).read()
        if old not in text:
            print("MUTANT DOES NOT APPLY:", why); sys.exit(2)
        open(f, "w").write(text.replace(old, new, 1))
        try:
            t = subprocess.run([cancho, "test", "tests/cache_test.cho", "src/dns.cho", "src/stub.cho", "src/cache.cho", "src/store.cho", "--std"],
                               cwd=d, capture_output=True, text=True, timeout=300)
            dead = t.returncode != 0
            if dead and "error" in t.stderr + t.stdout and "FAILED" not in t.stdout:
                print("BUILD FAILED (mutant invalid):", why, (t.stderr + t.stdout)[-300:]); sys.exit(2)
        except subprocess.TimeoutExpired:
            dead = True
    print(("killed  " if dead else "SURVIVED"), why)
    killed += dead
print("%d of %d mutants killed" % (killed, len(MUTANTS)))
sys.exit(0 if killed == len(MUTANTS) else 1)
