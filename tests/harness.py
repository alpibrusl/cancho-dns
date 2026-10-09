"""Shared pieces of the forwarding tests: build the server with a chosen upstream table, run it, and play the upstream."""
import os, shutil, socket, subprocess, sys, tempfile, threading, time

import dns.flags, dns.message, dns.query, dns.rcode, dns.rdataclass, dns.rdatatype, dns.rrset

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = ["src/server.cho", "src/dns.cho", "src/stub.cho", "src/cache.cho", "src/store.cho", "src/rng.cho", "src/forward.cho", "src/limit.cho", "src/local.cho", "src/localtab.cho", "src/cli.cho", "src/rules.cho", "src/log.cho", "generated/built.cho"]


def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def build(cancho, upstream_ports, out, mutate=None, access_conf=None, local_tab=None):
    """Build the server in `out` with an upstream table of 127.0.0.1:<port> for each port given (and, with `access_conf`, an access list
    from those lines instead of the repository's). `mutate` is (file, old, new), applied
    to a scratch copy of src/ so that a mutant of the matching code can be built the same way."""
    work = tempfile.mkdtemp(prefix="dnsbuild-")
    try:
        shutil.copytree(os.path.join(ROOT, "src"), os.path.join(work, "src"))
        shutil.copytree(os.path.join(ROOT, "generated"), os.path.join(work, "generated"))
        conf = os.path.join(work, "upstreams.conf")
        with open(conf, "w") as f:
            f.write("".join("127.0.0.1 %d\n" % p for p in upstream_ports))
        gen = os.path.join(work, "upstreams.cho")
        subprocess.run([sys.executable, os.path.join(ROOT, "tests", "gen_upstreams.py"), conf, gen], check=True)
        srcs = [s for s in SOURCES] + ["upstreams.cho"]
        if access_conf is None:
            srcs.append("src/access.cho")
        else:
            with open(os.path.join(work, "access.conf"), "w") as f:
                f.write(access_conf)
            subprocess.run([sys.executable, os.path.join(ROOT, "tests", "gen_access.py"), os.path.join(work, "access.conf"), os.path.join(work, "access.cho")], check=True)
            os.remove(os.path.join(work, "src", "access.cho"))
            srcs.append("access.cho")
        if local_tab:
            # The generated table replaces the repository's own src/localtab.cho.
            srcs = [s for s in srcs if s != "src/localtab.cho"]
            srcs.append(local_tab)
        if mutate:
            f = os.path.join(work, mutate[0]); text = open(f).read()
            assert mutate[1] in text, "mutant does not apply: %r" % (mutate,)
            open(f, "w").write(text.replace(mutate[1], mutate[2], 1))
        # CI builds with the default (LLVM) backend; a machine without clang sets CANCHO_BACKEND (e.g. "cranelift").
        backend = os.environ.get("CANCHO_BACKEND")
        cmd = [cancho, "build", "--std"]
        if backend:
            cmd += ["--backend", backend]
        r = subprocess.run(cmd + srcs + ["-o", os.path.abspath(out)], cwd=work, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError("build failed: " + (r.stderr + r.stdout)[-600:])
    finally:
        shutil.rmtree(work, ignore_errors=True)


class Server:
    def __init__(self, binary, idle=10, min_ttl=1, memory=4 * 1048576, keys=4096, rate=0, burst=1):
        self.port = free_port()
        self.proc = subprocess.Popen([binary, str(self.port), str(idle), str(min_ttl), str(memory), str(keys), str(rate), str(burst)], stderr=subprocess.PIPE)
        line = self.proc.stderr.readline()
        if not line.startswith(b"listening"):
            raise RuntimeError("server did not start: %r" % line)

    def stop(self):
        self.proc.kill(); self.proc.wait(); self.proc.stderr.close()

    def ask(self, name, rtype="A", timeout=8, **kw):
        return dns.query.udp(dns.message.make_query(name, rtype, **kw), "127.0.0.1", port=self.port, timeout=timeout)

    def ask_tcp(self, name, rtype="A", timeout=8, **kw):
        return dns.query.tcp(dns.message.make_query(name, rtype, **kw), "127.0.0.1", port=self.port, timeout=timeout)

    def stats(self):
        r = dns.query.udp(dns.message.make_query("stats.bind.", "TXT", rdclass="CH"), "127.0.0.1", port=self.port, timeout=3)
        out = {}
        for rd in r.answer[0]:
            for s in rd.strings:
                k, v = s.decode().split("=")
                out[k] = int(v)
        return out

    def rss_kb(self):
        with open("/proc/%d/status" % self.proc.pid) as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])


class Upstream:
    """A UDP server on 127.0.0.1:port that answers by `handler(query_message, source_address, socket) -> [bytes] | None`: the wire
    messages to send back, in order, or None for silence. Every query is recorded as (time, source port, message)."""

    def __init__(self, port, handler):
        self.port = port
        self.handler = handler
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.seen = []
        self.lock = threading.Lock()
        self.stopping = False
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        while not self.stopping:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                q = dns.message.from_wire(data)
            except Exception:
                continue
            with self.lock:
                self.seen.append((time.time(), addr[1], q))
            out = self.handler(q, addr, self.sock)
            for w in out or []:
                self.sock.sendto(w, addr)

    def stop(self):
        self.stopping = True
        self.thread.join(timeout=2)
        self.sock.close()

    def count(self):
        with self.lock:
            return len(self.seen)


def answer(q, address="192.0.2.7", ttl=30, rcode=0):
    """The honest reply to `q`: its id, question (so its case) and one A record for the name."""
    r = dns.message.make_response(q, recursion_available=True)
    r.set_rcode(rcode)
    if q.question[0].rdtype == dns.rdatatype.A:
        r.answer.append(dns.rrset.from_text(q.question[0].name, ttl, "IN", "A", address))
    return r


def nxdomain(q, ttl=30):
    r = dns.message.make_response(q, recursion_available=True)
    r.set_rcode(dns.rcode.NXDOMAIN)
    r.authority.append(dns.rrset.from_text("example.", ttl, "IN", "SOA", "ns.example. hostmaster.example. 1 %d %d %d %d" % (ttl, ttl, ttl, ttl)))
    return r
