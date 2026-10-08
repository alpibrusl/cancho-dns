"""Gate 3b of docs/design.md section 15: memory while every query is a miss that is forwarded.

usage: forward_memory_test.py <cancho> [<queries>]

100,000 (by default) distinct names are forwarded through a resolver with a 1 MiB cache. `VmRSS` after 80,000 and after the last must
agree within 1% (the first 65,536 datagrams touch the runtime's peer ring for the first time, section 14.1), the cache must have
evicted and stayed inside its key cap, and the socket table must be empty at the end: every query's socket is closed.
"""
import os, socket, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h
import dns.message

CANCHO = os.path.abspath(sys.argv[1])
N = int(sys.argv[2]) if len(sys.argv) > 2 else 100000


def open_fds(pid):
    return len(os.listdir("/proc/%d/fd" % pid))


def main():
    port = h.free_udp_port()
    binary = os.path.join(tempfile.mkdtemp(prefix="fwdmem-"), "server")
    h.build(CANCHO, [port], binary)
    up = h.Upstream(port, lambda q, a, s: [h.answer(q).to_wire()])
    up.seen = type("Discard", (list,), {"append": lambda self, x: None})()
    server = h.Server(binary, memory=1048576, keys=2048)
    try:
        base_fds = open_fds(server.proc.pid)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", server.port))
        batch = 100
        rss = {}
        for start in range(0, N, batch):
            for n in range(start, start + batch):
                sock.send(dns.message.make_query("m%d.example." % n, "A").to_wire())
            for _ in range(batch):
                sock.recv(4096)
            if start + batch == int(N * 0.8):
                rss["early"] = server.rss_kb()
        rss["late"] = server.rss_kb()
        st = server.stats()
        fds = open_fds(server.proc.pid)
    finally:
        up.stop(); server.stop()
    growth = (rss["late"] - rss["early"]) / rss["early"]
    print("RSS after %d: %d KiB; after %d: %d KiB; growth %.2f%%; evicted %d; live %d; fwd_sent %d; open descriptors %d (at start %d)" % (
        int(N * 0.8), rss["early"], N, rss["late"], growth * 100, st["evicted"], st["live"], st["fwd_sent"], fds, base_fds))
    ok = growth < 0.01 and st["evicted"] > 0 and st["live"] <= 2048 and st["fwd_sent"] == N and fds <= base_fds + 4
    print("OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
