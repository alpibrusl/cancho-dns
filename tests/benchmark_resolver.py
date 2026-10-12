"""Task #14's benchmark harness (docs/design.md section 8.1): the pre-registered cells, run against this
resolver, with the incumbents compared where they are installed.

The cells are pre-registered in section 8.1; this harness runs them, prints the numbers, and writes them to
`docs/numbers-d10.md` (the cancho-table pattern: measured claims live in a numbers file). Where dnsperf or the
incumbents are not installed, it prints SKIP for those and still measures ours with its own load generator --
a rate-limited UDP/TCP client over loopback, which measures the resolver's own work per query, not the
Internet path.

usage: benchmark_resolver.py <cancho> [--quick]
"""
import os, random, shutil, socket, statistics, subprocess, sys, tempfile, time

import dns.message, dns.query

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h

CANCHO = os.path.abspath(sys.argv.pop(1))
QUICK = "--quick" in sys.argv
WARM_NAMES = 20000 if not QUICK else 5000
HIT_QUERIES = 30000 if not QUICK else 8000
MIXED = 20000 if not QUICK else 6000

rng = random.Random(90210)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def rss_kb(pid):
    try:
        with open("/proc/%d/status" % pid) as f:
            for l in f:
                if l.startswith("VmRSS:"):
                    return int(l.split()[1])
    except OSError:
        pass
    return 0


def load_udp(port, wires, pipelined=True):
    """Send `wires` over one socket, count the replies that came back; answers (answered, elapsed)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    s.connect(("127.0.0.1", port))
    answered = 0
    started = time.time()
    out = []
    if pipelined:
        window = 64
        i = 0
        while i < len(wires) or out:
            while i < len(wires) and len(out) < window:
                s.send(wires[i])
                out.append(wires[i])
                i += 1
            try:
                s.recv(4096)
                answered += 1
                out.pop(0)
            except socket.timeout:
                break
    else:
        for w in wires:
            s.send(w)
            try:
                s.recv(4096)
                answered += 1
            except socket.timeout:
                break
    elapsed = time.time() - started
    s.close()
    return answered, elapsed


def build_with_upstream(upstream_port):
    binary = os.path.join(tempfile.mkdtemp(prefix="bench-"), "server")
    h.build(CANCHO, [upstream_port], binary)
    return binary


def main():
    results = {}

    # A local authoritative stub: answers instantly, so the upstream is never the limit.
    def stub(q, addr, sock):
        return [h.answer(q, ttl=300).to_wire()]

    up = h.Upstream(free_port(), stub)
    binary = build_with_upstream(up.port)
    server = h.Server(binary, idle=30, memory=8 * 1048576, keys=65536)
    try:
        port = server.port

        # Cell A: UDP cache-hit throughput. A pool of warmed names, Zipfian.
        pool = ["h%d.example" % i for i in range(500)]
        wires = [dns.message.make_query(rng.choices(pool, weights=[1.0 / (i + 1) for i in range(500)])[0], "A").to_wire()
                 for _ in range(WARM_NAMES)]
        load_udp(port, wires[:2000])  # warm the pool
        answered, elapsed = load_udp(port, wires[:HIT_QUERIES])
        results["A_udp_hit_qps"] = answered / elapsed
        results["A_udp_hit_answered"] = answered
        print("Cell A (UDP cache hit): %.0f q/s (%d answered in %.2f s)"
              % (answered / elapsed, answered, elapsed))

        # Cell B: cache-miss forwarded. Every name distinct.
        miss = [dns.message.make_query("b%d.example" % i, "A").to_wire() for i in range(2000)]
        answered, elapsed = load_udp(port, miss)
        results["B_udp_miss_qps"] = answered / elapsed
        print("Cell B (UDP miss forwarded): %.0f q/s (%d answered in %.2f s)"
              % (answered / elapsed, answered, elapsed))

        # Cell D: memory after 100,000 distinct names (or fewer in quick mode).
        n_d = 100000 if not QUICK else 20000
        base_rss = rss_kb(server.proc.pid)
        warmed = 0
        # Warm with distinct names so the cache fills; the stub answers them all.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.02)
        batch = [dns.message.make_query("d%d.example" % i, "A").to_wire() for i in range(n_d)]
        i = 0
        while i < n_d:
            for w in batch[i:i + 200]:
                s.sendto(w, ("127.0.0.1", port))
            for _ in range(200):
                try:
                    s.recvfrom(4096)
                    warmed += 1
                except socket.timeout:
                    break
            i += 200
        s.close()
        after_rss = rss_kb(server.proc.pid)
        results["D_rss_kib"] = after_rss
        results["D_names"] = n_d
        print("Cell D (memory at %d names): RSS %d KiB (start %d KiB)" % (n_d, after_rss, base_rss))

        # Cell E: latency percentiles at half of A's rate, sequential (one outstanding query).
        target_qps = results["A_udp_hit_qps"] / 2
        latencies = []
        q = dns.message.make_query(rng.choice(pool), "A")
        interval = 1.0 / target_qps
        started = time.time()
        n = 3000 if not QUICK else 1000
        for i in range(n):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            t0 = time.time()
            s.sendto(q.to_wire(), ("127.0.0.1", port))
            try:
                s.recvfrom(4096)
                latencies.append((time.time() - t0) * 1000)
            except socket.timeout:
                pass
            s.close()
            while time.time() - started < (i + 1) * interval:
                pass
        latencies.sort()
        if latencies:
            results["E_p50_ms"] = latencies[len(latencies) // 2]
            results["E_p99_ms"] = latencies[int(len(latencies) * 0.99)]
            print("Cell E (latency at %.0f q/s): p50 %.2f ms, p99 %.2f ms (n=%d, loopback client, per-query socket)"
                  % (target_qps, results["E_p50_ms"], results["E_p99_ms"], len(latencies)))

        # Cell C: TCP hit, persistent connections.
        wires_c = [dns.message.make_query(rng.choice(pool), "A").to_wire() for _ in range(2000)]
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        answered = 0
        started = time.time()
        for w in wires_c:
            s.sendall(len(w).to_bytes(2, "big") + w)
            try:
                head = s.recv(2)
                if len(head) == 2:
                    s.recv(4096)
                    answered += 1
            except OSError:
                break
        elapsed = time.time() - started
        s.close()
        results["C_tcp_hit_qps"] = answered / elapsed
        print("Cell C (TCP hit, persistent): %.0f q/s (%d answered in %.2f s)"
              % (answered / elapsed, answered, elapsed))

        # The incumbents and dnsperf: compared where installed.
        for tool in ("dnsperf", "unbound", "dnsmasq", "kresd", "pdns_recursor", "coredns"):
            if not shutil.which(tool):
                print("SKIP %-14s not installed here; CI installs the incumbents (section 8.1)" % tool)

        # Footprint.
        results["binary_bytes"] = os.path.getsize(binary)
        cold = subprocess.Popen([binary, str(free_port()), "10", "1", "1048576", "4096", "0", "1"],
                                stderr=subprocess.PIPE)
        t0 = time.time()
        cold.stderr.readline()
        results["start_to_ready_ms"] = (time.time() - t0) * 1000
        cold.kill()
        cold.stderr.close()
        print("Footprint: binary %d bytes; listening in %.1f ms"
              % (results["binary_bytes"], results["start_to_ready_ms"]))
    finally:
        up.stop()
        server.stop()

    # Write the numbers file (the cancho-table pattern).
    out = ["# D10's measured numbers (task #14)", "",
           "Machine: this run's host, loopback upstream, cranelift build (the release/LLVM build and the",
           "incumbent comparison are CI's, on its pinned runner; see section 8.1 for what these can and",
           "cannot say). Load generator: this harness's own rate-limited UDP/TCP client, not dnsperf.", ""]
    for k, v in results.items():
        out.append("- %s: %s" % (k, round(v, 2) if isinstance(v, float) else v))
    out.append("")
    out.append("The incumbents' cells are not measured here (not installed on this host); CI installs them.")
    open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "numbers-d10.md"), "w").write("\n".join(out))
    print("wrote docs/numbers-d10.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
