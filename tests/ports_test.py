"""Gate 5 of docs/design.md section 15: the source ports of the upstream sockets, collected and reported whichever way they point.

usage: ports_test.py <cancho> [<queries>]

10,000 (by default) distinct names are asked of a resolver whose one upstream records the source port of every query it gets. The
report: distinct ports, the number that many independent uniform draws from the range would give, the range seen, the share inside the
kernel's ephemeral range, the lag-1 serial correlation, and a chi-square over 16 equal bins. The pre-registered reading (section 15):
fewer than 95% of the expected distinct ports, or a lag-1 correlation over 0.05 in absolute value, is "predictable". The test fails
if the ports are predictable, and prints the report either way.
"""
import json, math, os, socket, struct, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness as h
import dns.message

CANCHO = os.path.abspath(sys.argv[1])
N = int(sys.argv[2]) if len(sys.argv) > 2 else 10000


def ephemeral_range():
    try:
        lo, hi = open("/proc/sys/net/ipv4/ip_local_port_range").read().split()
        return int(lo), int(hi)
    except OSError:
        return 32768, 60999


def main():
    port = h.free_udp_port()
    binary = os.path.join(tempfile.mkdtemp(prefix="ports-"), "server")
    h.build(CANCHO, [port], binary)
    up = h.Upstream(port, lambda q, a, s: [h.answer(q).to_wire()])
    server = h.Server(binary, memory=8 * 1048576, keys=16384)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", server.port))
        batch = 100
        for start in range(0, N, batch):
            for n in range(start, min(N, start + batch)):
                sock.send(dns.message.make_query("p%d.example." % n, "A").to_wire())
            for _ in range(min(batch, N - start)):
                sock.recv(4096)
        ports = [p for _, p, _ in up.seen]
    finally:
        up.stop(); server.stop()
    lo, hi = ephemeral_range()
    span = hi - lo + 1
    n = len(ports)
    distinct = len(set(ports))
    expected = span * (1 - (1 - 1 / span) ** n)
    inside = sum(1 for p in ports if lo <= p <= hi) / n
    mean = sum(ports) / n
    num = sum((ports[i] - mean) * (ports[i + 1] - mean) for i in range(n - 1))
    den = sum((p - mean) ** 2 for p in ports)
    lag1 = num / den
    bins = [0] * 16
    for p in ports:
        if lo <= p <= hi:
            bins[min(15, (p - lo) * 16 // span)] += 1
    e = sum(bins) / 16
    chi2 = sum((b - e) ** 2 / e for b in bins)
    report = {
        "queries": n, "distinct": distinct, "expected_distinct_if_uniform": round(expected, 1),
        "distinct_over_expected": round(distinct / expected, 4), "min": min(ports), "max": max(ports),
        "ephemeral_range": [lo, hi], "share_in_range": round(inside, 4), "lag1_correlation": round(lag1, 4),
        "chi_square_16_bins": round(chi2, 2), "chi_square_critical_p001_df15": 37.7,
    }
    print(json.dumps(report, indent=2))
    predictable = distinct < 0.95 * expected or abs(lag1) > 0.05
    print("READING: " + ("PREDICTABLE (pre-registered threshold crossed)" if predictable else "not predictable by the pre-registered tests"))
    return 1 if predictable else 0


if __name__ == "__main__":
    sys.exit(main())
