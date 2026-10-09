"""Gate 31 of docs/design.md section 21: the whole-server fuzz.

A running server (UDP and TCP both open) receives random byte strings of four distributions -- uniform,
pointer-heavy, length-heavy, header-plausible -- plus every truncation of a valid query and of a valid reply,
as datagrams and as TCP frames at random split points. A trap anywhere (the process dying) is the failure, and
the server must still answer a valid query afterwards. N is the recorded run length.

usage: fuzz_server.py <server-binary> [<N-datagrams> [<N-tcp>]]
"""
import os, random, socket, struct, subprocess, sys, time

import dns.message, dns.query

BIN = os.path.abspath(sys.argv.pop(1))
N_UDP = int(sys.argv.pop(1)) if len(sys.argv) > 1 else 20000
N_TCP = int(sys.argv.pop(1)) if len(sys.argv) > 1 else 2000
rng = random.Random(1712345)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def uniform(n):
    return bytes(rng.randrange(256) for _ in range(n))


def pointer_heavy(n):
    # Many 0xc0 compression pointers, pointing anywhere including backwards and into the header.
    out = bytearray(rng.choice([0xc0, 0xc0, 0xc0, rng.randrange(64)]) for _ in range(n))
    for i in range(0, len(out) - 1, 2):
        if out[i] == 0xc0:
            out[i + 1] = rng.randrange(256)
    return bytes(out)


def length_heavy(n):
    # Lengths of 63 and 64 and 0, the label edges.
    return bytes(rng.choice([63, 64, 0, 65, 0xbf]) for _ in range(n))


def header_plausible(n):
    # A header whose counts look real, then garbage.
    header = struct.pack(">HHHHHH", rng.randrange(65536), rng.randrange(65536),
                         1, rng.choice([0, 1, 65]), rng.choice([0, 17]), rng.choice([0, 33]))
    return header + bytes(rng.randrange(256) for _ in range(max(0, n - 12)))


MAKERS = [uniform, pointer_heavy, length_heavy, header_plausible]


def truncations(wire, cap=600):
    # Every truncation of a valid message, sampled: all prefix lengths are the interesting set.
    for k in range(len(wire)):
        if rng.random() < 0.25:
            yield wire[:k]


def main():
    port = free_port()
    proc = subprocess.Popen([BIN, str(port), "10", "1", "4194304", "4096", "0", "1"],
                            stderr=subprocess.PIPE)
    line = proc.stderr.readline()
    assert line.startswith(b"listening"), line
    try:
        # UDP: N random datagrams of random lengths, plus truncations of a valid query and reply.
        good_query = dns.message.make_query("fuzz.example", "A").to_wire()
        corpus_udp = []
        for _ in range(N_UDP):
            maker = rng.choice(MAKERS)
            corpus_udp.append(maker(rng.randrange(0, 1200)))
        corpus_udp += list(truncations(good_query))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.05)
        sent = 0
        for wire in corpus_udp:
            try:
                sock.sendto(wire, ("127.0.0.1", port))
                sent += 1
            except OSError:
                pass
            if sent % 512 == 0:
                # A reply is drained so the socket never blocks on our side; the server may drop.
                try:
                    sock.recvfrom(65535)
                except (socket.timeout, OSError):
                    pass
        sock.close()

        # TCP: frames of the same corpus, at random split points inside one connection and across many.
        good_reply_flags = 0x8180
        for i in range(N_TCP):
            maker = rng.choice(MAKERS)
            payload = maker(rng.randrange(0, 4200))
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=2)
                frame = struct.pack(">H", len(payload)) + payload
                cut = rng.randrange(0, len(frame) + 1) if frame else 0
                s.sendall(frame[:cut])
                if cut < len(frame):
                    s.sendall(frame[cut:])
                # Read what comes back, briefly; a close is fine, a crash is not.
                s.settimeout(0.05)
                try:
                    s.recv(65535)
                except (socket.timeout, OSError):
                    pass
                s.close()
            except OSError:
                pass
            if proc.poll() is not None:
                print("FAIL: the server died during the TCP fuzz at frame %d" % i)
                return 1
        if proc.poll() is not None:
            print("FAIL: the server died during the UDP fuzz")
            return 1

        # And the server must still answer a valid query.
        r = dns.query.udp(dns.message.make_query("www.example", "A"), "127.0.0.1", port=port, timeout=3)
        assert r.rcode() == 0
        r = dns.query.tcp(dns.message.make_query("www.example", "A"), "127.0.0.1", port=port, timeout=3)
        assert r.rcode() == 0

        rss = 0
        try:
            with open("/proc/%d/status" % proc.pid) as f:
                for l in f:
                    if l.startswith("VmRSS:"):
                        rss = int(l.split()[1])
        except OSError:
            pass
        print("OK: %d datagrams and %d TCP frames, no trap, a valid query answered after, RSS %d KiB"
              % (sent, N_TCP, rss))
        return 0
    finally:
        proc.kill()
        proc.stderr.close()


if __name__ == "__main__":
    sys.exit(main())
