# D10's measured numbers (task #14)

Machine: this run's host, loopback upstream, cranelift build (the release/LLVM build and the
incumbent comparison are CI's, on its pinned runner; see section 8.1 for what these can and
cannot say). Load generator: this harness's own rate-limited UDP/TCP client, not dnsperf.

- A_udp_hit_qps: 146280.61
- A_udp_hit_answered: 5000
- B_udp_miss_qps: 5555.38
- D_rss_kib: 7604
- D_names: 20000
- E_p50_ms: 0.06
- E_p99_ms: 0.1
- C_tcp_hit_qps: 24306.28
- binary_bytes: 228304
- start_to_ready_ms: 8.27

The incumbents' cells are not measured here (not installed on this host); CI installs them.