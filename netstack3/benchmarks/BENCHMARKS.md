# netstack3-benchmarks

Run the aggregate harness:

```bash
cargo bench -p netstack3-benchmarks --bench netstack3
```

UDP-only:

```bash
cargo bench -p netstack3-benchmarks --bench udp_receive_throughput
```

## UDP IPv4 connected receive (early-demux)

Measured on a Cloud Agent VM, release profile. Each `/bytes` iteration processes one second of traffic at the **1.00 Gbps harness target** (~119 MiB wire bytes). Each `/per-packet` iteration receives one datagram.

### Per-packet cost (median)

| Payload | Wire size | Pkts @ 1 Gbps | Time/pkt | Stack rate | Headroom |
|--------:|----------:|--------------:|---------:|-----------:|---------:|
| 64 B | 92 B | 1.36 M/s | 178 ns | 5.60 Mpps | 4.1× |
| 128 B | 156 B | 801 K/s | 185 ns | 5.42 Mpps | 6.8× |
| 256 B | 284 B | 440 K/s | 198 ns | 5.04 Mpps | 11.5× |
| 512 B | 540 B | 231 K/s | 212 ns | 4.71 Mpps | 20.5× |
| 1024 B | 1052 B | 119 K/s | 271 ns | 3.69 Mpps | 31.1× |
| 1472 B | 1500 B | 83 K/s | 335 ns | 2.99 Mpps | 35.9× |
| 4096 B | 4124 B | 30 K/s | 802 ns | 1.25 Mpps | 41.1× |
| 8192 B | 8220 B | 15 K/s | 1.23 µs | 0.81 Mpps | 53.3× |
| 9000 B | 9028 B | 14 K/s | 1.56 µs | 0.64 Mpps | 46.2× |

### Batch throughput `/bytes` (1 s @ 1 Gbps per iteration)

| Payload | Batch pkts | Batch size | Time | Throughput | vs 1 Gbps |
|--------:|-----------:|-----------:|-----:|-----------:|----------:|
| 64 B | 1,358,695 | 119 MiB | 242 ms | 492 MiB/s | 4.1× |
| 128 B | 801,282 | 119 MiB | 148 ms | 807 MiB/s | 6.8× |
| 256 B | 440,140 | 119 MiB | 85.5 ms | 1.36 GiB/s | 11.5× |
| 512 B | 231,481 | 119 MiB | 48.1 ms | 2.42 GiB/s | 20.5× |
| 1024 B | 118,821 | 119 MiB | 28.8 ms | 4.05 GiB/s | 34.8× |
| 1472 B | 83,333 | 119 MiB | 23.5 ms | 4.96 GiB/s | 42.6× |
| 4096 B | 30,310 | 119 MiB | 13.7 ms | 8.47 GiB/s | 72.7× |
| 8192 B | 15,206 | 119 MiB | 9.6 ms | 12.1 GiB/s | 104× |
| 9000 B | 13,845 | 119 MiB | 9.2 ms | 12.6 GiB/s | 108× |

### Summary

- **Stack ceiling:** ~5.6 Mpps at 64 B (~178 ns/pkt fixed overhead).
- **1 Gbps @ 64 B** needs ~1.36 Mpps (736 ns/pkt budget) — **~4× headroom** at minimum MTU.
- Larger payloads amortize per-packet overhead; at 9000 B the stack processes 1 Gbps-equivalent traffic in ~9 ms instead of 1000 ms.

Criterion may extend measurement time for large `/bytes` batches (64–128 B warn they cannot finish 50 samples in 3 s).
