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

Each `/bytes` iteration processes one second of traffic at the **1.00 Gbps harness target** (~119 MiB wire bytes). Each `/per-packet` iteration receives one datagram.

Bench builds enable `bench-receive` (no-op bindings delivery) so the measurement covers **stack receive only**, not fake-bindings queue allocation. Without `bench-receive`, per-packet cost includes bindings queue work (~+35 ns @ 64 B on typical fake bindings).

Production bindings should use [`UdpReceiveBuffer`](../../core/udp/src/receive_buffer.rs) (Arc-backed payload) and [`UdpApi::try_recv`](../../core/udp/src/base.rs) to dequeue without copying bytes again.

### Stack ceiling (64 B payload, best observed)

| Metric | Value |
|--------|------:|
| Per-packet time | **~110 ns** |
| Stack rate | **~9.2 Mpps** |
| 1 Gbps budget @ 64 B | 736 ns/pkt (~1.36 Mpps needed) |
| Headroom vs 1 Gbps | **~6.7×** |

### Per-packet cost (median, `bench-receive` enabled)

| Payload | Wire size | Time/pkt (best) | Mpps (best) | Headroom vs 1 Gbps |
|--------:|----------:|----------------:|------------:|-------------------:|
| 64 B | 92 B | **~110 ns** | **~9.2** | ~6.7× |
| 128 B | 156 B | ~120 ns | ~8.3 | ~10× |
| 256 B | 284 B | ~130 ns | ~7.7 | ~17× |
| 512 B | 540 B | ~140 ns | ~7.1 | ~31× |
| 1024 B | 1052 B | ~160 ns | ~6.3 | ~53× |
| 1472 B | 1500 B | ~200 ns | ~5.0 | ~60× |
| 4096 B | 4124 B | ~450 ns | ~2.2 | ~73× |
| 8192 B | 8220 B | ~800 ns | ~1.2 | ~82× |
| 9000 B | 9028 B | ~850 ns | ~1.2 | ~85× |

Best-observed numbers come from release builds with early-demux, `single-stack`, single-threaded NoOp `RwLock`, filter bypass, and `bench-receive`. Cloud VM reruns typically land **~140–160 ns @ 64 B** depending on CPU state; treat ~110 ns as the stack ceiling, not a guaranteed floor on every host.

### Batch throughput `/bytes` (1 s @ 1 Gbps per iteration)

With `bench-receive`, the stack processes one second of 1 Gbps wire traffic in roughly:

| Payload | Batch pkts | Time (typical) | Effective rate vs 1 Gbps |
|--------:|-----------:|---------------:|-------------------------:|
| 64 B | 1,358,695 | ~150 ms | ~6.7× |
| 512 B | 231,481 | ~35 ms | ~29× |
| 1472 B | 83,333 | ~20 ms | ~50× |
| 9000 B | 13,845 | ~8 ms | ~125× |

### Summary

- **Stack ceiling:** ~**9.2 Mpps** (~**110 ns**/pkt) at 64 B with all receive hot-path optimizations enabled.
- **1 Gbps @ 64 B** needs ~1.36 Mpps — well within budget.
- **~178 ns @ 64 B** indicates `bench-receive` was not enabled (bindings queue measured); not the stack ceiling.

Criterion may extend measurement time for large `/bytes` batches (64–128 B warn they cannot finish 50 samples in 3 s).
