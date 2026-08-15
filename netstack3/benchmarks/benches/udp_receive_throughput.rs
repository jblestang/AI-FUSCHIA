use criterion::{Criterion, criterion_group, criterion_main};

fn bench_udp_receive(c: &mut Criterion) {
    let mut group = c.benchmark_group("netstack3/udp/receive_throughput");
    netstack3_benchmarks::common::configure_group(&mut group);
    netstack3_udp::bench_support::add_benches(&mut group);
    group.finish();
}

criterion_group!(benches, bench_udp_receive);
criterion_main!(benches);
