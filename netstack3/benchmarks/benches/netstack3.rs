use criterion::{Criterion, criterion_group, criterion_main};

fn bench_netstack3(c: &mut Criterion) {
    let mut base_group = c.benchmark_group("netstack3/base");
    netstack3_benchmarks::common::configure_group(&mut base_group);
    netstack3_benchmarks::token_bucket::add_benches(&mut base_group);
    base_group.finish();

    let mut udp_group = c.benchmark_group("netstack3/udp/receive_throughput");
    netstack3_benchmarks::common::configure_group(&mut udp_group);
    netstack3_udp::bench_support::add_benches(&mut udp_group);
    udp_group.finish();
}

criterion_group!(benches, bench_netstack3);
criterion_main!(benches);
