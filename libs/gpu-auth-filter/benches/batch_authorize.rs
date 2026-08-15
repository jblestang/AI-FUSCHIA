use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use gpu_auth_filter::{AuthorizedBitMask, BatchAuthorize, CpuBatchAuthorize, MaskedRangeRule};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

fn bench_cpu_exact(c: &mut Criterion) {
    let mut group = c.benchmark_group("cpu/authorize_exact");
    let rules = [
        AuthorizedBitMask::exact(0xFFFF_0000, 0x1000_0000),
        AuthorizedBitMask::exact(0x0000_00FF, 0x0000_0023),
    ];

    for &count in &[1_024, 16_384, 262_144] {
        let mut rng = StdRng::seed_from_u64(42);
        let values: Vec<u32> = (0..count).map(|_| rng.random()).collect();
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &values, |b, values| {
            let backend = BatchAuthorize::Cpu(CpuBatchAuthorize);
            b.iter(|| backend.authorize_exact(black_box(values), black_box(&rules)));
        });
    }
    group.finish();
}

fn bench_cpu_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("cpu/authorize_range");
    let rules = [
        MaskedRangeRule { mask: 0xFF, start: 0x10, end: 0x7F },
        MaskedRangeRule { mask: 0xF000, start: 0x1000, end: 0xF000 },
    ];

    for &count in &[1_024, 16_384, 262_144] {
        let mut rng = StdRng::seed_from_u64(7);
        let values: Vec<u32> = (0..count).map(|_| rng.random()).collect();
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &values, |b, values| {
            let backend = BatchAuthorize::Cpu(CpuBatchAuthorize);
            b.iter(|| backend.authorize_range(black_box(values), black_box(&rules)));
        });
    }
    group.finish();
}

#[cfg(feature = "gpu")]
fn bench_gpu_exact(c: &mut Criterion) {
    let Ok(gpu) = gpu_auth_filter::GpuBatchAuthorize::new() else {
        return;
    };
    let backend = BatchAuthorize::Gpu(gpu);
    let mut group = c.benchmark_group("gpu/authorize_exact");
    let rules = [AuthorizedBitMask::exact(0xFFFF, 0x1000)];

    for &count in &[1_024, 65_536, 1_048_576] {
        let values: Vec<u32> = (0..count).map(|i| 0x1000 | (i as u32 & 0xFF)).collect();
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::from_parameter(count), &values, |b, values| {
            b.iter(|| backend.authorize_exact(black_box(values), black_box(&rules)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_cpu_exact,
    bench_cpu_range,
    #[cfg(feature = "gpu")]
    bench_gpu_exact
);
criterion_main!(benches);
