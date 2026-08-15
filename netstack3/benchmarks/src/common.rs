use core::time::Duration;

use criterion::{BenchmarkGroup, measurement::WallTime};

pub fn configure_group(group: &mut BenchmarkGroup<'_, WallTime>) {
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));
    group.sample_size(50);
}
