//! GPU batch authorization via wgpu compute shaders.

use crate::{AuthorizedBitMask, MaskedRangeRule};

use bytemuck::{Pod, Zeroable};
use wgpu::util::DeviceExt;

/// GPU compute backend for batch bitmask authorization.
pub struct GpuBatchAuthorize {
    device: wgpu::Device,
    queue: wgpu::Queue,
    exact_pipeline: wgpu::ComputePipeline,
    range_pipeline: wgpu::ComputePipeline,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct ExactRuleGpu {
    mask: u32,
    authorized: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct RangeRuleGpu {
    mask: u32,
    start: u32,
    end: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Params {
    value_count: u32,
    rule_count: u32,
    _pad: [u32; 2],
}

const WORKGROUP_SIZE: u32 = 256;

const EXACT_SHADER: &str = r#"
struct ExactRule {
    mask: u32,
    authorized: u32,
}

struct Params {
    value_count: u32,
    rule_count: u32,
}

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read> values: array<u32>;
@group(0) @binding(2) var<storage, read> rules: array<ExactRule>;
@group(0) @binding(3) var<storage, read_write> results: array<u32>;

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    if (i >= params.value_count) {
        return;
    }
    let v = values[i];
    var pass = true;
    for (var r = 0u; r < params.rule_count; r = r + 1u) {
        let rule = rules[r];
        if ((v & rule.mask) != (rule.authorized & rule.mask)) {
            pass = false;
            break;
        }
    }
    results[i] = select(0u, 1u, pass);
}
"#;

const RANGE_SHADER: &str = r#"
struct RangeRule {
    mask: u32,
    start: u32,
    end: u32,
}

struct Params {
    value_count: u32,
    rule_count: u32,
}

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read> values: array<u32>;
@group(0) @binding(2) var<storage, read> rules: array<RangeRule>;
@group(0) @binding(3) var<storage, read_write> results: array<u32>;

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    if (i >= params.value_count) {
        return;
    }
    let v = values[i];
    var pass = true;
    for (var r = 0u; r < params.rule_count; r = r + 1u) {
        let rule = rules[r];
        let masked = v & rule.mask;
        if (masked < rule.start || masked > rule.end) {
            pass = false;
            break;
        }
    }
    results[i] = select(0u, 1u, pass);
}
"#;

impl GpuBatchAuthorize {
    /// Initializes GPU resources. Returns an error if no adapter is available.
    pub fn new() -> Result<Self, String> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
            backends: wgpu::Backends::all(),
            ..Default::default()
        });

        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        }))
        .ok_or_else(|| "no wgpu adapter available".to_string())?;

        let (device, queue) = pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("gpu-auth-filter"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::default(),
                memory_hints: wgpu::MemoryHints::Performance,
            },
            None,
        ))
        .map_err(|e| format!("failed to create wgpu device: {e}"))?;

        let exact_pipeline = build_pipeline(&device, EXACT_SHADER, "authorize_exact");
        let range_pipeline = build_pipeline(&device, RANGE_SHADER, "authorize_range");

        Ok(Self { device, queue, exact_pipeline, range_pipeline })
    }

    /// Evaluates exact bitmask rules on the GPU.
    pub fn authorize_exact(&self, values: &[u32], rules: &[AuthorizedBitMask]) -> Vec<bool> {
        if values.is_empty() {
            return Vec::new();
        }
        if rules.is_empty() {
            return vec![true; values.len()];
        }

        let gpu_rules: Vec<ExactRuleGpu> = rules
            .iter()
            .map(|rule| ExactRuleGpu { mask: rule.mask, authorized: rule.authorized })
            .collect();

        let raw = self.dispatch(
            &self.exact_pipeline,
            values,
            bytemuck::cast_slice(&gpu_rules),
            std::mem::size_of::<ExactRuleGpu>(),
        );
        raw.into_iter().map(|b| b != 0).collect()
    }

    /// Evaluates masked range rules on the GPU.
    pub fn authorize_range(&self, values: &[u32], rules: &[MaskedRangeRule]) -> Vec<bool> {
        if values.is_empty() {
            return Vec::new();
        }
        if rules.is_empty() {
            return vec![true; values.len()];
        }

        let gpu_rules: Vec<RangeRuleGpu> = rules
            .iter()
            .map(|rule| RangeRuleGpu { mask: rule.mask, start: rule.start, end: rule.end })
            .collect();

        let raw = self.dispatch(
            &self.range_pipeline,
            values,
            bytemuck::cast_slice(&gpu_rules),
            std::mem::size_of::<RangeRuleGpu>(),
        );
        raw.into_iter().map(|b| b != 0).collect()
    }

    fn dispatch(
        &self,
        pipeline: &wgpu::ComputePipeline,
        values: &[u32],
        rules_bytes: &[u8],
        rule_stride: usize,
    ) -> Vec<u32> {
        let rule_count = rules_bytes.len() / rule_stride;
        let params = Params {
            value_count: values.len() as u32,
            rule_count: rule_count as u32,
            _pad: [0, 0],
        };

        let params_buffer =
            self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("params"),
                contents: bytemuck::bytes_of(&params),
                usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            });

        let values_buffer = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("values"),
            contents: bytemuck::cast_slice(values),
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        });

        let rules_buffer = self.device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("rules"),
            contents: rules_bytes,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        });

        let results_buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("results"),
            size: (values.len() * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        });

        let readback_buffer = self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("readback"),
            size: (values.len() * std::mem::size_of::<u32>()) as u64,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let bind_group_layout = pipeline.get_bind_group_layout(0);
        let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("authorize_bind_group"),
            layout: &bind_group_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: params_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: values_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: rules_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: results_buffer.as_entire_binding(),
                },
            ],
        });

        let mut encoder =
            self.device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("authorize_encoder"),
            });

        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("authorize_pass"),
                timestamp_writes: None,
            });
            pass.set_pipeline(pipeline);
            pass.set_bind_group(0, &bind_group, &[]);
            let workgroups = values.len().div_ceil(WORKGROUP_SIZE as usize) as u32;
            pass.dispatch_workgroups(workgroups, 1, 1);
        }

        encoder.copy_buffer_to_buffer(
            &results_buffer,
            0,
            &readback_buffer,
            0,
            readback_buffer.size(),
        );

        self.queue.submit(Some(encoder.finish()));

        let buffer_slice = readback_buffer.slice(..);
        let (sender, receiver) = std::sync::mpsc::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |result| {
            let _ = sender.send(result);
        });
        self.device.poll(wgpu::Maintain::Wait);
        receiver
            .recv()
            .expect("map_async callback dropped")
            .expect("failed to map readback buffer");

        let data = buffer_slice.get_mapped_range();
        let results: Vec<u32> = bytemuck::cast_slice(&data).to_vec();
        drop(data);
        readback_buffer.unmap();
        results
    }
}

fn build_pipeline(device: &wgpu::Device, source: &str, label: &str) -> wgpu::ComputePipeline {
    let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some(label),
        source: wgpu::ShaderSource::Wgsl(source.into()),
    });

    let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("authorize_layout"),
        entries: &[
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Uniform,
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 2,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 3,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("authorize_pipeline_layout"),
        bind_group_layouts: &[&bind_group_layout],
        push_constant_ranges: &[],
    });

    device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some(label),
        layout: Some(&pipeline_layout),
        module: &module,
        entry_point: Some("main"),
        compilation_options: Default::default(),
        cache: None,
    })
}

