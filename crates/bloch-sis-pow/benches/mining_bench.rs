// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Mining throughput benchmark.
//
// Run with:
//   cargo bench --bench mining_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

use bloch_sis_pow::difficulty::Target;
use bloch_sis_pow::expand::expand_matrix_and_target;
use bloch_sis_pow::field::infinity_norm;
use bloch_sis_pow::matrix::residual_centered;
use bloch_sis_pow::solver::derive_pow_seed;
use bloch_sis_pow::params::{B, BETA_I64, N};

fn bench_seed_expansion(c: &mut Criterion) {
    let header = b"bench-header-1234";
    c.bench_function("derive_pow_seed", |b| {
        b.iter(|| {
            let _ = derive_pow_seed(black_box(header), black_box(42));
        })
    });
}

fn bench_matrix_expansion(c: &mut Criterion) {
    let seed = [0u8; 64];
    c.bench_function("expand_matrix_and_target_512x256", |b| {
        b.iter(|| {
            let _ = expand_matrix_and_target(black_box(&seed));
        })
    });
}

fn bench_residual(c: &mut Criterion) {
    let header = b"bench-residual";
    let seed = derive_pow_seed(header, 0);
    let (a, t) = expand_matrix_and_target(&seed);

    let mut group = c.benchmark_group("residual_centered");
    for &density in &[0u32, N as u32 / 2, N as u32] {
        let mut s = [0i32; N];
        for i in 0..(density as usize) {
            s[i] = (i as i32 % (2 * B + 1)) - B;
        }
        group.bench_with_input(
            BenchmarkId::from_parameter(density),
            &density,
            |b, _| {
                b.iter(|| {
                    let r = residual_centered(black_box(&a), black_box(&s), black_box(&t));
                    let _ = infinity_norm(&r);
                });
            },
        );
    }
    group.finish();
}

fn bench_full_attempt(c: &mut Criterion) {
    // One full inner-loop iteration: sample s, expand-once already, residual,
    // norm check, aux hash. Approximates the cost per candidate-s.
    let header = b"bench-full";
    let seed = derive_pow_seed(header, 0);
    let (a, t) = expand_matrix_and_target(&seed);

    c.bench_function("inner_loop_per_candidate", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            // Cheap deterministic candidate generator
            counter = counter.wrapping_add(1);
            let mut s = [0i32; N];
            let mut state = counter.wrapping_mul(0x9E37_79B9_7F4A_7C15);
            for slot in s.iter_mut() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let v = ((state >> 33) % (2 * B as u64 + 1)) as i32;
                *slot = v - B;
            }

            let r = residual_centered(black_box(&a), black_box(&s), black_box(&t));
            let _norm = infinity_norm(&r);
            // Don't compute aux hash here — its cost is amortized by
            // the residual filter rejection (most candidates fail
            // residual before reaching aux).
        });
    });
}

criterion_group!(
    benches,
    bench_seed_expansion,
    bench_matrix_expansion,
    bench_residual,
    bench_full_attempt,
);
criterion_main!(benches);
