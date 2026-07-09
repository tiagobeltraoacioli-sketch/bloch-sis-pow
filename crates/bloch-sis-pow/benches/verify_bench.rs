// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Verification benchmark.
//
// Run with:
//   cargo bench --bench verify_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use bloch_sis_pow::difficulty::Target;
use bloch_sis_pow::expand::expand_matrix_and_target;
use bloch_sis_pow::field::infinity_norm;
use bloch_sis_pow::matrix::residual_centered;
use bloch_sis_pow::params::{B, N};
use bloch_sis_pow::solver::derive_pow_seed;
use bloch_sis_pow::verify::compute_aux_hash;

fn bench_verify_components(c: &mut Criterion) {
    let header = b"bench-verify-header";
    let nonce = 12345u64;
    let mut s = [0i32; N];
    for i in 0..N {
        s[i] = (i as i32 % (2 * B + 1)) - B;
    }

    c.bench_function("verify::seed_derive", |b| {
        b.iter(|| {
            let _ = derive_pow_seed(black_box(header), black_box(nonce));
        })
    });

    let seed = derive_pow_seed(header, nonce);
    c.bench_function("verify::expand_matrix_and_target", |b| {
        b.iter(|| {
            let _ = expand_matrix_and_target(black_box(&seed));
        })
    });

    let (a, t) = expand_matrix_and_target(&seed);
    c.bench_function("verify::residual_and_norm", |b| {
        b.iter(|| {
            let r = residual_centered(black_box(&a), black_box(&s), black_box(&t));
            let _ = infinity_norm(&r);
        })
    });

    c.bench_function("verify::aux_hash", |b| {
        b.iter(|| {
            let _ = compute_aux_hash(black_box(header), black_box(nonce), black_box(&s));
        })
    });
}

fn bench_verify_end_to_end(c: &mut Criterion) {
    use bloch_sis_pow::verify::verify;

    let header = b"bench-verify-e2e";
    let nonce = 7777u64;
    let s = [0i32; N];
    let target = Target::MAX; // verify will fail on residual, but we time the full call
    c.bench_function("verify::end_to_end_call", |b| {
        b.iter(|| {
            let _ = verify(black_box(header), black_box(nonce), black_box(&s), black_box(&target));
        })
    });
}

criterion_group!(benches, bench_verify_components, bench_verify_end_to_end);
criterion_main!(benches);
