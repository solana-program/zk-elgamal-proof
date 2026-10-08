use {
    criterion::{criterion_group, criterion_main, Criterion},
    solana_zk_sdk::{
        encryption::pedersen::Pedersen,
        zk_elgamal_proof_program::{
            build_batched_range_proof_u128_data, build_batched_range_proof_u256_data,
            build_batched_range_proof_u64_data, VerifyZkProof,
        },
    },
    std::hint::black_box,
};

fn bench_range_proof_verification(c: &mut Criterion) {
    let amounts = [
        u64::MAX,
        u64::from(u16::MAX),
        u64::from(u32::MAX),
        0,
        1 << 31,
    ];
    let (commitments, openings): (Vec<_>, Vec<_>) =
        amounts.iter().map(|&amount| Pedersen::new(amount)).unzip();

    let proof_u64 = build_batched_range_proof_u64_data(
        commitments[..1].iter().collect(),
        amounts[..1].to_vec(),
        vec![64],
        openings[..1].iter().collect(),
    )
    .unwrap();
    let proof_u128 = build_batched_range_proof_u128_data(
        commitments[..4].iter().collect(),
        amounts[..4].to_vec(),
        vec![64, 16, 32, 16],
        openings[..4].iter().collect(),
    )
    .unwrap();
    let proof_u256 = build_batched_range_proof_u256_data(
        commitments.iter().collect(),
        amounts.to_vec(),
        vec![64, 64, 64, 32, 32],
        openings.iter().collect(),
    )
    .unwrap();

    let mut group = c.benchmark_group("range_proof_verification");
    group.bench_function("u64", |b| {
        b.iter(|| black_box(&proof_u64).verify_proof().unwrap());
    });
    group.bench_function("u128", |b| {
        b.iter(|| black_box(&proof_u128).verify_proof().unwrap());
    });
    group.bench_function("u256", |b| {
        b.iter(|| black_box(&proof_u256).verify_proof().unwrap());
    });
    group.finish();
}

criterion_group!(benches, bench_range_proof_verification);
criterion_main!(benches);
