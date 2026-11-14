use {
    criterion::{criterion_group, criterion_main, Criterion},
    solana_zk_sdk::encryption::{
        elgamal::ElGamalKeypair,
        pedersen::{Pedersen, PedersenOpening},
    },
    std::{hint::black_box, num::NonZeroUsize},
};

fn bench_pedersen_commitment(c: &mut Criterion) {
    let amount: u64 = 55;
    let opening = PedersenOpening::new_rand();

    c.bench_function("pedersen_commitment", |b| {
        b.iter(|| Pedersen::with(black_box(amount), &opening));
    });
}

fn bench_elgamal_encryption(c: &mut Criterion) {
    let keypair = ElGamalKeypair::new_rand();
    let amount: u64 = 55;
    let opening = PedersenOpening::new_rand();

    c.bench_function("elgamal_encryption", |b| {
        b.iter(|| keypair.pubkey().encrypt_with(black_box(amount), &opening));
    });
}

fn bench_elgamal_decryption(c: &mut Criterion) {
    let keypair = ElGamalKeypair::new_rand();
    let secret = keypair.secret();
    let ciphertext = keypair.pubkey().encrypt(u64::from(u32::MAX));
    let num_threads = NonZeroUsize::new(4).unwrap();

    let mut group = c.benchmark_group("elgamal_decryption");
    group.bench_function("u32_max", |b| {
        b.iter(|| secret.decrypt_u32(black_box(&ciphertext)).unwrap());
    });
    // `decode_u32` stops joining workers once one of them returns the result. `u32::MAX` is found
    // by the last worker joined, so every worker has finished before the call returns and none
    // overlaps with the next iteration.
    group.bench_function("u32_max_4_threads", |b| {
        b.iter(|| {
            let mut discrete_log = secret.decrypt(black_box(&ciphertext));
            discrete_log.num_threads(num_threads).unwrap();
            discrete_log.decode_u32().unwrap()
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_pedersen_commitment,
    bench_elgamal_encryption,
    bench_elgamal_decryption,
);
criterion_main!(benches);
