use {
    criterion::{criterion_group, criterion_main, Criterion},
    solana_zk_sdk::{
        encryption::{
            elgamal::ElGamalKeypair,
            grouped_elgamal::GroupedElGamal,
            pedersen::{Pedersen, PedersenOpening},
        },
        zk_elgamal_proof_program::{
            build_batched_grouped_ciphertext_2_handles_validity_proof_data,
            build_batched_grouped_ciphertext_3_handles_validity_proof_data,
            build_ciphertext_ciphertext_equality_proof_data,
            build_ciphertext_commitment_equality_proof_data,
            build_grouped_ciphertext_2_handles_validity_proof_data,
            build_grouped_ciphertext_3_handles_validity_proof_data,
            build_percentage_with_cap_proof_data, build_pubkey_validity_proof_data,
            build_zero_ciphertext_proof_data, VerifyZkProof,
        },
    },
    std::hint::black_box,
};

// Generation is timed through the public builders, so it includes their input consistency checks.
fn bench_proof<T: VerifyZkProof>(c: &mut Criterion, name: &str, build: impl Fn() -> T) {
    let mut group = c.benchmark_group("sigma_proof_generation");
    group.bench_function(name, |b| {
        b.iter(&build);
    });
    group.finish();

    let proof = build();

    let mut group = c.benchmark_group("sigma_proof_verification");
    group.bench_function(name, |b| {
        b.iter(|| black_box(&proof).verify_proof().unwrap());
    });
    group.finish();
}

fn bench_pubkey_validity(c: &mut Criterion) {
    let keypair = ElGamalKeypair::new_rand();

    bench_proof(c, "pubkey_validity", || {
        build_pubkey_validity_proof_data(&keypair).unwrap()
    });
}

fn bench_zero_ciphertext(c: &mut Criterion) {
    let keypair = ElGamalKeypair::new_rand();
    let ciphertext = keypair.pubkey().encrypt(0_u64);

    bench_proof(c, "zero_ciphertext", || {
        build_zero_ciphertext_proof_data(&keypair, &ciphertext).unwrap()
    });
}

fn bench_ciphertext_commitment_equality(c: &mut Criterion) {
    let keypair = ElGamalKeypair::new_rand();
    let amount: u64 = 55;
    let ciphertext = keypair.pubkey().encrypt(amount);
    let (commitment, opening) = Pedersen::new(amount);

    bench_proof(c, "ciphertext_commitment_equality", || {
        build_ciphertext_commitment_equality_proof_data(
            &keypair,
            &ciphertext,
            &commitment,
            &opening,
            amount,
        )
        .unwrap()
    });
}

fn bench_ciphertext_ciphertext_equality(c: &mut Criterion) {
    let first_keypair = ElGamalKeypair::new_rand();
    let second_keypair = ElGamalKeypair::new_rand();

    let amount: u64 = 55;
    let first_ciphertext = first_keypair.pubkey().encrypt(amount);

    let second_opening = PedersenOpening::new_rand();
    let second_ciphertext = second_keypair
        .pubkey()
        .encrypt_with(amount, &second_opening);

    bench_proof(c, "ciphertext_ciphertext_equality", || {
        build_ciphertext_ciphertext_equality_proof_data(
            &first_keypair,
            second_keypair.pubkey(),
            &first_ciphertext,
            &second_ciphertext,
            &second_opening,
            amount,
        )
        .unwrap()
    });
}

fn bench_grouped_ciphertext_2_handles_validity(c: &mut Criterion) {
    let first_keypair = ElGamalKeypair::new_rand();
    let first_pubkey = first_keypair.pubkey();

    let second_keypair = ElGamalKeypair::new_rand();
    let second_pubkey = second_keypair.pubkey();

    let amount: u64 = 55;
    let opening = PedersenOpening::new_rand();
    let grouped_ciphertext =
        GroupedElGamal::encrypt_with([first_pubkey, second_pubkey], amount, &opening);

    bench_proof(c, "grouped_ciphertext_2_handles_validity", || {
        build_grouped_ciphertext_2_handles_validity_proof_data(
            first_pubkey,
            second_pubkey,
            &grouped_ciphertext,
            amount,
            &opening,
        )
        .unwrap()
    });
}

fn bench_grouped_ciphertext_3_handles_validity(c: &mut Criterion) {
    let first_keypair = ElGamalKeypair::new_rand();
    let first_pubkey = first_keypair.pubkey();

    let second_keypair = ElGamalKeypair::new_rand();
    let second_pubkey = second_keypair.pubkey();

    let third_keypair = ElGamalKeypair::new_rand();
    let third_pubkey = third_keypair.pubkey();

    let amount: u64 = 55;
    let opening = PedersenOpening::new_rand();
    let grouped_ciphertext = GroupedElGamal::encrypt_with(
        [first_pubkey, second_pubkey, third_pubkey],
        amount,
        &opening,
    );

    bench_proof(c, "grouped_ciphertext_3_handles_validity", || {
        build_grouped_ciphertext_3_handles_validity_proof_data(
            first_pubkey,
            second_pubkey,
            third_pubkey,
            &grouped_ciphertext,
            amount,
            &opening,
        )
        .unwrap()
    });
}

fn bench_batched_grouped_ciphertext_2_handles_validity(c: &mut Criterion) {
    let first_keypair = ElGamalKeypair::new_rand();
    let first_pubkey = first_keypair.pubkey();

    let second_keypair = ElGamalKeypair::new_rand();
    let second_pubkey = second_keypair.pubkey();

    let amount_lo: u64 = 11;
    let amount_hi: u64 = 22;

    let opening_lo = PedersenOpening::new_rand();
    let opening_hi = PedersenOpening::new_rand();

    let grouped_ciphertext_lo =
        GroupedElGamal::encrypt_with([first_pubkey, second_pubkey], amount_lo, &opening_lo);
    let grouped_ciphertext_hi =
        GroupedElGamal::encrypt_with([first_pubkey, second_pubkey], amount_hi, &opening_hi);

    bench_proof(c, "batched_grouped_ciphertext_2_handles_validity", || {
        build_batched_grouped_ciphertext_2_handles_validity_proof_data(
            first_pubkey,
            second_pubkey,
            &grouped_ciphertext_lo,
            &grouped_ciphertext_hi,
            amount_lo,
            amount_hi,
            &opening_lo,
            &opening_hi,
        )
        .unwrap()
    });
}

fn bench_batched_grouped_ciphertext_3_handles_validity(c: &mut Criterion) {
    let first_keypair = ElGamalKeypair::new_rand();
    let first_pubkey = first_keypair.pubkey();

    let second_keypair = ElGamalKeypair::new_rand();
    let second_pubkey = second_keypair.pubkey();

    let third_keypair = ElGamalKeypair::new_rand();
    let third_pubkey = third_keypair.pubkey();

    let amount_lo: u64 = 11;
    let amount_hi: u64 = 22;

    let opening_lo = PedersenOpening::new_rand();
    let opening_hi = PedersenOpening::new_rand();

    let grouped_ciphertext_lo = GroupedElGamal::encrypt_with(
        [first_pubkey, second_pubkey, third_pubkey],
        amount_lo,
        &opening_lo,
    );
    let grouped_ciphertext_hi = GroupedElGamal::encrypt_with(
        [first_pubkey, second_pubkey, third_pubkey],
        amount_hi,
        &opening_hi,
    );

    bench_proof(c, "batched_grouped_ciphertext_3_handles_validity", || {
        build_batched_grouped_ciphertext_3_handles_validity_proof_data(
            first_pubkey,
            second_pubkey,
            third_pubkey,
            &grouped_ciphertext_lo,
            &grouped_ciphertext_hi,
            amount_lo,
            amount_hi,
            &opening_lo,
            &opening_hi,
        )
        .unwrap()
    });
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "Commitment and opening operations use modular curve arithmetic."
)]
fn bench_percentage_with_cap(c: &mut Criterion) {
    let base_amount: u64 = 1;
    let max_value: u64 = 3;

    let percentage_rate: u64 = 400;
    let percentage_amount: u64 = 1;
    let delta_amount: u64 = 9600;

    let (base_commitment, base_opening) = Pedersen::new(base_amount);
    let (percentage_commitment, percentage_opening) = Pedersen::new(percentage_amount);

    let delta_commitment = percentage_commitment * 10_000_u64 - base_commitment * percentage_rate;
    let delta_opening = &percentage_opening * 10_000_u64 - &base_opening * percentage_rate;

    let (claimed_commitment, claimed_opening) = Pedersen::new(delta_amount);

    bench_proof(c, "percentage_with_cap", || {
        build_percentage_with_cap_proof_data(
            &percentage_commitment,
            &percentage_opening,
            percentage_amount,
            &delta_commitment,
            &delta_opening,
            delta_amount,
            &claimed_commitment,
            &claimed_opening,
            max_value,
        )
        .unwrap()
    });
}

criterion_group!(
    benches,
    bench_pubkey_validity,
    bench_zero_ciphertext,
    bench_ciphertext_commitment_equality,
    bench_ciphertext_ciphertext_equality,
    bench_grouped_ciphertext_2_handles_validity,
    bench_grouped_ciphertext_3_handles_validity,
    bench_batched_grouped_ciphertext_2_handles_validity,
    bench_batched_grouped_ciphertext_3_handles_validity,
    bench_percentage_with_cap,
);
criterion_main!(benches);
