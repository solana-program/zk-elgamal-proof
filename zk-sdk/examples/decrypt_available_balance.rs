//! Recovers a confidential-transfer available balance from the ElGamal secret key alone.
//!
//! Token-2022 stores two views of the same available balance: `available_balance`, a twisted
//! ElGamal ciphertext the program updates homomorphically, and `decryptable_available_balance`,
//! an AES ciphertext the owner rewrites on every operation. Clients normally read the AES view
//! because it decrypts in constant time. A custodian whose key management system only holds the
//! ElGamal key has to go through `available_balance` instead, which means solving a discrete log.
//!
//! This example measures what that costs and where it stops working. Run with:
//!
//! ```text
//! cargo run --release --example decrypt_available_balance
//! ```

use {
    solana_zk_sdk::encryption::elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalSecretKey},
    std::{num::NonZeroUsize, time::Instant},
};

const TWO32: u64 = 1 << 32;

/// Rebuilds an `available_balance` the way the program does: deposits arrive as whole ciphertexts
/// applied from the pending balance, withdrawals and transfers subtract a cleartext amount from
/// the commitment while leaving the decrypt handle alone.
fn simulate_available_balance(
    keypair: &ElGamalKeypair,
    deposits: &[u64],
    withdrawals: &[u64],
) -> ElGamalCiphertext {
    let mut balance = keypair.pubkey().encrypt_u64(0);
    for amount in deposits {
        balance = balance + keypair.pubkey().encrypt_u64(*amount);
    }
    for amount in withdrawals {
        balance = balance.subtract_amount(*amount);
    }
    balance
}

fn decrypt_timed(
    ciphertext: &ElGamalCiphertext,
    secret: &ElGamalSecretKey,
    threads: Option<usize>,
) -> (Option<u64>, f64) {
    let start = Instant::now();
    let decoded = match threads {
        Some(threads) => {
            let mut instance = ciphertext.decrypt(secret);
            instance
                .num_threads(NonZeroUsize::new(threads).unwrap())
                .unwrap();
            instance.decode_u32()
        }
        None => ciphertext.decrypt_u32(secret),
    };
    (decoded, start.elapsed().as_secs_f64())
}

fn report(label: &str, expected: u64, decoded: Option<u64>, secs: f64) {
    match decoded {
        Some(amount) if amount == expected => println!("  {label:<38} {amount:>22}  {secs:>8.3}s"),
        Some(amount) => println!("  {label:<38} WRONG: got {amount}  {secs:>8.3}s"),
        None => println!("  {label:<38} {:>22}  {secs:>8.3}s", "none"),
    }
}

fn main() {
    let keypair = ElGamalKeypair::new(ElGamalSecretKey::from_seed(&[0u8; 32]).unwrap());
    let secret = keypair.secret();

    println!("Accumulated available balance, single thread");
    println!("  {:<38} {:>22}  {:>9}", "balance", "decrypted", "elapsed");
    for balance in [0_u64, 1, 1_000_000, 4_000_000_000, TWO32 - 1] {
        let ciphertext = simulate_available_balance(&keypair, &[balance + 7], &[7]);
        let (decoded, secs) = decrypt_timed(&ciphertext, secret, None);
        report(&format!("{balance}"), balance, decoded, secs);
    }

    println!("\nAt and past the 32-bit ceiling");
    for balance in [TWO32, TWO32 + 1, 1_000_000_000_000] {
        let ciphertext = simulate_available_balance(&keypair, &[balance], &[]);
        let (decoded, secs) = decrypt_timed(&ciphertext, secret, None);
        report(&format!("{balance}"), balance, decoded, secs);
    }

    println!("\nThread scaling at the 32-bit ceiling");
    let ciphertext = simulate_available_balance(&keypair, &[TWO32 - 1], &[]);
    for threads in [1_usize, 2, 4, 8] {
        let (decoded, secs) = decrypt_timed(&ciphertext, secret, Some(threads));
        report(&format!("{threads} thread(s)"), TWO32 - 1, decoded, secs);
    }

    println!("\nSubtracting a known lower bound first");
    let balance = 1_000_000_000_000_u64;
    let ciphertext = simulate_available_balance(&keypair, &[balance], &[]);
    for hint in [balance - 500, balance / 2] {
        let residual = ciphertext.subtract_amount(hint);
        let (decoded, secs) = decrypt_timed(&residual, secret, None);
        let label = format!("hint {hint} (delta {})", balance - hint);
        report(&label, balance - hint, decoded, secs);
    }
}
