//! The discrete log implementation for the twisted ElGamal decryption.
//!
//! The implementation uses the baby-step giant-step method, which consists of a precomputation
//! step and an online step. The precomputation step involves computing a hash table of a number
//! of Ristretto points that is independent of a discrete log instance. The online phase computes
//! the final discrete log solution using the discrete log instance and the pre-computed hash
//! table. More details on the baby-step giant-step algorithm and the implementation can be found
//! in the [spl documentation](https://spl.solana.com).
//!
//! The hash table holds the points `x_lo * G` for the low 16 bits `x_lo` of a solution. The online
//! phase subtracts multiples of `2^16 * G` from the discrete log instance and looks each result up
//! in the table. The table is keyed by truncated points, so the online phase confirms each match
//! on the full point before it accepts it.
//!
//! The implementation is NOT intended to run in constant-time. There are some measures to prevent
//! straightforward timing attacks. For instance, it does not short-circuit the search when a
//! solution is found. However, the use of hash tables, batching, threads, and the confirmation of
//! truncated matches, whose number depends on the discrete log instance, make the implementation
//! inherently not constant-time. This may theoretically allow an adversary to gain information on
//! a discrete log solution depending on the execution time of the implementation.
//!

use {
    itertools::Itertools,
    serde::{Deserialize, Serialize},
    solana_ed25519::{
        constants::RISTRETTO_BASEPOINT_POINT as G,
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::{Identity, IsIdentity},
    },
    std::{collections::HashMap, num::NonZeroUsize, panic, thread},
    thiserror::Error,
};

const TWO16: u64 = 65536; // 2^16

/// Maximum number of threads permitted for discrete log computation
const MAX_THREAD: usize = 65536;

/// Number of bytes of a compressed Ristretto point that the precomputed table keeps as a key
const PRECOMPUTATION_KEY_LEN: usize = 4;

/// Offset of those bytes in the compressed point. The keys of the table have to be distinct, and
/// the first four bytes of its points are not.
const PRECOMPUTATION_KEY_OFFSET: usize = 4;

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum DiscreteLogError {
    #[error("discrete log number of threads not power-of-two")]
    DiscreteLogThreads,
    #[error("discrete log batch size too large")]
    DiscreteLogBatchSize,
}

/// Type that captures a discrete log challenge.
///
/// The goal of discrete log is to find x such that `x * generator = target`.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, Eq, PartialEq)]
pub struct DiscreteLog {
    /// Target point for discrete log
    pub target: RistrettoPoint,
    /// Number of threads used for discrete log computation
    num_threads: Option<NonZeroUsize>,
    /// Range bound for discrete log search derived from the max value to search for and
    /// `num_threads`
    range_bound: NonZeroUsize,
    /// Ristretto point representing each step of the discrete log search
    step_point: RistrettoPoint,
    /// Ristretto point compression batch size
    compression_batch_size: NonZeroUsize,
}

#[derive(Serialize, Deserialize, Default)]
pub struct DecodePrecomputation(HashMap<[u8; PRECOMPUTATION_KEY_LEN], u16>);

/// Truncates a compressed Ristretto point to its key in the precomputed table
fn precomputation_key(point: &CompressedRistretto) -> [u8; PRECOMPUTATION_KEY_LEN] {
    point.as_bytes()[PRECOMPUTATION_KEY_OFFSET..PRECOMPUTATION_KEY_OFFSET + PRECOMPUTATION_KEY_LEN]
        .try_into()
        .unwrap()
}

/// Builds a `HashMap` of `2^16` elements
#[allow(dead_code)]
fn decode_u32_precomputation() -> DecodePrecomputation {
    let mut hashmap = HashMap::new();

    // the online search compresses the doubles of its points, so the points are doubled here too
    let identity = RistrettoPoint::identity(); // 0 * G
    let generator = Scalar::from(2_u64) * G; // 2 * G

    // iterator for 2*0G , 2*1G, 2*2G, ...
    let ristretto_iter = RistrettoIterator::new((identity, 0), (generator, 1));
    for (point, x_lo) in ristretto_iter.take(TWO16 as usize) {
        let key = precomputation_key(&point.compress());
        hashmap.insert(key, x_lo as u16);
    }

    DecodePrecomputation(hashmap)
}

static DECODE_PRECOMPUTATION_FOR_G_BYTES: &[u8] =
    include_bytes!("decode_u32_precomputation_for_G.bincode");

/// Pre-computed `HashMap` needed for decryption. The `HashMap` is independent of (works for) any key.
pub static DECODE_PRECOMPUTATION_FOR_G: std::sync::LazyLock<DecodePrecomputation> =
    std::sync::LazyLock::new(|| {
        DecodePrecomputation(
            wincode::deserialize(DECODE_PRECOMPUTATION_FOR_G_BYTES)
                .expect("embedded discrete log precomputation is malformed"),
        )
    });

/// Giant step `2^16 * G` of the discrete log search
static GIANT_STEP_FOR_G: std::sync::LazyLock<RistrettoPoint> =
    std::sync::LazyLock::new(|| Scalar::from(TWO16) * G);

/// Solves the discrete log instance using a 16/16 bit offline/online split
impl DiscreteLog {
    /// Discrete log instance constructor for a fixed generator.
    ///
    /// Default number of threads set to 1.
    /// Default compression batch size set to 256.
    pub fn new_for_g(target: RistrettoPoint) -> Self {
        Self {
            target,
            num_threads: None,
            range_bound: (TWO16 as usize).try_into().unwrap(),
            step_point: *GIANT_STEP_FOR_G,
            // the gain from sharing an inversion flattens out past 256, and a batch of 4096
            // measured slower than one of 32
            compression_batch_size: 256.try_into().unwrap(),
        }
    }

    /// Adjusts number of threads in a discrete log instance.
    pub fn num_threads(&mut self, num_threads: NonZeroUsize) -> Result<(), DiscreteLogError> {
        // number of threads must be a positive power-of-two integer
        if !num_threads.is_power_of_two() || num_threads.get() > MAX_THREAD {
            return Err(DiscreteLogError::DiscreteLogThreads);
        }

        self.num_threads = Some(num_threads);
        self.range_bound = (TWO16 as usize)
            .checked_div(num_threads.get())
            .and_then(|range_bound| range_bound.try_into().ok())
            .unwrap(); // `num_threads` cannot exceed `TWO16`, so `range_bound` always non-zero
        self.step_point = *GIANT_STEP_FOR_G * Scalar::from(num_threads.get() as u64);

        Ok(())
    }

    /// Adjusts inversion batch size in a discrete log instance.
    pub fn set_compression_batch_size(
        &mut self,
        compression_batch_size: NonZeroUsize,
    ) -> Result<(), DiscreteLogError> {
        if compression_batch_size.get() >= TWO16 as usize {
            return Err(DiscreteLogError::DiscreteLogBatchSize);
        }
        self.compression_batch_size = compression_batch_size;

        Ok(())
    }

    /// Solves the discrete log problem under the assumption that the solution
    /// is a positive 32-bit number.
    pub fn decode_u32(self) -> Option<u64> {
        #[allow(unused_variables)]
        if let Some(num_threads) = self.num_threads {
            // scoped threads are all joined before `scope` returns, so no worker outlives this call
            thread::scope(|scope| {
                let mut starting_point = self.target;
                let handles = (0..num_threads.get())
                    .map(|i| {
                        let ristretto_iterator = RistrettoIterator::new(
                            (starting_point, i as u64),
                            (-(&self.step_point), num_threads.get() as u64),
                        );

                        let handle = scope.spawn(move || {
                            Self::decode_range(
                                ristretto_iterator,
                                self.range_bound,
                                self.compression_batch_size,
                            )
                        });

                        starting_point -= *GIANT_STEP_FOR_G;
                        handle
                    })
                    .collect::<Vec<_>>();

                // a worker panic is re-raised here, as it would be without threads
                handles
                    .into_iter()
                    .map(|h| match h.join() {
                        Ok(decoded) => decoded,
                        Err(payload) => panic::resume_unwind(payload),
                    })
                    .fold(None, Option::or)
            })
        } else {
            let ristretto_iterator =
                RistrettoIterator::new((self.target, 0_u64), (-(&self.step_point), 1u64));

            Self::decode_range(
                ristretto_iterator,
                self.range_bound,
                self.compression_batch_size,
            )
        }
    }

    fn decode_range(
        ristretto_iterator: RistrettoIterator,
        range_bound: NonZeroUsize,
        compression_batch_size: NonZeroUsize,
    ) -> Option<u64> {
        let hashmap = &DECODE_PRECOMPUTATION_FOR_G;
        let mut decoded = None;

        for batch in &ristretto_iterator
            .take(range_bound.get())
            .chunks(compression_batch_size.get())
        {
            // batch compression currently errors if any point in the batch is the identity point
            let (batch_points, batch_indices): (Vec<_>, Vec<_>) = batch
                .filter(|(point, index)| {
                    if point.is_identity() {
                        decoded = Some(TWO16 * index);
                        return false;
                    }
                    true
                })
                .unzip();

            let batch_compressed = RistrettoPoint::double_and_compress_batch(&batch_points);

            for ((point, compressed), x_hi) in batch_points
                .iter()
                .zip(batch_compressed.iter())
                .zip(batch_indices.iter())
            {
                let key = precomputation_key(compressed);
                if let Some(&x_lo) = hashmap.0.get(&key) {
                    // the key is truncated, so the match is confirmed on the point itself
                    if Scalar::from(x_lo as u64) * G == *point {
                        decoded = Some(x_lo as u64 + TWO16 * x_hi);
                    }
                }
            }
        }

        decoded
    }
}

/// Hashable Ristretto iterator.
///
/// Given an initial point X and a stepping point P, the iterator iterates through
/// `X + 0*P, X + 1*P, X + 2*P, X + 3*P, ...`
struct RistrettoIterator {
    pub current: (RistrettoPoint, u64),
    pub step: (RistrettoPoint, u64),
}

impl RistrettoIterator {
    fn new(current: (RistrettoPoint, u64), step: (RistrettoPoint, u64)) -> Self {
        RistrettoIterator { current, step }
    }
}

impl Iterator for RistrettoIterator {
    type Item = (RistrettoPoint, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let r = self.current;
        self.current = (self.current.0 + self.step.0, self.current.1 + self.step.1);
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, std::time::Instant};

    #[test]
    #[allow(non_snake_case)]
    fn test_serialize_decode_u32_precomputation_for_G() {
        let decode_u32_precomputation_for_G = decode_u32_precomputation();

        if decode_u32_precomputation_for_G.0 != DECODE_PRECOMPUTATION_FOR_G.0 {
            use std::{fs::File, io::Write, path::PathBuf};
            let mut f = File::create(PathBuf::from(
                "src/encryption/decode_u32_precomputation_for_G.bincode",
            ))
            .unwrap();
            f.write_all(&wincode::serialize(&decode_u32_precomputation_for_G.0).unwrap())
                .unwrap();
            panic!("Rebuild and run this test again");
        }
    }

    #[test]
    fn test_wincode_decodes_embedded_precomputation() {
        let decoded: HashMap<[u8; PRECOMPUTATION_KEY_LEN], u16> =
            wincode::deserialize(DECODE_PRECOMPUTATION_FOR_G_BYTES).unwrap();
        // no two of the truncated keys are equal
        assert_eq!(decoded.len(), TWO16 as usize);
        assert_eq!(decoded, decode_u32_precomputation().0);

        let bincode_decoded: DecodePrecomputation =
            bincode::deserialize(DECODE_PRECOMPUTATION_FOR_G_BYTES).unwrap();
        assert_eq!(decoded, bincode_decoded.0);
    }

    #[test]
    fn test_wincode_serialize_matches_embedded_layout() {
        let encoded = wincode::serialize(&DECODE_PRECOMPUTATION_FOR_G.0).unwrap();
        assert_eq!(encoded.len(), DECODE_PRECOMPUTATION_FOR_G_BYTES.len());

        let decoded: HashMap<[u8; PRECOMPUTATION_KEY_LEN], u16> =
            wincode::deserialize(&encoded).unwrap();
        assert_eq!(decoded, DECODE_PRECOMPUTATION_FOR_G.0);
    }

    #[test]
    fn test_decode_correctness() {
        // general case
        let amount: u64 = 4294967295;

        let instance = DiscreteLog::new_for_g(Scalar::from(amount) * G);

        // Very informal measurements for now
        let start_computation = Instant::now();
        let decoded = instance.decode_u32();
        let computation_secs = start_computation.elapsed().as_secs_f64();

        assert_eq!(amount, decoded.unwrap());

        println!("single thread discrete log computation secs: {computation_secs:?} sec");

        // multiples of 2^16 are found when the search reaches the identity, not through the table
        for amount in [0, 1 << 16, 0xffff_0000_u64] {
            let instance = DiscreteLog::new_for_g(Scalar::from(amount) * G);

            let decoded = instance.decode_u32();
            assert_eq!(amount, decoded.unwrap());
        }
    }

    /// Counts the points in the search for `target` that match a truncated key of the table
    fn count_truncated_key_matches(target: RistrettoPoint) -> usize {
        let points = RistrettoIterator::new((target, 0), (-*GIANT_STEP_FOR_G, 1))
            .take(TWO16 as usize)
            .map(|(point, _)| point)
            .collect::<Vec<_>>();

        RistrettoPoint::double_and_compress_batch(&points)
            .iter()
            .filter(|compressed| {
                let key = precomputation_key(compressed);
                DECODE_PRECOMPUTATION_FOR_G.0.contains_key(&key)
            })
            .count()
    }

    #[test]
    fn test_decode_truncated_key_matches() {
        // the search for each of these amounts meets points that match a truncated key of the
        // table without being a solution

        // the matches come after the solution, which is found on the first step
        let amount: u64 = 1;
        let target = Scalar::from(amount) * G;
        assert!(count_truncated_key_matches(target) > 1);

        let instance = DiscreteLog::new_for_g(target);

        let decoded = instance.decode_u32();
        assert_eq!(amount, decoded.unwrap());

        // there is no solution in the 32-bit range
        let amount: u64 = (1_u64 << 32) + 1;
        let target = Scalar::from(amount) * G;
        assert!(count_truncated_key_matches(target) > 0);

        let instance = DiscreteLog::new_for_g(target);

        let decoded = instance.decode_u32();
        assert!(decoded.is_none());
    }

    #[test]
    fn test_decode_correctness_threaded() {
        // general case
        let amount: u64 = 55;

        let mut instance = DiscreteLog::new_for_g(Scalar::from(amount) * G);
        instance.num_threads(4.try_into().unwrap()).unwrap();

        // Very informal measurements for now
        let start_computation = Instant::now();
        let decoded = instance.decode_u32();
        let computation_secs = start_computation.elapsed().as_secs_f64();

        assert_eq!(amount, decoded.unwrap());

        println!("4 thread discrete log computation: {computation_secs:?} sec");

        // each of the 4 workers finds one amount on its first step, where the point is the
        // identity, and one amount on its last step, through the table lookup
        for amount in (0..4_u64).flat_map(|i| [i << 16, u64::from(u32::MAX) - (i << 16)]) {
            let mut instance = DiscreteLog::new_for_g(Scalar::from(amount) * G);
            instance.num_threads(4.try_into().unwrap()).unwrap();

            let decoded = instance.decode_u32();
            assert_eq!(amount, decoded.unwrap());
        }
    }
}
