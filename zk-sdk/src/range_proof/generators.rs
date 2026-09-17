//! Manages the generation of orthogonal public generators for Bulletproofs.
//!
//! The `RangeProofGens` struct is the main entry point for creating and managing
//! the generator points **G** and **H**. These are the public parameters required
//! by the Bulletproofs protocol.
//!
//! A key security feature of Bulletproofs is that these generators are created
//! deterministically from a seed using a hash function (in this case, SHAKE256).
//! This avoids the need for a trusted setup ceremony.

use {
    crate::range_proof::errors::RangeProofGeneratorError,
    curve25519_dalek::ristretto::RistrettoPoint,
    shake::{
        digest::{ExtendableOutput, Update, XofReader},
        Shake256, Shake256Reader,
    },
    std::sync::LazyLock,
};

/// The maximum number of generators that can be created.
const MAX_GENERATOR_LENGTH: usize = u32::MAX as usize;

pub(super) const CACHED_GENERATOR_LENGTH: usize = 256;

// Smaller proofs use prefixes of this set.
pub(super) static CACHED_GENERATORS: LazyLock<RangeProofGens> =
    LazyLock::new(|| RangeProofGens::new(CACHED_GENERATOR_LENGTH).unwrap());

/// A factory for creating an effectively infinite stream of generator points.
///
/// `GeneratorsChain` is an iterator that produces `RistrettoPoint`s by hashing
/// a domain-separated label. It uses SHAKE256 to produce a stream of bytes
/// which are then mapped to points.
struct GeneratorsChain {
    reader: Shake256Reader,
}

impl GeneratorsChain {
    /// Creates a new chain of generators, uniquely determined by the `label`.
    ///
    /// The protocol uses different labels (e.g., `b"G"`, `b"H"`) to ensure
    /// the generated sets of points are independent.
    fn new(label: &[u8]) -> Self {
        let mut shake = Shake256::default();
        shake.update(b"GeneratorsChain");
        shake.update(label);

        GeneratorsChain {
            reader: shake.finalize_xof(),
        }
    }

    /// Advances the reader `n` positions by squeezing and discarding the bytes.
    ///
    /// This is used to efficiently skip generators that have already been created
    /// when extending the capacity of `RangeProofGens`.
    fn fast_forward(mut self, n: usize) -> Self {
        for _ in 0..n {
            let mut buf = [0u8; 64];
            self.reader.read(&mut buf);
        }
        self
    }
}

impl Default for GeneratorsChain {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl Iterator for GeneratorsChain {
    type Item = RistrettoPoint;

    fn next(&mut self) -> Option<Self::Item> {
        let mut uniform_bytes = [0u8; 64];
        self.reader.read(&mut uniform_bytes);

        Some(RistrettoPoint::from_uniform_bytes(&uniform_bytes))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
}

/// A container for the precomputed generator points used in a range proof.
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct RangeProofGens {
    /// The number of **G** and **H** generators available.
    pub gens_capacity: usize,
    /// Precomputed **G** generators for the vector Pedersen commitment.
    G_vec: Vec<RistrettoPoint>,
    /// Precomputed **H** generators for the vector Pedersen commitment.
    H_vec: Vec<RistrettoPoint>,
}

impl RangeProofGens {
    /// Creates a new set of generators with the specified capacity.
    pub fn new(gens_capacity: usize) -> Result<Self, RangeProofGeneratorError> {
        let mut gens = RangeProofGens {
            gens_capacity: 0,
            G_vec: Vec::new(),
            H_vec: Vec::new(),
        };
        gens.increase_capacity(gens_capacity)?;
        Ok(gens)
    }

    /// Increases the generators' capacity to `new_capacity`.
    /// If `new_capacity` is less than or equal to the current capacity, this does nothing.
    pub fn increase_capacity(
        &mut self,
        new_capacity: usize,
    ) -> Result<(), RangeProofGeneratorError> {
        if self.gens_capacity >= new_capacity {
            return Ok(());
        }

        if new_capacity > MAX_GENERATOR_LENGTH {
            return Err(RangeProofGeneratorError::MaximumGeneratorLengthExceeded);
        }

        // To extend the generators, we fast-forward the chain to the current capacity
        // and then take the next `new_capacity - self.gens_capacity` points.
        self.G_vec.extend(
            &mut GeneratorsChain::new(b"G")
                .fast_forward(self.gens_capacity)
                .take(new_capacity - self.gens_capacity),
        );

        self.H_vec.extend(
            &mut GeneratorsChain::new(b"H")
                .fast_forward(self.gens_capacity)
                .take(new_capacity - self.gens_capacity),
        );

        self.gens_capacity = new_capacity;
        Ok(())
    }

    /// Returns an iterator over the first `n` **G** generators.
    #[allow(non_snake_case)]
    pub(crate) fn G(&self, n: usize) -> impl Iterator<Item = &RistrettoPoint> {
        GensIter {
            array: &self.G_vec,
            n,
            gen_idx: 0,
        }
    }

    /// Returns an iterator over the first `n` **H** generators.
    #[allow(non_snake_case)]
    pub(crate) fn H(&self, n: usize) -> impl Iterator<Item = &RistrettoPoint> {
        GensIter {
            array: &self.H_vec,
            n,
            gen_idx: 0,
        }
    }
}

/// An iterator that provides a view into the first `n` elements of a generator vector.
struct GensIter<'a> {
    array: &'a Vec<RistrettoPoint>,
    n: usize,
    gen_idx: usize,
}

impl<'a> Iterator for GensIter<'a> {
    type Item = &'a RistrettoPoint;

    fn next(&mut self) -> Option<Self::Item> {
        if self.gen_idx >= self.n {
            None
        } else {
            let cur_gen = self.gen_idx;
            self.gen_idx += 1;
            Some(&self.array[cur_gen])
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.n - self.gen_idx;
        (size, Some(size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_generators_match_uncached() {
        let cached = &*CACHED_GENERATORS;
        for n in [0, 1, 2, 3, 8, 32, 63, 64, 65, 127, 128, 129, 255, 256] {
            let uncached = RangeProofGens::new(n).unwrap();
            assert!(cached.G(n).eq(uncached.G(n)));
            assert!(cached.H(n).eq(uncached.H(n)));
            assert!(cached
                .G(n)
                .chain(cached.H(n))
                .map(|p| p.compress())
                .eq(uncached.G(n).chain(uncached.H(n)).map(|p| p.compress())));
        }
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn oversized_generators_are_rejected() {
        let n = MAX_GENERATOR_LENGTH + 1;
        assert_eq!(
            RangeProofGens::new(n).err(),
            Some(RangeProofGeneratorError::MaximumGeneratorLengthExceeded),
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn concurrent_access_shares_generators() {
        use std::{sync::Barrier, thread};

        let barrier = Barrier::new(9);
        thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|i| {
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        let n = [64, 128, 256][i % 3];
                        let gens = &*CACHED_GENERATORS;
                        assert!(gens.G(n).eq(RangeProofGens::new(n).unwrap().G(n)));
                        gens
                    })
                })
                .collect();
            barrier.wait();
            for handle in handles {
                assert!(std::ptr::eq(handle.join().unwrap(), &*CACHED_GENERATORS));
            }
        });
    }

    #[test]
    fn retained_cache_memory() {
        let gens = &*CACHED_GENERATORS;
        let heap_bytes =
            (gens.G_vec.capacity() + gens.H_vec.capacity()) * std::mem::size_of::<RistrettoPoint>();
        assert_eq!(gens.G_vec.capacity(), CACHED_GENERATOR_LENGTH);
        assert_eq!(gens.H_vec.capacity(), CACHED_GENERATOR_LENGTH);
        let static_bytes = std::mem::size_of_val(&CACHED_GENERATORS);
        let message =
            format!("generator cache: {heap_bytes} heap bytes + {static_bytes} static bytes");
        println!("{message}");
    }
}
