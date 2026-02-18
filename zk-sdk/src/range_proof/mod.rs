// Copyright (c) 2018 Chain, Inc.
// This code is licensed under the MIT license.

//! The Bulletproofs range-proof implementation over Curve25519 Ristretto points.
//!
//! The implementation is based on the dalek-cryptography bulletproofs
//! [implementation](https://github.com/dalek-cryptography/bulletproofs). Compared to the original
//! implementation by dalek-cryptography:
//! - This implementation focuses on the range proof implementation, while the dalek-cryptography
//!   crate additionally implements the general bulletproofs implementation for languages that can be
//!   represented by arithmetic circuits as well as MPC.
//! - This implementation implements a non-interactive range proof aggregation that is specified in
//!   the original Bulletproofs [paper](https://eprint.iacr.org/2017/1066) (Section 4.3).

#![allow(dead_code)]

use crate::{RISTRETTO_POINT_LEN, SCALAR_LEN};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::pedersen::{Pedersen, PedersenCommitment, PedersenOpening, G, H},
        range_proof::{
            errors::{RangeProofGenerationError, RangeProofVerificationError},
            generators::RangeProofGens,
            inner_product::InnerProductProof,
        },
        transcript::TranscriptProtocol,
    },
    core::iter,
    curve25519_dalek::traits::MultiscalarMul,
    curve25519_dalek::{
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::{IsIdentity, VartimeMultiscalarMul},
    },
    merlin::Transcript,
    rand::rngs::OsRng,
    subtle::{Choice, ConditionallySelectable},
    zeroize::Zeroize,
};

pub mod errors;
pub mod pod;

#[cfg(not(target_os = "solana"))]
pub mod generators;
#[cfg(not(target_os = "solana"))]
pub mod inner_product;
#[cfg(not(target_os = "solana"))]
pub mod util;

/// Byte length of a range proof excluding the inner-product proof component
pub const RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN: usize =
    5 * RISTRETTO_POINT_LEN + 2 * SCALAR_LEN;

/// Byte length of an inner-product proof for a vector of length 64
pub const INNER_PRODUCT_PROOF_U64_LEN: usize = 448;

/// Byte length of a range proof for an unsigned 64-bit number
pub const RANGE_PROOF_U64_LEN: usize =
    INNER_PRODUCT_PROOF_U64_LEN + RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN; // 672 bytes

/// Byte length of an inner-product proof for a vector of length 128
pub const INNER_PRODUCT_PROOF_U128_LEN: usize = 512;

/// Byte length of a range proof for an unsigned 128-bit number
pub const RANGE_PROOF_U128_LEN: usize =
    INNER_PRODUCT_PROOF_U128_LEN + RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN; // 736 bytes

/// Byte length of an inner-product proof for a vector of length 256
pub const INNER_PRODUCT_PROOF_U256_LEN: usize = 576;

/// Byte length of a range proof for an unsigned 256-bit number
pub const RANGE_PROOF_U256_LEN: usize =
    INNER_PRODUCT_PROOF_U256_LEN + RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN; // 800 bytes

/// A Bulletproofs range proof.
#[allow(non_snake_case)]
#[cfg(not(target_os = "solana"))]
#[derive(Clone)]
pub struct RangeProof {
    /// A commitment to the bit-vectors `a_L` and `a_R`.
    pub(crate) A: CompressedRistretto, // 32 bytes
    /// A commitment to the blinding vectors `s_L` and `s_R`.
    pub(crate) S: CompressedRistretto, // 32 bytes
    /// A commitment to the `t_1` coefficient of the polynomial `t(x)`.
    pub(crate) T_1: CompressedRistretto, // 32 bytes
    /// A commitment to the `t_2` coefficient of the polynomial `t(x)`.
    pub(crate) T_2: CompressedRistretto, // 32 bytes
    /// The evaluation of the polynomial `t(x)` at the challenge point `x`.
    pub(crate) t_x: Scalar, // 32 bytes
    /// The blinding factor for the `t_x` value.
    pub(crate) t_x_blinding: Scalar, // 32 bytes
    /// The blinding factor for the synthetic commitment to `l(x)` and `r(x)`.
    pub(crate) e_blinding: Scalar, // 32 bytes
    /// The inner product proof.
    pub(crate) ipp_proof: InnerProductProof, // 448 bytes for withdraw; 512 for transfer
}

#[allow(non_snake_case)]
#[cfg(not(target_os = "solana"))]
impl RangeProof {
    /// Creates an aggregated range proof for a set of values that are committed to a set of
    /// Pedersen commitments.
    ///
    /// This function implements the aggregated proof generation logic from Section 4.3
    /// of the Bulletproofs paper. It allows proving that multiple values are in their
    /// respective ranges, creating one proof that is much smaller than the sum of
    /// individual proofs.
    ///
    /// WARNING: This function does *not* hash the public statement for the proof. For security,
    /// the caller (the main protocol) must hash these public statement prior to invoking this
    /// constructor.
    ///
    /// # Panics
    /// This function will panic if the `openings` vector does not contain the same number
    /// of elements as the `amounts` and `bit_lengths` vectors.
    #[allow(clippy::many_single_char_names)]
    #[cfg(not(target_os = "solana"))]
    pub fn new(
        amounts: Vec<u64>,
        bit_lengths: Vec<usize>,
        openings: Vec<&PedersenOpening>,
        transcript: &mut Transcript,
    ) -> Result<Self, RangeProofGenerationError> {
        // 1. Validate inputs
        let m = amounts.len();
        if bit_lengths.len() != m || openings.len() != m {
            return Err(RangeProofGenerationError::VectorLengthMismatch);
        }

        // each bit length must be greater than 0 for the proof to make sense
        if bit_lengths
            .iter()
            .any(|bit_length| *bit_length == 0 || *bit_length > u64::BITS as usize)
        {
            return Err(RangeProofGenerationError::InvalidBitSize);
        }

        // total vector dimension to compute the ultimate inner product proof for
        let nm: usize = bit_lengths.iter().sum();
        if !nm.is_power_of_two() {
            return Err(RangeProofGenerationError::VectorLengthMismatch);
        }

        let bp_gens = RangeProofGens::new(nm)
            .map_err(|_| RangeProofGenerationError::MaximumGeneratorLengthExceeded)?;

        transcript.range_proof_domain_separator(nm as u64);

        // 2. Create commitments A and S.
        // A is a commitment to the bit-vectors a_L and a_R
        let mut a_blinding = Scalar::random(&mut OsRng);
        let mut A = a_blinding * &(*H);

        let mut gens_iter = bp_gens.G(nm).zip(bp_gens.H(nm));
        for (amount_i, n_i) in amounts.iter().zip(bit_lengths.iter()) {
            for j in 0..(*n_i) {
                let (G_ij, H_ij) = gens_iter.next().unwrap();

                // `j` is guaranteed to be at most `u64::BITS` (a 6-bit number) and therefore,
                // casting is lossless and right shift can be safely unwrapped
                let v_ij = Choice::from((amount_i.checked_shr(j as u32).unwrap() & 1) as u8);
                let mut point = -H_ij;
                // Add G_ij if bit is 1, else do nothing (since a_R = a_L - 1)
                point.conditional_assign(G_ij, v_ij);
                A += point;
            }
        }
        let A = A.compress();

        // generate blinding factors and generate their Pedersen vector commitment
        let mut s_L: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut OsRng)).collect();
        let mut s_R: Vec<Scalar> = (0..nm).map(|_| Scalar::random(&mut OsRng)).collect();

        // generate blinding factor for Pedersen commitment; `s_blinding` should not to be confused
        // with blinding factors for the actual inner product vector
        let mut s_blinding = Scalar::random(&mut OsRng);

        let S = RistrettoPoint::multiscalar_mul(
            iter::once(&s_blinding).chain(s_L.iter()).chain(s_R.iter()),
            iter::once(&(*H)).chain(bp_gens.G(nm)).chain(bp_gens.H(nm)),
        )
        .compress();

        // 3. Derive challenges y and z.
        transcript.append_point(b"A", &A);
        transcript.append_point(b"S", &S);

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        // 4. Construct the blinded vector polynomials l(x) and r(x).
        //    l(x) = (a_L - z*1) + s_L*x
        //    r(x) = y^nm o (a_R + z*1 + s_R*x) + (z^2*2^n_1 || ... || z^{m+1}*2^n_m)
        //    where `o` is the Hadamard product and `||` is vector concatenation.
        let mut l_poly = util::VecPoly1::zero(nm);
        let mut r_poly = util::VecPoly1::zero(nm);

        let mut i = 0;
        let mut exp_z = z * z;
        let mut exp_y = Scalar::ONE;

        for (amount_i, n_i) in amounts.iter().zip(bit_lengths.iter()) {
            let mut exp_2 = Scalar::ONE;

            for j in 0..(*n_i) {
                // `j` is guaranteed to be at most `u64::BITS` (a 6-bit number) and therefore,
                // casting is lossless and right shift can be safely unwrapped
                let a_L_j = Scalar::from(amount_i.checked_shr(j as u32).unwrap() & 1);
                let a_R_j = a_L_j - Scalar::ONE;

                l_poly.0[i] = a_L_j - z;
                l_poly.1[i] = s_L[i];
                r_poly.0[i] = exp_y * (a_R_j + z) + exp_z * exp_2;
                r_poly.1[i] = exp_y * s_R[i];

                exp_y *= y;
                exp_2 = exp_2 + exp_2;

                // `i` is capped by the sum of vectors in `bit_lengths`
                i = i.checked_add(1).unwrap();
            }
            exp_z *= z;
        }

        // 5. Compute the inner product polynomial t(x) = <l(x), r(x)>.
        let t_poly = l_poly
            .inner_product(&r_poly)
            .ok_or(RangeProofGenerationError::InnerProductLengthMismatch)?;

        // 6. Commit to the t_1 and t_2 coefficients of t(x).
        let (T_1, t_1_blinding) = Pedersen::new(t_poly.1);
        let (T_2, t_2_blinding) = Pedersen::new(t_poly.2);

        let T_1 = T_1.get_point().compress();
        let T_2 = T_2.get_point().compress();

        transcript.append_point(b"T_1", &T_1);
        transcript.append_point(b"T_2", &T_2);

        // 7. Derive challenge x and compute openings.
        let x = transcript.challenge_scalar(b"x");

        // Compute the aggregated blinding factor for all value commitments.
        let mut agg_opening = Scalar::ZERO;
        let mut exp_z = z;
        for opening in openings {
            exp_z *= z;
            agg_opening += exp_z * opening.get_scalar();
        }

        let t_blinding_poly = util::Poly2(
            agg_opening,
            *t_1_blinding.get_scalar(),
            *t_2_blinding.get_scalar(),
        );

        let t_x = t_poly.eval(x);
        let t_x_blinding = t_blinding_poly.eval(x);

        transcript.append_scalar(b"t_x", &t_x);
        transcript.append_scalar(b"t_x_blinding", &t_x_blinding);

        // homomorphically compuate the openings for A + x*S
        let e_blinding = a_blinding + s_blinding * x;

        // 8. Finally, create the inner product proof.
        let l_vec = l_poly.eval(x);
        let r_vec = r_poly.eval(x);

        transcript.append_scalar(b"e_blinding", &e_blinding);

        // compute the inner product argument on the commitment:
        // P = <l(x), G> + <r(x), H'> + <l(x), r(x)>*Q
        let w = transcript.challenge_scalar(b"w");
        let Q = w * &G;

        let G_factors: Vec<Scalar> = iter::repeat_n(Scalar::ONE, nm).collect();
        let H_factors: Vec<Scalar> = util::exp_iter(y.invert()).take(nm).collect();

        // compute challenge `c` for consistency with the verifier
        let _c = transcript.challenge_scalar(b"c");

        let ipp_proof = InnerProductProof::new(
            &Q,
            &G_factors,
            &H_factors,
            bp_gens.G(nm).cloned().collect(),
            bp_gens.H(nm).cloned().collect(),
            l_vec,
            r_vec,
            transcript,
        )?;

        // compute challenge `d` for consistency with the verifier
        transcript.append_scalar(b"ipp_a", &ipp_proof.a);
        transcript.append_scalar(b"ipp_b", &ipp_proof.b);
        let _d = transcript.challenge_scalar(b"d");

        a_blinding.zeroize();
        s_blinding.zeroize();
        s_L.zeroize();
        s_R.zeroize();

        Ok(RangeProof {
            A,
            S,
            T_1,
            T_2,
            t_x,
            t_x_blinding,
            e_blinding,
            ipp_proof,
        })
    }

    /// Verifies an aggregated range proof for a set of commitments.
    ///
    /// This function implements the verifier's logic, which is optimized into a
    /// single large multiscalar multiplication (`mega_check`) for efficiency. This
    /// check simultaneously verifies all aspects of the proof.
    #[allow(clippy::many_single_char_names)]
    pub fn verify(
        &self,
        comms: Vec<&PedersenCommitment>,
        bit_lengths: Vec<usize>,
        transcript: &mut Transcript,
    ) -> Result<(), RangeProofVerificationError> {
        // 1. Validate inputs and reconstruct challenges from the transcript.
        if comms.len() != bit_lengths.len() {
            return Err(RangeProofVerificationError::VectorLengthMismatch);
        }

        // explicitly reject identity commitments.
        if comms.iter().any(|c| c.get_point().is_identity()) {
            return Err(RangeProofVerificationError::AlgebraicRelation);
        }

        let m = bit_lengths.len();
        let nm: usize = bit_lengths.iter().sum();
        if !nm.is_power_of_two() {
            return Err(RangeProofVerificationError::InvalidBitSize);
        }

        let bp_gens = RangeProofGens::new(nm)
            .map_err(|_| RangeProofVerificationError::MaximumGeneratorLengthExceeded)?;

        transcript.range_proof_domain_separator(nm as u64);

        // append proof data to transcript and derive appropriate challenge scalars
        transcript.validate_and_append_point(b"A", &self.A)?;
        transcript.validate_and_append_point(b"S", &self.S)?;

        let y = transcript.challenge_scalar(b"y");
        let z = transcript.challenge_scalar(b"z");

        let zz = z * z;
        let minus_z = -z;

        transcript.validate_and_append_point(b"T_1", &self.T_1)?;
        transcript.validate_and_append_point(b"T_2", &self.T_2)?;

        let x = transcript.challenge_scalar(b"x");

        transcript.append_scalar(b"t_x", &self.t_x);
        transcript.append_scalar(b"t_x_blinding", &self.t_x_blinding);
        transcript.append_scalar(b"e_blinding", &self.e_blinding);

        let w = transcript.challenge_scalar(b"w");

        // The challenge `c` is a legacy component from an older implementation.
        // It is now unused, but is kept here for backward compatibility.
        let _c = transcript.challenge_scalar(b"c");

        // 2. Compute the scalars for the verification equation.
        let (x_sq, x_inv_sq, s) = self.ipp_proof.verification_scalars(nm, transcript)?;
        let s_inv = s.iter().rev();

        let a = self.ipp_proof.a;
        let b = self.ipp_proof.b;

        transcript.append_scalar(b"ipp_a", &a);
        transcript.append_scalar(b"ipp_b", &b);

        // Challenge for batching the main algebraic relation checks
        let d = transcript.challenge_scalar(b"d");

        // 3. Construct the scalars for the single large multiscalar multiplication.

        // This vector is used in the `h` terms of the final check.
        // It's a concatenation of powers-of-2 vectors, each scaled by a power of z.
        // Formula: z^0*2^n_0 || z^1*2^n_1 || ... || z^{m-1}*2^n_{m-1}
        let concat_z_and_2: Vec<Scalar> = util::exp_iter(z)
            .zip(bit_lengths.iter())
            .flat_map(|(exp_z, n_i)| {
                util::exp_iter(Scalar::from(2u64))
                    .take(*n_i)
                    .map(move |exp_2| exp_2 * exp_z)
            })
            .collect();

        let gs = s.iter().map(|s_i| minus_z - a * s_i);
        let hs = s_inv
            .zip(util::exp_iter(y.invert()))
            .zip(concat_z_and_2.iter())
            .map(|((s_i_inv, exp_y_inv), z_and_2)| z + exp_y_inv * (zz * z_and_2 - b * s_i_inv));

        let basepoint_scalar =
            w * (self.t_x - a * b) + d * (delta(&bit_lengths, &y, &z) - self.t_x);
        let value_commitment_scalars = util::exp_iter(z).take(m).map(|z_exp| d * zz * z_exp);

        // 4. Perform the final "mega-check"
        // This single multiscalar multiplication verifies all relations simultaneously.
        let mega_check = RistrettoPoint::optional_multiscalar_mul(
            iter::once(Scalar::ONE)
                .chain(iter::once(x))
                .chain(iter::once(d * x))
                .chain(iter::once(d * x * x))
                .chain(iter::once(-self.e_blinding - d * self.t_x_blinding))
                .chain(iter::once(basepoint_scalar))
                .chain(x_sq.iter().cloned())
                .chain(x_inv_sq.iter().cloned())
                .chain(gs)
                .chain(hs)
                .chain(value_commitment_scalars),
            iter::once(self.A.decompress())
                .chain(iter::once(self.S.decompress()))
                .chain(iter::once(self.T_1.decompress()))
                .chain(iter::once(self.T_2.decompress()))
                .chain(iter::once(Some(*H)))
                .chain(iter::once(Some(G)))
                .chain(self.ipp_proof.L_vec.iter().map(|L| L.decompress()))
                .chain(self.ipp_proof.R_vec.iter().map(|R| R.decompress()))
                .chain(bp_gens.G(nm).map(|&x| Some(x)))
                .chain(bp_gens.H(nm).map(|&x| Some(x)))
                .chain(comms.iter().map(|V| Some(*V.get_point()))),
        )
        .ok_or(RangeProofVerificationError::MultiscalarMul)?;

        if mega_check.is_identity() {
            Ok(())
        } else {
            Err(RangeProofVerificationError::AlgebraicRelation)
        }
    }

    // Following the dalek rangeproof library signature for now. The exact method signature can be
    // changed.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7 * 32 + self.ipp_proof.serialized_size());
        buf.extend_from_slice(self.A.as_bytes());
        buf.extend_from_slice(self.S.as_bytes());
        buf.extend_from_slice(self.T_1.as_bytes());
        buf.extend_from_slice(self.T_2.as_bytes());
        buf.extend_from_slice(self.t_x.as_bytes());
        buf.extend_from_slice(self.t_x_blinding.as_bytes());
        buf.extend_from_slice(self.e_blinding.as_bytes());
        buf.extend_from_slice(&self.ipp_proof.to_bytes());
        buf
    }

    // Following the dalek rangeproof library signature for now. The exact method signature can be
    // changed.
    pub fn from_bytes(slice: &[u8]) -> Result<RangeProof, RangeProofVerificationError> {
        if slice.len() % 32 != 0 {
            return Err(RangeProofVerificationError::Deserialization);
        }
        if slice.len() < 7 * 32 {
            return Err(RangeProofVerificationError::Deserialization);
        }

        let A = CompressedRistretto(util::read32(&slice[0..]));
        let S = CompressedRistretto(util::read32(&slice[32..]));
        let T_1 = CompressedRistretto(util::read32(&slice[2 * 32..]));
        let T_2 = CompressedRistretto(util::read32(&slice[3 * 32..]));

        let t_x = Scalar::from_canonical_bytes(util::read32(&slice[4 * 32..]))
            .into_option()
            .ok_or(RangeProofVerificationError::Deserialization)?;
        let t_x_blinding = Scalar::from_canonical_bytes(util::read32(&slice[5 * 32..]))
            .into_option()
            .ok_or(RangeProofVerificationError::Deserialization)?;
        let e_blinding = Scalar::from_canonical_bytes(util::read32(&slice[6 * 32..]))
            .into_option()
            .ok_or(RangeProofVerificationError::Deserialization)?;

        let ipp_proof = InnerProductProof::from_bytes(&slice[7 * 32..])?;

        Ok(RangeProof {
            A,
            S,
            T_1,
            T_2,
            t_x,
            t_x_blinding,
            e_blinding,
            ipp_proof,
        })
    }
}

/// Computes the `delta(y,z)` term for the verification equation.
///
/// This term is a function of the challenges `y` and `z` and the proof dimensions.
/// It is needed to correctly aggregate the polynomial checks.
/// The formula is: `delta(y,z) = (z - z^2) * <1, y^nm> - sum_{j=0}^{m-1} z^(j+3) * <1, 2^n_j>`
#[cfg(not(target_os = "solana"))]
fn delta(bit_lengths: &[usize], y: &Scalar, z: &Scalar) -> Scalar {
    let nm: usize = bit_lengths.iter().sum();
    let sum_y = util::sum_of_powers(y, nm);

    let mut agg_delta = (z - z * z) * sum_y;
    let mut exp_z = z * z * z;
    for n_i in bit_lengths.iter() {
        let sum_2 = util::sum_of_powers(&Scalar::from(2u64), *n_i);
        agg_delta -= exp_z * sum_2;
        exp_z *= z;
    }
    agg_delta
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            encryption::pod::pedersen::PodPedersenCommitment, range_proof::pod::PodRangeProofU128,
        },
        std::str::FromStr,
    };

    #[test]
    fn test_single_rangeproof() {
        let (comm, open) = Pedersen::new(55_u64);

        let mut transcript_create = Transcript::new_zk_elgamal_transcript(b"Test");
        let mut transcript_verify = Transcript::new_zk_elgamal_transcript(b"Test");

        let proof =
            RangeProof::new(vec![55], vec![32], vec![&open], &mut transcript_create).unwrap();

        proof
            .verify(vec![&comm], vec![32], &mut transcript_verify)
            .unwrap();

        assert_eq!(
            transcript_create.challenge_scalar(b"test"),
            transcript_verify.challenge_scalar(b"test"),
        )
    }

    #[test]
    fn test_aggregated_rangeproof() {
        let (comm_1, open_1) = Pedersen::new(55_u64);
        let (comm_2, open_2) = Pedersen::new(77_u64);
        let (comm_3, open_3) = Pedersen::new(99_u64);

        let mut transcript_create = Transcript::new_zk_elgamal_transcript(b"Test");
        let mut transcript_verify = Transcript::new_zk_elgamal_transcript(b"Test");

        let proof = RangeProof::new(
            vec![55, 77, 99],
            vec![64, 32, 32],
            vec![&open_1, &open_2, &open_3],
            &mut transcript_create,
        )
        .unwrap();

        proof
            .verify(
                vec![&comm_1, &comm_2, &comm_3],
                vec![64, 32, 32],
                &mut transcript_verify,
            )
            .unwrap();

        assert_eq!(
            transcript_create.challenge_scalar(b"test"),
            transcript_verify.challenge_scalar(b"test"),
        )
    }

    #[test]
    fn range_proof_bytes_roundtrip() {
        let (comm, open) = Pedersen::new(42_u64);

        let mut transcript_create = Transcript::new_zk_elgamal_transcript(b"Test");
        let mut transcript_verify = Transcript::new_zk_elgamal_transcript(b"Test");

        let bits: usize = 8;

        let proof = RangeProof::new(vec![42], vec![bits], vec![&open], &mut transcript_create)
            .expect("proof create");

        let enc = proof.to_bytes();
        assert!(!enc.is_empty());

        let dec = RangeProof::from_bytes(&enc).expect("from_bytes");

        assert_eq!(enc, dec.to_bytes());

        assert!(dec
            .verify(vec![&comm], vec![bits], &mut transcript_verify)
            .is_ok());
    }

    #[test]
    fn test_range_proof_string() {
        let commitment_1_str = "qtkYT/O6bSJ9y7mtqxjZ7dOqloJwLGTcTaeG+5GlBWo=";
        let pod_commitment_1 = PodPedersenCommitment::from_str(commitment_1_str).unwrap();
        let commitment_1: PedersenCommitment = pod_commitment_1.try_into().unwrap();

        let commitment_2_str = "pCdHYFSN7yMEK9Li01M1w1OeRzbaVgQ8xYHlxPTUtF0=";
        let pod_commitment_2 = PodPedersenCommitment::from_str(commitment_2_str).unwrap();
        let commitment_2: PedersenCommitment = pod_commitment_2.try_into().unwrap();

        let commitment_3_str = "gqs3gA6CqT3Uvpb2eCW/lo6m/A2RxHSSopObQkv3DCU=";
        let pod_commitment_3 = PodPedersenCommitment::from_str(commitment_3_str).unwrap();
        let commitment_3: PedersenCommitment = pod_commitment_3.try_into().unwrap();

        let proof_str = "lLDpeo97bHU8A34ruX/wKUY4SJgCKLZf7HiBy6Tz5R8EGdLQuqleOmGWWt+tWO9XMqww1vBNDSADFTMONLWsNLrsArLR2ALxpqUSo/Kw9LG3gH+YApSZksWrYuk7RG1K0JtVnt6j9hYSoLiuinkIm3iWTyfrVZooiX1FMoRAnD5SyPYNJxV4e4POb6WpJvkgXVZuNUC5DF0SK2yVihGmBu05fpG8eHhMcekSPUfIVjNfSQImJ09YvVUgVJvGAcAKBIbB/L2bOfUcmRcrun/F8cOnV5MuSJ0IzYcl9SkEPgEKiC5qv4oep2fWg4Ch0RUM9uWBxI+FXbM/xesdvTzfC3bIhntvws8f5BON6hm/6reWR/7J+z+8rSM0pbpFDalaWLXYxM7uSm4sHzvZtU+Z6/eDvpmNJyVCfFbkcETQsQ/OMzavDAbhpbsvcOPHIgTiesOtgDFBYWarJSrWSmckcaqQ1bEftaSkB+Kbs6zvfc0Pl0LfOy5zt3a3Nqh0a5BwgFEerolBgu/ZX5sptjTnu2psvgBPDzOsUYtRKhY1sXPyg2t9KhFVJ/Riw1+AlnQuAL0GJYCFPUVSkJX2dRVzHQ41kdti6pMsTh/ifBLLlSf5AYk9jiYeHk1HCokBITcwXL36nI3B1HQl6g3/nsx//Jd7w17hJuuIYkOhNuz7iTtisvnCNZdiDkFcTky8ya8oJBM1kJrdakdesStWTXzJOvKfs5jUrl5yVksq+E/jM/oU09cYSoesUQMxAgHqJmkvipRlx71+/YgL1349W4wJ3oPd6kkYx0YVwEHjqiZTvnJEVyUvQxc6X0ddUpNBrjfRxKJ5OV+axOaz76S22PokJh6LNbwa7EUVEwVW0BIABytN9fOe7y+2w4+k73Q8LuFE5QIaqcWX/9IRHey5wEbKtF4ARD6pot92nqXZLxUP1whvrMYNlbFeYLGBX6T6J5+7j3c3fHgCZAhMWSU+MNuGBQ==";
        let pod_proof = PodRangeProofU128::from_str(proof_str).unwrap();
        let proof: RangeProof = pod_proof.try_into().unwrap();

        let mut transcript_verify = Transcript::new_zk_elgamal_transcript(b"Test");

        proof
            .verify(
                vec![&commitment_1, &commitment_2, &commitment_3],
                vec![64, 32, 32],
                &mut transcript_verify,
            )
            .unwrap()
    }

    #[test]
    fn test_aggregated_rangeproof_non_power_of_two_lengths() {
        // 10 + 22 = 32 (Power of two sum is required)
        let bit_len_1 = 10;
        let bit_len_2 = 22;

        // Create amounts that fit within these arbitrary ranges
        let amount_1 = (1 << bit_len_1) - 1; // Max value for 10 bits
        let amount_2 = (1 << bit_len_2) - 1; // Max value for 22 bits

        let (comm_1, open_1) = Pedersen::new(amount_1);
        let (comm_2, open_2) = Pedersen::new(amount_2);

        let mut transcript_create = Transcript::new_zk_elgamal_transcript(b"Test");
        let mut transcript_verify = Transcript::new_zk_elgamal_transcript(b"Test");

        let proof = RangeProof::new(
            vec![amount_1, amount_2],
            vec![bit_len_1, bit_len_2],
            vec![&open_1, &open_2],
            &mut transcript_create,
        )
        .unwrap();

        assert!(proof
            .verify(
                vec![&comm_1, &comm_2],
                vec![bit_len_1, bit_len_2],
                &mut transcript_verify,
            )
            .is_ok());

        assert_eq!(
            transcript_create.challenge_scalar(b"test"),
            transcript_verify.challenge_scalar(b"test"),
        );
    }
}
