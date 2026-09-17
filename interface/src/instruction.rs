//! Instructions provided by the [`ZK ElGamal proof`] program.
//!
//! There are two types of instructions in the proof program: proof verification instructions and
//! the `CloseContextState` instruction.
//!
//! Each proof verification instruction verifies a certain type of zero-knowledge proof. These
//! instructions are processed by the program in two steps:
//!   1. The program verifies the zero-knowledge proof.
//!   2. The program optionally stores the context component of the zero-knowledge proof to a
//!      dedicated [`context-state`] account.
//!
//! In step 1, the zero-knowledge proof can either be included directly as the instruction data or
//! pre-written to an account. The program determines the mode by inspecting the length of the
//! instruction data.
//!
//! **Case A: Proof in a separate account**
//! If the instruction data is exactly 5 bytes (1-byte instruction discriminator plus 4-byte unsigned
//! integer for offset), the program assumes that the first account provided with the instruction
//! contains the zero-knowledge proof. It then verifies the account data at the offset specified in
//! the instruction.
//!
//! **Case B: Proof in instruction data**
//! If two additional accounts are provided (for the context state and its owner), the program
//! interprets this as a request to store the proof's context data and writes it to the specified
//! context-state account.
//!
//! In step 2, the program determines whether to create a context-state account by inspecting the
//! number of accounts provided with the instruction. If two additional accounts are provided with
//! the instruction after verifying the zero-knowledge proof, then the program writes the context
//! data to the specified context-state account.
//!
//! NOTE: A context-state account must be pre-allocated to the exact size of the context data that
//! is expected for a proof type before it is included as part of a proof verification instruction.
//!
//! The `CloseContextState` instruction closes a context state account. A transaction containing
//! this instruction must be signed by the context account's owner. This instruction can be used by
//! the account owner to reclaim lamports for storage.
//!
//! [`ZK ElGamal proof`]: https://docs.solanalabs.com/runtime/zk-token-proof
//! [`context-state`]: https://docs.solanalabs.com/runtime/zk-token-proof#context-data

use {
    crate::proof_data::{ProofType, ZkProofData},
    alloc::vec,
    bytemuck::{bytes_of, Pod},
    num_derive::{FromPrimitive, ToPrimitive},
    num_traits::{FromPrimitive, ToPrimitive},
    solana_address::Address,
    solana_instruction::{AccountMeta, Instruction},
    solana_instruction_error::InstructionError,
};

#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofInstruction {
    /// Close a zero-knowledge proof context state.
    ///
    /// Accounts expected by this instruction:
    ///   0. `[writable]` The proof context account to close
    ///   1. `[writable]` The destination account for lamports
    ///   2. `[signer]` The context account's owner
    ///
    /// Data expected by this instruction:
    ///   None
    ///
    CloseContextState,

    /// Verify a zero-ciphertext proof.
    ///
    /// A zero-ciphertext proof certifies that an ElGamal ciphertext encrypts the value zero.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `ZeroCiphertextProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyZeroCiphertext,

    /// Verify a ciphertext-ciphertext equality proof.
    ///
    /// A ciphertext-ciphertext equality proof certifies that two ElGamal ciphertexts encrypt the
    /// same message.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `CiphertextCiphertextEqualityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyCiphertextCiphertextEquality,

    /// Verify a ciphertext-commitment equality proof.
    ///
    /// A ciphertext-commitment equality proof certifies that an ElGamal ciphertext and a Pedersen
    /// commitment encrypt/encode the same message.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `CiphertextCommitmentEqualityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyCiphertextCommitmentEquality,

    /// Verify a public key validity zero-knowledge proof.
    ///
    /// A public key validity proof certifies that an ElGamal public key is well-formed and the
    /// prover knows the corresponding secret key.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `PubkeyValidityData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyPubkeyValidity,

    /// Verify a percentage-with-cap proof.
    ///
    /// A percentage-with-cap proof certifies that a tuple of Pedersen commitments satisfy a
    /// percentage relation.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `PercentageWithCapProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyPercentageWithCap,

    /// Verify a 64-bit batched range proof.
    ///
    /// A batched range proof is defined with respect to a sequence of Pedersen commitments `[C_1,
    /// ..., C_N]` and bit-lengths `[n_1, ..., n_N]`. It certifies that each commitment `C_i` is a
    /// commitment to a positive number of bit-length `n_i`. Batch verifying range proofs is more
    /// efficient than verifying independent range proofs on commitments `C_1, ..., C_N`
    /// separately.
    ///
    /// The bit-length of a batched range proof specifies the sum of the individual bit-lengths
    /// `n_1, ..., n_N`. For example, this instruction can be used to certify that two commitments
    /// `C_1` and `C_2` each hold positive 32-bit numbers.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `BatchedRangeProofU64Data` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyBatchedRangeProofU64,

    /// Verify 128-bit batched range proof.
    ///
    /// The bit-length of a batched range proof specifies the sum of the individual bit-lengths
    /// `n_1, ..., n_N`. For example, this instruction can be used to certify that two commitments
    /// `C_1` and `C_2` each hold positive 64-bit numbers.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `BatchedRangeProofU128Data` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyBatchedRangeProofU128,

    /// Verify 256-bit batched range proof.
    ///
    /// The bit-length of a batched range proof specifies the sum of the individual bit-lengths
    /// `n_1, ..., n_N`. For example, this instruction can be used to certify that four commitments
    /// `[C_1, C_2, C_3, C_4]` each hold positive 64-bit numbers.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `BatchedRangeProofU256Data` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyBatchedRangeProofU256,

    /// Verify a grouped-ciphertext with 2 handles validity proof.
    ///
    /// A grouped-ciphertext validity proof certifies that a grouped ElGamal ciphertext is
    /// well-defined, i.e. the ciphertext can be decrypted by private keys associated with its
    /// decryption handles.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `GroupedCiphertext2HandlesValidityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyGroupedCiphertext2HandlesValidity,

    /// Verify a batched grouped-ciphertext with 2 handles validity proof.
    ///
    /// A batched grouped-ciphertext validity proof certifies the validity of two grouped ElGamal
    /// ciphertext that are encrypted using the same set of ElGamal public keys. A batched
    /// grouped-ciphertext validity proof is shorter and more efficient than two individual
    /// grouped-ciphertext validity proofs.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `BatchedGroupedCiphertext2HandlesValidityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyBatchedGroupedCiphertext2HandlesValidity,

    /// Verify a grouped-ciphertext with 3 handles validity proof.
    ///
    /// A grouped-ciphertext validity proof certifies that a grouped ElGamal ciphertext is
    /// well-defined, i.e. the ciphertext can be decrypted by private keys associated with its
    /// decryption handles.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `GroupedCiphertext3HandlesValidityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyGroupedCiphertext3HandlesValidity,

    /// Verify a batched grouped-ciphertext with 3 handles validity proof.
    ///
    /// A batched grouped-ciphertext validity proof certifies the validity of two grouped ElGamal
    /// ciphertext that are encrypted using the same set of ElGamal public keys. A batched
    /// grouped-ciphertext validity proof is shorter and more efficient than two individual
    /// grouped-ciphertext validity proofs.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   There are four ways to structure the accounts, depending on whether the
    ///   proof is provided as instruction data or in a separate account, and whether
    ///   a proof context is created.
    ///
    ///   1. **Proof in instruction data, no context state:**
    ///      - No accounts are required.
    ///
    ///   2. **Proof in instruction data, with context state:**
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    ///   3. **Proof in account, no context state:**
    ///      - `[]` Account to read the proof from.
    ///
    ///   4. **Proof in account, with context state:**
    ///      - `[]` Account to read the proof from.
    ///      - `[writable]` The proof context account to create.
    ///      - `[]` The proof context account owner.
    ///
    /// The instruction expects either:
    ///   i. `BatchedGroupedCiphertext3HandlesValidityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    /// Note that the context state account is not required to be a signer and
    /// MUST be included within the same Transaction as the system program's
    /// `CreateAccount` instruction that creates the account being initialized.
    /// Otherwise another party can acquire ownership of the uninitialized
    /// account.
    ///
    VerifyBatchedGroupedCiphertext3HandlesValidity,
}

/// Pubkeys associated with a context state account to be used as parameters to functions.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ContextStateInfo<'a> {
    pub context_state_account: &'a Address,
    pub context_state_authority: &'a Address,
}

/// Create a `CloseContextState` instruction.
pub fn close_context_state(
    context_state_info: ContextStateInfo,
    destination_account: &Address,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*context_state_info.context_state_account, false),
        AccountMeta::new(*destination_account, false),
        AccountMeta::new_readonly(*context_state_info.context_state_authority, true),
    ];

    let data = vec![ToPrimitive::to_u8(&ProofInstruction::CloseContextState).unwrap()];

    Instruction {
        program_id: crate::id(),
        accounts,
        data,
    }
}

impl TryFrom<ProofType> for ProofInstruction {
    type Error = InstructionError;

    /// Return the verification instruction, rejecting `ProofType::Uninitialized`.
    fn try_from(proof_type: ProofType) -> Result<Self, Self::Error> {
        Ok(match proof_type {
            ProofType::Uninitialized => return Err(InstructionError::InvalidInstructionData),
            ProofType::ZeroCiphertext => Self::VerifyZeroCiphertext,
            ProofType::CiphertextCiphertextEquality => Self::VerifyCiphertextCiphertextEquality,
            ProofType::CiphertextCommitmentEquality => Self::VerifyCiphertextCommitmentEquality,
            ProofType::PubkeyValidity => Self::VerifyPubkeyValidity,
            ProofType::PercentageWithCap => Self::VerifyPercentageWithCap,
            ProofType::BatchedRangeProofU64 => Self::VerifyBatchedRangeProofU64,
            ProofType::BatchedRangeProofU128 => Self::VerifyBatchedRangeProofU128,
            ProofType::BatchedRangeProofU256 => Self::VerifyBatchedRangeProofU256,
            ProofType::GroupedCiphertext2HandlesValidity => {
                Self::VerifyGroupedCiphertext2HandlesValidity
            }
            ProofType::BatchedGroupedCiphertext2HandlesValidity => {
                Self::VerifyBatchedGroupedCiphertext2HandlesValidity
            }
            ProofType::GroupedCiphertext3HandlesValidity => {
                Self::VerifyGroupedCiphertext3HandlesValidity
            }
            ProofType::BatchedGroupedCiphertext3HandlesValidity => {
                Self::VerifyBatchedGroupedCiphertext3HandlesValidity
            }
        })
    }
}

impl ProofInstruction {
    pub fn encode_verify_proof<T, U>(
        &self,
        context_state_info: Option<ContextStateInfo>,
        proof_data: &T,
    ) -> Instruction
    where
        T: Pod + ZkProofData<U>,
        U: Pod,
    {
        assert_eq!(
            Self::try_from(T::PROOF_TYPE),
            Ok(*self),
            "proof instruction does not match proof type"
        );

        let accounts = if let Some(context_state_info) = context_state_info {
            vec![
                AccountMeta::new(*context_state_info.context_state_account, false),
                AccountMeta::new_readonly(*context_state_info.context_state_authority, false),
            ]
        } else {
            vec![]
        };

        let mut data = vec![ToPrimitive::to_u8(self).unwrap()];
        data.extend_from_slice(bytes_of(proof_data));

        Instruction {
            program_id: crate::id(),
            accounts,
            data,
        }
    }

    pub fn encode_verify_proof_from_account(
        &self,
        context_state_info: Option<ContextStateInfo>,
        proof_account: &Address,
        offset: u32,
    ) -> Instruction {
        let accounts = if let Some(context_state_info) = context_state_info {
            vec![
                AccountMeta::new_readonly(*proof_account, false),
                AccountMeta::new(*context_state_info.context_state_account, false),
                AccountMeta::new_readonly(*context_state_info.context_state_authority, false),
            ]
        } else {
            vec![AccountMeta::new_readonly(*proof_account, false)]
        };

        let mut data = vec![ToPrimitive::to_u8(self).unwrap()];
        data.extend_from_slice(&offset.to_le_bytes());

        Instruction {
            program_id: crate::id(),
            accounts,
            data,
        }
    }

    pub fn instruction_type(input: &[u8]) -> Option<Self> {
        input
            .first()
            .and_then(|instruction| FromPrimitive::from_u8(*instruction))
    }

    pub fn proof_data<T, U>(input: &[u8]) -> Option<&T>
    where
        T: Pod + ZkProofData<U>,
        U: Pod,
    {
        if Self::instruction_type(input)? != Self::try_from(T::PROOF_TYPE).ok()? {
            return None;
        }

        input
            .get(1..)
            .and_then(|data| bytemuck::try_from_bytes(data).ok())
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::proof_data::*, bytemuck::Zeroable, core::mem::size_of};

    // These fixtures exercise serialization, not cryptographic proof verification.
    fn proof_fixture<T: Pod>() -> T {
        bytemuck::pod_read_unaligned(&vec![0x5a; size_of::<T>()])
    }

    fn check_instruction_bytes_and_accounts<T, U>(instruction_type: ProofInstruction, tag: u8)
    where
        T: Pod + ZkProofData<U>,
        U: Pod,
    {
        let proof = proof_fixture::<T>();
        let context_account = Address::new_from_array([1; 32]);
        let context_authority = Address::new_from_array([2; 32]);
        let context_info = ContextStateInfo {
            context_state_account: &context_account,
            context_state_authority: &context_authority,
        };

        for context in [None, Some(context_info)] {
            let expected_accounts = if context.is_some() {
                vec![
                    AccountMeta::new(context_account, false),
                    AccountMeta::new_readonly(context_authority, false),
                ]
            } else {
                vec![]
            };
            let instruction = instruction_type.encode_verify_proof(context, &proof);
            let mut expected_data = vec![tag];
            expected_data.extend_from_slice(bytes_of(&proof));
            assert_eq!(instruction.program_id, crate::id());
            assert_eq!(instruction.accounts, expected_accounts);
            assert_eq!(instruction.data, expected_data);
            assert_eq!(
                ProofInstruction::instruction_type(&instruction.data),
                Some(instruction_type)
            );
            let decoded = ProofInstruction::proof_data::<T, U>(&instruction.data).unwrap();
            assert_eq!(bytes_of(decoded), bytes_of(&proof));
            assert_eq!(bytes_of(decoded).as_ptr(), instruction.data[1..].as_ptr());
        }
    }

    fn check_rejects_other_tags<T, U>(tag: u8)
    where
        T: Pod + ZkProofData<U>,
        U: Pod,
    {
        let mut data = vec![tag];
        data.extend_from_slice(bytes_of(&proof_fixture::<T>()));
        for other_tag in 0..=u8::MAX {
            if other_tag != tag {
                data[0] = other_tag;
                assert!(
                    ProofInstruction::proof_data::<T, U>(&data).is_none(),
                    "accepted tag {other_tag} for proof tag {tag}"
                );
            }
        }
    }

    fn check_rejects_wrong_lengths<T, U>(tag: u8)
    where
        T: Pod + ZkProofData<U>,
        U: Pod,
    {
        let mut data = vec![tag];
        data.extend_from_slice(bytes_of(&proof_fixture::<T>()));
        // Includes empty input, the tag alone, an account offset, and truncated proofs.
        for len in 0..data.len() {
            assert!(ProofInstruction::proof_data::<T, U>(&data[..len]).is_none());
        }
        data.push(0);
        assert!(ProofInstruction::proof_data::<T, U>(&data).is_none());
    }

    macro_rules! test_proof_types {
        ($($name:ident: $proof:ty => $instruction:ident = $tag:literal),+ $(,)?) => {
            $(
                #[test]
                fn $name() {
                    check_instruction_bytes_and_accounts::<$proof, _>(ProofInstruction::$instruction, $tag);
                    check_rejects_wrong_lengths::<$proof, _>($tag);
                    check_rejects_other_tags::<$proof, _>($tag);
                }
            )+
        };
    }

    // Pin the wire tags independently of either enum's numeric representation.
    test_proof_types! {
        zero_ciphertext: ZeroCiphertextProofData => VerifyZeroCiphertext = 1,
        ciphertext_ciphertext_equality:
            CiphertextCiphertextEqualityProofData => VerifyCiphertextCiphertextEquality = 2,
        ciphertext_commitment_equality:
            CiphertextCommitmentEqualityProofData => VerifyCiphertextCommitmentEquality = 3,
        pubkey_validity: PubkeyValidityProofData => VerifyPubkeyValidity = 4,
        percentage_with_cap: PercentageWithCapProofData => VerifyPercentageWithCap = 5,
        batched_range_u64: BatchedRangeProofU64Data => VerifyBatchedRangeProofU64 = 6,
        batched_range_u128: BatchedRangeProofU128Data => VerifyBatchedRangeProofU128 = 7,
        batched_range_u256: BatchedRangeProofU256Data => VerifyBatchedRangeProofU256 = 8,
        grouped_2_handles:
            GroupedCiphertext2HandlesValidityProofData => VerifyGroupedCiphertext2HandlesValidity = 9,
        batched_grouped_2_handles:
            BatchedGroupedCiphertext2HandlesValidityProofData => VerifyBatchedGroupedCiphertext2HandlesValidity = 10,
        grouped_3_handles:
            GroupedCiphertext3HandlesValidityProofData => VerifyGroupedCiphertext3HandlesValidity = 11,
        batched_grouped_3_handles:
            BatchedGroupedCiphertext3HandlesValidityProofData => VerifyBatchedGroupedCiphertext3HandlesValidity = 12,
    }

    #[test]
    #[should_panic]
    fn encode_rejects_mismatched_proof_type() {
        ProofInstruction::VerifyZeroCiphertext
            .encode_verify_proof(None, &PubkeyValidityProofData::zeroed());
    }

    #[test]
    #[should_panic]
    fn encode_rejects_close_context_state() {
        ProofInstruction::CloseContextState
            .encode_verify_proof(None, &PubkeyValidityProofData::zeroed());
    }

    #[test]
    #[should_panic]
    fn encode_rejects_equal_length_proof_type() {
        ProofInstruction::VerifyGroupedCiphertext3HandlesValidity.encode_verify_proof(
            None,
            &BatchedGroupedCiphertext2HandlesValidityProofData::zeroed(),
        );
    }

    #[test]
    fn decode_rejects_equal_length_proof_types() {
        type Batched = BatchedGroupedCiphertext2HandlesValidityProofData;
        type Grouped = GroupedCiphertext3HandlesValidityProofData;
        assert_eq!(size_of::<Batched>(), 416);
        assert_eq!(size_of::<Grouped>(), 416);

        let batched = ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity
            .encode_verify_proof(None, &Batched::zeroed());
        assert!(ProofInstruction::proof_data::<Grouped, _>(&batched.data).is_none());
        let grouped = ProofInstruction::VerifyGroupedCiphertext3HandlesValidity
            .encode_verify_proof(None, &Grouped::zeroed());
        assert!(ProofInstruction::proof_data::<Batched, _>(&grouped.data).is_none());
    }

    // ZkProofData is public and downstream implementations can select Uninitialized.
    #[derive(Clone, Copy, bytemuck_derive::Pod, bytemuck_derive::Zeroable)]
    #[repr(transparent)]
    struct UninitializedProof(u8);

    impl ZkProofData<u8> for UninitializedProof {
        const PROOF_TYPE: ProofType = ProofType::Uninitialized;

        fn context_data(&self) -> &u8 {
            &self.0
        }
    }

    #[test]
    #[should_panic]
    fn encode_rejects_uninitialized_proof_type() {
        ProofInstruction::CloseContextState.encode_verify_proof(None, &UninitializedProof(0));
    }

    #[test]
    fn decode_rejects_uninitialized_proof_type() {
        for tag in 0..=u8::MAX {
            assert!(ProofInstruction::proof_data::<UninitializedProof, _>(&[tag, 0]).is_none());
        }
    }
}
