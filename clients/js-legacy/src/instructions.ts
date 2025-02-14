import type { AccountMeta, Signer } from '@solana/web3.js';
import { PublicKey, TransactionInstruction } from '@solana/web3.js';
import { getU32Codec } from '@solana/codecs-numbers';
import type {
    ElGamalCiphertext,
    ElGamalKeypair,
    ElGamalPubkey,
    PedersenOpening,
    PedersenCommitment,
} from '@solana/zk-sdk';
import {
    CiphertextCiphertextEqualityProofData,
    CiphertextCommitmentEqualityProofData,
    PubkeyValidityProofData,
    ZeroCiphertextProofData,
} from '@solana/zk-sdk';
import { ZK_ELGAMAL_PROOF_PROGRAM_ID } from './constants.js';

/** Context state account information to be used as parameters to functions */
export interface ContextStateInfo {
    /** The context state account keypair or public key */
    account: Signer | PublicKey;
    /** Authority of the context state account */
    authority: PublicKey;
}

/** Record account information to be used as parameters to functions */
export interface RecordAccountInfo {
    /** The record account address */
    account: PublicKey;
    /** The offset for which the proof is to be read from */
    offset: number;
}

export enum ZkElGamalProofInstruction {
    CloseContextState = 0,
    VerifyZeroCiphertext = 1,
    VerifyCiphertextCiphertextEquality = 2,
    VerifyCiphertextCommitmentEquality = 3,
    VerifyPubkeyValidity = 4,
    VerifyPercentageWithCap = 5,
    VerifyBatchedRangeProofU64 = 6,
    VerifyBatchedRangeProofU128 = 7,
    VerifyBatchedRangeProofU256 = 8,
    VerifyGroupedCiphertext2HandlesValidity = 9,
    VerifyBatchedGroupedCiphertext2HandlesValidity = 10,
    VerifyGroupedCiphertext3HandlesValidity = 11,
    VerifyBatchedGroupedCiphertext3HandlesValidity = 12,
}

/**
 * Create a CloseContextState instruction
 *
 * @param contextStateAddress       Address of the context state account
 * @param contextStateAuthority     Authority of the context state account
 * @param destinationAccount        Destination account for the lamports
 *
 * @return Instruction to add to a transaction
 */
export function createCloseContextStateInstruction(
    contextStateAddress: PublicKey,
    destinationAccount: PublicKey,
    contextStateAuthority: PublicKey,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
) {
    const keys = [
        { pubkey: contextStateAddress, isSigner: false, isWritable: true },
        { pubkey: destinationAccount, isSigner: false, isWritable: true },
        { pubkey: contextStateAuthority, isSigner: true, isWritable: false },
    ];
    const data = Buffer.from([ZkElGamalProofInstruction.CloseContextState]);

    return new TransactionInstruction({ keys, programId, data });
}

/** Data input needed to generate a zero-ciphertext proof */
export interface ZeroCiphertextProofInput {
    elgamalKeypair: ElGamalKeypair;
    elgamalCiphertext: ElGamalCiphertext;
}

/**
 * Create a VerifyZeroCiphertext instruction
 *
 * A `contextStateInfo` should be provided when creating a context state info.
 *
 * @param elgamalKeypair            ElGamal keypair associated with the ciphertext
 * @param elgamalCiphertext         ElGamal encryption of zero
 * @param contextStateInfo          Optional context state info
 *
 * @return Instruction to add to a transaction
 */
export function createVerifyZeroCiphertextInstruction(
    proofInput: ZeroCiphertextProofInput | RecordAccountInfo,
    contextStateInfo?: ContextStateInfo,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): TransactionInstruction {
    const keys: AccountMeta[] = [];
    if ('account' in proofInput) {
        keys.push({ pubkey: proofInput.account, isSigner: false, isWritable: false });
    }
    if (contextStateInfo) {
        const contextStateAccount =
            contextStateInfo.account instanceof PublicKey
                ? contextStateInfo.account
                : contextStateInfo.account.publicKey;

        keys.push({ pubkey: contextStateAccount, isSigner: false, isWritable: true });
        keys.push({ pubkey: contextStateInfo.authority, isSigner: false, isWritable: false });
    }

    const data = [ZkElGamalProofInstruction.VerifyZeroCiphertext];
    if ('offset' in proofInput) {
        data.push(...getU32Codec().encode(proofInput.offset));
    } else {
        const proofData = ZeroCiphertextProofData.new(proofInput.elgamalKeypair, proofInput.elgamalCiphertext);
        data.push(...proofData.toBytes());
    }

    return new TransactionInstruction({ keys, programId, data: Buffer.from(data) });
}

/** Data input needed to generate a ciphertext-ciphertext equality proof */
export interface CiphertextCiphertextEqualityProofInput {
    firstKeypair: ElGamalKeypair;
    secondPubkey: ElGamalPubkey;
    firstCiphertext: ElGamalCiphertext;
    secondCiphertext: ElGamalCiphertext;
    secondOpening: PedersenOpening;
    amount: bigint;
}

/**
 * Create a VerifyCiphertextCiphertextEquality instruction
 *
 * A `contextStateInfo` should be provided when creating a context state info.
 *
 * @param firstKeypair              ElGamal keypair associated with the first ciphertext
 * @param secondPubkey              ElGamal pubkey associated with the second ciphertext
 * @param firstCiphertext           First ElGamal ciphertext
 * @param secondCiphertext          Second ElGamal ciphertext
 * @param secondOpening             Pedersen opening associated with the second ciphertext
 * @param amount                    Encrypted amount associated with the ciphertexts
 * @param contextStateInfo          Optional context state info
 *
 * @return Instruction to add to a transaction
 */
export function createVerifyCiphertextCiphertextEqualityInstruction(
    proofInput: CiphertextCiphertextEqualityProofInput | RecordAccountInfo,
    contextStateInfo?: ContextStateInfo,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): TransactionInstruction {
    const keys: AccountMeta[] = [];
    if ('account' in proofInput) {
        keys.push({ pubkey: proofInput.account, isSigner: false, isWritable: false });
    }
    if (contextStateInfo) {
        const contextStateAccount =
            contextStateInfo.account instanceof PublicKey
                ? contextStateInfo.account
                : contextStateInfo.account.publicKey;

        keys.push({ pubkey: contextStateAccount, isSigner: false, isWritable: true });
        keys.push({ pubkey: contextStateInfo.authority, isSigner: false, isWritable: false });
    }

    const data = [ZkElGamalProofInstruction.VerifyCiphertextCiphertextEquality];
    if ('offset' in proofInput) {
        data.push(...getU32Codec().encode(proofInput.offset));
    } else {
        const proofData = CiphertextCiphertextEqualityProofData.new(
            proofInput.firstKeypair,
            proofInput.secondPubkey,
            proofInput.firstCiphertext,
            proofInput.secondCiphertext,
            proofInput.secondOpening,
            proofInput.amount,
        );
        data.push(...proofData.toBytes());
    }

    return new TransactionInstruction({ keys, programId, data: Buffer.from(data) });
}

/** Data input needed to generate a zero-ciphertext proof */
export interface CiphertextCommitmentEqualityProofInput {
    elgamalKeypair: ElGamalKeypair;
    elgamalCiphertext: ElGamalCiphertext;
    pedersenCommitment: PedersenCommitment;
    pedersenOpening: PedersenOpening;
    amount: bigint;
}

/**
 * Create a VerifyCiphertextCommitmentEquality instruction
 *
 * A `contextStateInfo` should be provided when creating a context state info.
 *
 * @param elgamalKeypair            ElGamal keypair associated with the ciphertext
 * @param elgamalCiphertext         ElGamal ciphertext to be proved
 * @param pedersenCommitment        Pedersen commitment to be proved
 * @param pedersenOpening           Pedersen opening for the Pedersen commitment
 * @param amount                    Amount that is encrypted and committed
 * @param contextStateInfo          Optional context state info
 *
 * @return Instruction to add to a transaction
 */
export function createVerifyCiphertextCommitmentEqualityInstruction(
    proofInput: CiphertextCommitmentEqualityProofInput | RecordAccountInfo,
    contextStateInfo?: ContextStateInfo,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): TransactionInstruction {
    const keys: AccountMeta[] = [];
    if ('account' in proofInput) {
        keys.push({ pubkey: proofInput.account, isSigner: false, isWritable: false });
    }
    if (contextStateInfo) {
        const contextStateAccount =
            contextStateInfo.account instanceof PublicKey
                ? contextStateInfo.account
                : contextStateInfo.account.publicKey;

        keys.push({ pubkey: contextStateAccount, isSigner: false, isWritable: true });
        keys.push({ pubkey: contextStateInfo.authority, isSigner: false, isWritable: false });
    }

    const data = [ZkElGamalProofInstruction.VerifyCiphertextCommitmentEquality];
    if ('offset' in proofInput) {
        data.push(...getU32Codec().encode(proofInput.offset));
    } else {
        const proofData = CiphertextCommitmentEqualityProofData.new(
            proofInput.elgamalKeypair,
            proofInput.elgamalCiphertext,
            proofInput.pedersenCommitment,
            proofInput.pedersenOpening,
            proofInput.amount,
        );
        data.push(...proofData.toBytes());
    }

    return new TransactionInstruction({ keys, programId, data: Buffer.from(data) });
}

/** Data input needed to generate a zero-ciphertext proof */
export interface PubkeyValidityProofInput {
    elgamalKeypair: ElGamalKeypair;
}

/**
 * Create a VerifyPubkeyValidity instruction
 *
 * A `contextStateInfo` should be provided when creating a context state info.
 *
 * @param elgamalKeypair            ElGamal keypair to be proved
 * @param contextStateInfo          Optional context state info
 *
 * @return Instruction to add to a transaction
 */
export function createVerifyPubkeyValidityInstruction(
    proofInput: PubkeyValidityProofInput | RecordAccountInfo,
    contextStateInfo?: ContextStateInfo,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): TransactionInstruction {
    const keys: AccountMeta[] = [];
    if ('account' in proofInput) {
        keys.push({ pubkey: proofInput.account, isSigner: false, isWritable: false });
    }
    if (contextStateInfo) {
        const contextStateAccount =
            contextStateInfo.account instanceof PublicKey
                ? contextStateInfo.account
                : contextStateInfo.account.publicKey;

        keys.push({ pubkey: contextStateAccount, isSigner: false, isWritable: true });
        keys.push({ pubkey: contextStateInfo.authority, isSigner: false, isWritable: false });
    }

    const data = [ZkElGamalProofInstruction.VerifyPubkeyValidity];
    if ('offset' in proofInput) {
        data.push(...getU32Codec().encode(proofInput.offset));
    } else {
        const proofData = PubkeyValidityProofData.new(proofInput.elgamalKeypair);
        data.push(...proofData.toBytes());
    }

    return new TransactionInstruction({ keys, programId, data: Buffer.from(data) });
}
