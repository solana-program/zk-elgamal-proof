import { AccountMeta, PublicKey, Signer, TransactionInstruction } from '@solana/web3.js';
import {
    CiphertextCiphertextEqualityProofData,
    CiphertextCommitmentEqualityProofData,
    ElGamalCiphertext,
    ElGamalKeypair,
    ElGamalPubkey,
    PedersenOpening,
    PedersenCommitment,
    PubkeyValidityProofData,
    ZeroCiphertextProofData,
} from '@solana/zk-sdk';
import { ZK_ELGAMAL_PROOF_PROGRAM_ID } from './constants';

/** Context state account information to be used as parameters to functions */
export interface ContextStateInfo {
    /** The context state account keypair or public key */
    account: (Signer | PublicKey)
    /** Authority of the context state account */
    authority: PublicKey,
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
    elgamalKeypair: ElGamalKeypair,
    elgamalCiphertext: ElGamalCiphertext,
    contextStateInfo?: ContextStateInfo,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): TransactionInstruction {
    let keys: AccountMeta[] = [];
    if (contextStateInfo) {
        const contextStateAccount = contextStateInfo.account instanceof PublicKey ? contextStateInfo.account : contextStateInfo.account.publicKey;

        keys = [
            { pubkey: contextStateAccount, isSigner: false, isWritable: true },
            { pubkey: contextStateInfo.authority, isSigner: false, isWritable: false },
        ]
    }

    let proofData = ZeroCiphertextProofData.new(elgamalKeypair, elgamalCiphertext);
    let proofDataBytes = proofData.toBytes();

    let data = Buffer.from([ZkElGamalProofInstruction.VerifyZeroCiphertext, ...proofDataBytes]);

    return new TransactionInstruction({ keys, programId, data });
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
    firstKeypair: ElGamalKeypair,
    secondPubkey: ElGamalPubkey,
    firstCiphertext: ElGamalCiphertext,
    secondCiphertext: ElGamalCiphertext,
    secondOpening: PedersenOpening,
    amount: bigint,
    contextStateInfo?: ContextStateInfo,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): TransactionInstruction {
    let keys: AccountMeta[] = [];
    if (contextStateInfo) {
        const contextStateAccount = contextStateInfo.account instanceof PublicKey ? contextStateInfo.account : contextStateInfo.account.publicKey;

        keys = [
            { pubkey: contextStateAccount, isSigner: false, isWritable: true },
            { pubkey: contextStateInfo.authority, isSigner: false, isWritable: false },
        ]
    }

    let proofData = CiphertextCiphertextEqualityProofData.new(
        firstKeypair,
        secondPubkey,
        firstCiphertext,
        secondCiphertext,
        secondOpening,
        amount
    );
    let proofDataBytes = proofData.toBytes();

    let data = Buffer.from([ZkElGamalProofInstruction.VerifyCiphertextCiphertextEquality, ...proofDataBytes]);

    return new TransactionInstruction({ keys, programId, data });
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
    elgamalKeypair: ElGamalKeypair,
    elgamalCiphertext: ElGamalCiphertext,
    pedersenCommitment: PedersenCommitment,
    pedersenOpening: PedersenOpening,
    amount: bigint,
    contextStateInfo?: ContextStateInfo,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): TransactionInstruction {
    let keys: AccountMeta[] = [];
    if (contextStateInfo) {
        const contextStateAccount = contextStateInfo.account instanceof PublicKey ? contextStateInfo.account : contextStateInfo.account.publicKey;

        keys = [
            { pubkey: contextStateAccount, isSigner: false, isWritable: true },
            { pubkey: contextStateInfo.authority, isSigner: false, isWritable: false },
        ]
    }

    let proofData = CiphertextCommitmentEqualityProofData.new(
        elgamalKeypair,
        elgamalCiphertext,
        pedersenCommitment,
        pedersenOpening,
        amount
    );
    let proofDataBytes = proofData.toBytes();

    let data = Buffer.from([ZkElGamalProofInstruction.VerifyCiphertextCommitmentEquality, ...proofDataBytes]);

    return new TransactionInstruction({ keys, programId, data });
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
    elgamalKeypair: ElGamalKeypair,
    contextStateInfo?: ContextStateInfo,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): TransactionInstruction {
    let keys: AccountMeta[] = [];
    if (contextStateInfo) {
        const contextStateAccount = contextStateInfo.account instanceof PublicKey ? contextStateInfo.account : contextStateInfo.account.publicKey;

        keys = [
            { pubkey: contextStateAccount, isSigner: false, isWritable: true },
            { pubkey: contextStateInfo.authority, isSigner: false, isWritable: false },
        ]
    }

    let proofData = PubkeyValidityProofData.new(elgamalKeypair);
    let proofDataBytes = proofData.toBytes();

    let data = Buffer.from([ZkElGamalProofInstruction.VerifyPubkeyValidity, ...proofDataBytes]);

    return new TransactionInstruction({ keys, programId, data });
}
