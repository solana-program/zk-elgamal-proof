import type { ConfirmOptions, Connection, Signer, TransactionSignature } from '@solana/web3.js';
import { PublicKey, sendAndConfirmTransaction, SystemProgram, Transaction } from '@solana/web3.js';
import {
    createCloseContextStateInstruction,
    createVerifyCiphertextCiphertextEqualityInstruction,
    createVerifyCiphertextCommitmentEqualityInstruction,
    createVerifyPubkeyValidityInstruction,
    createVerifyZeroCiphertextInstruction,
} from './instructions';
import {
    CIPHERTEXT_CIPHERTEXT_EQUALITY_CONTEXT_ACCOUNT_SIZE,
    CIPHERTEXT_COMMITMENT_EQUALITY_CONTEXT_ACCOUNT_SIZE,
    PUBKEY_VALIDITY_CONTEXT_ACCOUNT_SIZE,
    ZERO_CIPHERTEXT_CONTEXT_ACCOUNT_SIZE,
    ZK_ELGAMAL_PROOF_PROGRAM_ID
} from './constants';
import {
    ElGamalCiphertext,
    ElGamalKeypair,
    ElGamalPubkey,
    PedersenCommitment,
    PedersenOpening
} from '@solana/zk-sdk';

/** Context state account information to be used as parameters to functions */
export interface ContextStateInfo {
    /**
     * Keypair of the context state account. If provided, use the system
     * program to create the context state account.
     */
    keypair?: Signer,
    /** Address of the context state account */
    address: PublicKey,
    /** Authority of the context state account */
    authority: PublicKey,
}

/**
 * Close a context state account
 *
 * @param connection                Connection to use
 * @param payer                     Payer of the transaction fees
 * @param contextStateAddress       Address of the context state account
 * @param contextStateAuthority     Authority of the context state account
 * @param destinationAccount        Destination account for the lamports
 * @param confirmOptions            Options for confirming the transaction
 *
 * @return Signature of the confirmed transaction
 */
export async function closeContextStateProof(
    connection: Connection,
    payer: Signer,
    contextStateAddress: PublicKey,
    destinationAccount: PublicKey,
    contextStateAuthority: Signer,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    const transaction = new Transaction().add(
        createCloseContextStateInstruction(
            contextStateAddress,
            destinationAccount,
            contextStateAuthority.publicKey,
            programId,
        )
    );
    return await sendAndConfirmTransaction(connection, transaction, [payer, contextStateAuthority], confirmOptions);
}

/**
 * Verify a zero-ciphertext proof
 *
 * @param connection                Connection to use
 * @param payer                     Payer of the transaction fees
 * @param elgamalKeypair            ElGamal keypair associated with the ciphertext
 * @param elgamalCiphertext         ElGamal encryption of zero
 * @param contextStateInfo          Optional context state info
 * @param confirmOptions            Options for confirming the transaction
 *
 * @return Signature of the confirmed transaction
 */
export async function verifyZeroCiphertext(
    connection: Connection,
    payer: Signer,
    elgamalKeypair: ElGamalKeypair,
    elgamalCiphertext: ElGamalCiphertext,
    contextStateInfo?: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    let transaction = new Transaction();
    let signers = [payer];
    if (contextStateInfo && contextStateInfo.keypair) {
        const accountSize = ZERO_CIPHERTEXT_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.keypair.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        )
        signers.push(contextStateInfo.keypair);
    }

    transaction.add(
        createVerifyZeroCiphertextInstruction(
            elgamalKeypair,
            elgamalCiphertext,
            contextStateInfo,
            programId,
        )
    );
    return await sendAndConfirmTransaction(connection, transaction, signers, confirmOptions);
}

/**
 * Verify a ciphertext-ciphertext equality proof
 *
 * @param connection                Connection to use
 * @param payer                     Payer of the transaction fees
 * @param firstKeypair              ElGamal keypair associated with the first ciphertext
 * @param secondPubkey              ElGamal pubkey associated with the second ciphertext
 * @param firstCiphertext           First ElGamal ciphertext
 * @param secondCiphertext          Second ElGamal ciphertext
 * @param secondOpening             Pedersen opening associated with the second ciphertext
 * @param amount                    Encrypted amount associated with the ciphertexts
 * @param contextStateInfo          Optional context state info
 * @param confirmOptions            Options for confirming the transaction
 *
 * @return Signature of the confirmed transaction
 */
export async function verifyCiphertextCiphertextEquality(
    connection: Connection,
    payer: Signer,
    firstKeypair: ElGamalKeypair,
    secondPubkey: ElGamalPubkey,
    firstCiphertext: ElGamalCiphertext,
    secondCiphertext: ElGamalCiphertext,
    secondOpening: PedersenOpening,
    amount: bigint,
    contextStateInfo?: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    let transaction = new Transaction();
    let signers = [payer];
    if (contextStateInfo && contextStateInfo.keypair) {
        const accountSize = CIPHERTEXT_CIPHERTEXT_EQUALITY_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.keypair.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        )
        signers.push(contextStateInfo.keypair);
    }

    transaction.add(
        createVerifyCiphertextCiphertextEqualityInstruction(
            firstKeypair,
            secondPubkey,
            firstCiphertext,
            secondCiphertext,
            secondOpening,
            amount,
            contextStateInfo,
        )
    );
    return await sendAndConfirmTransaction(connection, transaction, signers, confirmOptions);
}

/**
 * Verify a ciphertext-commitment equality proof
 *
 * @param connection                Connection to use
 * @param payer                     Payer of the transaction fees
 * @param elgamalKeypair            ElGamal keypair associated with the ciphertext
 * @param elgamalCiphertext         ElGamal ciphertext to be proved
 * @param pedersenCommitment        Pedersen commitment to be proved
 * @param pedersenOpening           Pedersen opening for the Pedersen commitment
 * @param amount                    Amount that is encrypted and committed
 * @param contextStateInfo          Optional context state info
 * @param confirmOptions            Options for confirming the transaction
 *
 * @return Signature of the confirmed transaction
 */
export async function verifyCiphertextCommitmentEquality(
    connection: Connection,
    payer: Signer,
    elgamalKeypair: ElGamalKeypair,
    elgamalCiphertext: ElGamalCiphertext,
    pedersenCommitment: PedersenCommitment,
    pedersenOpening: PedersenOpening,
    amount: bigint,
    contextStateInfo?: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    let transaction = new Transaction();
    let signers = [payer];
    if (contextStateInfo && contextStateInfo.keypair) {
        const accountSize = CIPHERTEXT_COMMITMENT_EQUALITY_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.keypair.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        )
        signers.push(contextStateInfo.keypair);
    }

    transaction.add(
        createVerifyCiphertextCommitmentEqualityInstruction(
            elgamalKeypair,
            elgamalCiphertext,
            pedersenCommitment,
            pedersenOpening,
            amount,
            contextStateInfo,
        )
    );
    return await sendAndConfirmTransaction(connection, transaction, signers, confirmOptions);
}

/**
 * Verify an ElGamal public key validity proof
 *
 * @param connection                Connection to use
 * @param payer                     Payer of the transaction fees
 * @param elgamalKeypair            ElGamal keypair to be proved
 * @param contextStateInfo          Optional context state info
 * @param confirmOptions            Options for confirming the transaction
 *
 * @return Signature of the confirmed transaction
 */
export async function verifyPubkeyValidity(
    connection: Connection,
    payer: Signer,
    elgamalKeypair: ElGamalKeypair,
    contextStateInfo?: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    let transaction = new Transaction();
    let signers = [payer];
    if (contextStateInfo && contextStateInfo.keypair) {
        const accountSize = PUBKEY_VALIDITY_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.keypair.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        )
        signers.push(contextStateInfo.keypair);
    }

    transaction.add(
        createVerifyPubkeyValidityInstruction(
            elgamalKeypair,
            contextStateInfo,
        )
    );
    return await sendAndConfirmTransaction(connection, transaction, signers, confirmOptions);
}
