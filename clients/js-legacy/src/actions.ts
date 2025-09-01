import type { ConfirmOptions, Connection, Signer, TransactionSignature } from '@solana/web3.js';
import { PublicKey, sendAndConfirmTransaction, SystemProgram, Transaction } from '@solana/web3.js';
import type {
    BatchedGroupedCiphertext2HandlesValidityProofInput,
    BatchedGroupedCiphertext3HandlesValidityProofInput,
    ContextStateInfo,
    RecordAccountInfo,
    CiphertextCiphertextEqualityProofInput,
    CiphertextCommitmentEqualityProofInput,
    GroupedCiphertext2HandlesValidityProofInput,
    GroupedCiphertext3HandlesValidityProofInput,
    PubkeyValidityProofInput,
    ZeroCiphertextProofInput,
} from './instructions.js';
import {
    createCloseContextStateInstruction,
    createVerifyBatchedGroupedCiphertext2HandlesValidityInstruction,
    createVerifyBatchedGroupedCiphertext3HandlesValidityInstruction,
    createVerifyCiphertextCiphertextEqualityInstruction,
    createVerifyCiphertextCommitmentEqualityInstruction,
    createVerifyGroupedCiphertext2HandlesValidityInstruction,
    createVerifyGroupedCiphertext3HandlesValidityInstruction,
    createVerifyPubkeyValidityInstruction,
    createVerifyZeroCiphertextInstruction,
} from './instructions.js';
import {
    BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_CONTEXT_ACCOUNT_SIZE,
    BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_CONTEXT_ACCOUNT_SIZE,
    CIPHERTEXT_CIPHERTEXT_EQUALITY_CONTEXT_ACCOUNT_SIZE,
    CIPHERTEXT_COMMITMENT_EQUALITY_CONTEXT_ACCOUNT_SIZE,
    GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_CONTEXT_ACCOUNT_SIZE,
    GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_CONTEXT_ACCOUNT_SIZE,
    PUBKEY_VALIDITY_CONTEXT_ACCOUNT_SIZE,
    ZERO_CIPHERTEXT_CONTEXT_ACCOUNT_SIZE,
    ZK_ELGAMAL_PROOF_PROGRAM_ID,
} from './constants.js';

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
        ),
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
    proofInput: ZeroCiphertextProofInput | RecordAccountInfo,
    contextStateInfo: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    const transaction = new Transaction();
    const signers = [payer];
    if (contextStateInfo && !(contextStateInfo.account instanceof PublicKey)) {
        const accountSize = ZERO_CIPHERTEXT_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.account.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        );
        signers.push(contextStateInfo.account);
    }

    transaction.add(createVerifyZeroCiphertextInstruction(proofInput, contextStateInfo, programId));
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
    proofInput: CiphertextCiphertextEqualityProofInput | RecordAccountInfo,
    contextStateInfo: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    const transaction = new Transaction();
    const signers = [payer];
    if (contextStateInfo && !(contextStateInfo.account instanceof PublicKey)) {
        const accountSize = CIPHERTEXT_CIPHERTEXT_EQUALITY_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.account.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        );
        signers.push(contextStateInfo.account);
    }

    transaction.add(createVerifyCiphertextCiphertextEqualityInstruction(proofInput, contextStateInfo));
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
    proofInput: CiphertextCommitmentEqualityProofInput | RecordAccountInfo,
    contextStateInfo: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    const transaction = new Transaction();
    const signers = [payer];
    if (contextStateInfo && !(contextStateInfo.account instanceof PublicKey)) {
        const accountSize = CIPHERTEXT_COMMITMENT_EQUALITY_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.account.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        );
        signers.push(contextStateInfo.account);
    }

    transaction.add(createVerifyCiphertextCommitmentEqualityInstruction(proofInput, contextStateInfo));
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
    proofInput: PubkeyValidityProofInput | RecordAccountInfo,
    contextStateInfo: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    const transaction = new Transaction();
    const signers = [payer];
    if (contextStateInfo && !(contextStateInfo.account instanceof PublicKey)) {
        const accountSize = PUBKEY_VALIDITY_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.account.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        );
        signers.push(contextStateInfo.account);
    }

    transaction.add(createVerifyPubkeyValidityInstruction(proofInput, contextStateInfo));
    return await sendAndConfirmTransaction(connection, transaction, signers, confirmOptions);
}

export async function verifyGroupedCiphertext2HandlesValidity(
    connection: Connection,
    payer: Signer,
    proofInput: GroupedCiphertext2HandlesValidityProofInput | RecordAccountInfo,
    contextStateInfo: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    const transaction = new Transaction();
    const signers = [payer];
    if (contextStateInfo && !(contextStateInfo.account instanceof PublicKey)) {
        const accountSize = GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.account.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        );
        signers.push(contextStateInfo.account);
    }

    transaction.add(createVerifyGroupedCiphertext2HandlesValidityInstruction(proofInput, contextStateInfo));
    return await sendAndConfirmTransaction(connection, transaction, signers, confirmOptions);
}

export async function verifyGroupedCiphertext3HandlesValidity(
    connection: Connection,
    payer: Signer,
    proofInput: GroupedCiphertext3HandlesValidityProofInput | RecordAccountInfo,
    contextStateInfo: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    const transaction = new Transaction();
    const signers = [payer];
    if (contextStateInfo && !(contextStateInfo.account instanceof PublicKey)) {
        const accountSize = GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.account.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        );
        signers.push(contextStateInfo.account);
    }

    transaction.add(createVerifyGroupedCiphertext3HandlesValidityInstruction(proofInput, contextStateInfo));
    return await sendAndConfirmTransaction(connection, transaction, signers, confirmOptions);
}

export async function verifyBatchedGroupedCiphertext2HandlesValidity(
    connection: Connection,
    payer: Signer,
    proofInput: BatchedGroupedCiphertext2HandlesValidityProofInput | RecordAccountInfo,
    contextStateInfo: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    const transaction = new Transaction();
    const signers = [payer];
    if (contextStateInfo && !(contextStateInfo.account instanceof PublicKey)) {
        const accountSize = BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.account.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        );
        signers.push(contextStateInfo.account);
    }

    transaction.add(createVerifyBatchedGroupedCiphertext2HandlesValidityInstruction(proofInput, contextStateInfo));
    return await sendAndConfirmTransaction(connection, transaction, signers, confirmOptions);
}

export async function verifyBatchedGroupedCiphertext3HandlesValidity(
    connection: Connection,
    payer: Signer,
    proofInput: BatchedGroupedCiphertext3HandlesValidityProofInput | RecordAccountInfo,
    contextStateInfo: ContextStateInfo,
    confirmOptions?: ConfirmOptions,
    programId = ZK_ELGAMAL_PROOF_PROGRAM_ID,
): Promise<TransactionSignature> {
    const transaction = new Transaction();
    const signers = [payer];
    if (contextStateInfo && !(contextStateInfo.account instanceof PublicKey)) {
        const accountSize = BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_CONTEXT_ACCOUNT_SIZE;
        const lamports = await connection.getMinimumBalanceForRentExemption(accountSize);

        transaction.add(
            SystemProgram.createAccount({
                fromPubkey: payer.publicKey,
                newAccountPubkey: contextStateInfo.account.publicKey,
                space: accountSize,
                lamports,
                programId,
            }),
        );
        signers.push(contextStateInfo.account);
    }

    transaction.add(createVerifyBatchedGroupedCiphertext3HandlesValidityInstruction(proofInput, contextStateInfo));
    return await sendAndConfirmTransaction(connection, transaction, signers, confirmOptions);
}
