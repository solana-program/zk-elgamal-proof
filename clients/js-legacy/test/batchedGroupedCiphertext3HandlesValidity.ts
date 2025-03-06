import { expect } from 'chai';
import type { Connection, Signer } from '@solana/web3.js';
import { Keypair, sendAndConfirmTransaction, Transaction } from '@solana/web3.js';
import { newAccountWithLamports, getConnection } from './common';
import type { ContextStateInfo, RecordAccountInfo } from '../src';
import {
    closeContextStateProof,
    createVerifyBatchedGroupedCiphertext3HandlesValidityInstruction,
    verifyBatchedGroupedCiphertext3HandlesValidity,
} from '../src';
import type { ElGamalPubkey } from '@solana/zk-sdk';
import {
    ElGamalKeypair,
    PedersenOpening,
    BatchedGroupedCiphertext3HandlesValidityProofData,
    GroupedElGamalCiphertext3Handles,
} from '@solana/zk-sdk';
import { RECORD_META_DATA_SIZE, createInitializeWriteRecord, closeRecord } from '@solana/spl-record';

describe('batchedGroupedCiphertext2HandlesValidity', () => {
    let connection: Connection;
    let payer: Signer;

    let testFirstElGamalPubkey: ElGamalPubkey;
    let testSecondElGamalPubkey: ElGamalPubkey;
    let testThirdElGamalPubkey: ElGamalPubkey;
    let testGroupedCiphertextLo: GroupedElGamalCiphertext3Handles;
    let testGroupedCiphertextHi: GroupedElGamalCiphertext3Handles;
    let testAmountLo: bigint;
    let testAmountHi: bigint;
    let testOpeningLo: PedersenOpening;
    let testOpeningHi: PedersenOpening;

    before(async () => {
        connection = await getConnection();
        payer = await newAccountWithLamports(connection, 1000000000);
        testAmountLo = BigInt(10);
        testAmountHi = BigInt(10);

        const testFirstElGamalKeypair = ElGamalKeypair.newRand();
        testFirstElGamalPubkey = testFirstElGamalKeypair.pubkeyOwned();

        const testSecondElGamalKeypair = ElGamalKeypair.newRand();
        testSecondElGamalPubkey = testSecondElGamalKeypair.pubkeyOwned();

        const testThirdElGamalKeypair = ElGamalKeypair.newRand();
        testThirdElGamalPubkey = testThirdElGamalKeypair.pubkeyOwned();

        testOpeningLo = PedersenOpening.newRand();
        testOpeningHi = PedersenOpening.newRand();

        testGroupedCiphertextLo = GroupedElGamalCiphertext3Handles.encryptionWithU64(
            testFirstElGamalPubkey,
            testSecondElGamalPubkey,
            testThirdElGamalPubkey,
            testAmountLo,
            testOpeningLo,
        );

        testGroupedCiphertextHi = GroupedElGamalCiphertext3Handles.encryptionWithU64(
            testFirstElGamalPubkey,
            testSecondElGamalPubkey,
            testThirdElGamalPubkey,
            testAmountHi,
            testOpeningHi,
        );
    });

    it('verify proof data', async () => {
        const transaction = new Transaction().add(
            createVerifyBatchedGroupedCiphertext3HandlesValidityInstruction({
                firstPubkey: testFirstElGamalPubkey,
                secondPubkey: testSecondElGamalPubkey,
                thirdPubkey: testThirdElGamalPubkey,
                groupedCiphertextLo: testGroupedCiphertextLo,
                groupedCiphertextHi: testGroupedCiphertextHi,
                amountLo: testAmountLo,
                amountHi: testAmountHi,
                openingLo: testOpeningLo,
                openingHi: testOpeningHi,
            }),
        );
        await sendAndConfirmTransaction(connection, transaction, [payer]);
    });

    it('read proof data record', async () => {
        const recordAccount = Keypair.generate();
        const recordAccountAddress = recordAccount.publicKey;
        const recordAuthority = Keypair.generate();

        const proofData = BatchedGroupedCiphertext3HandlesValidityProofData.new(
            testFirstElGamalPubkey,
            testSecondElGamalPubkey,
            testThirdElGamalPubkey,
            testGroupedCiphertextLo,
            testGroupedCiphertextHi,
            testAmountLo,
            testAmountHi,
            testOpeningLo,
            testOpeningHi,
        );

        await createInitializeWriteRecord(
            connection,
            payer,
            recordAccount,
            recordAuthority,
            BigInt(0),
            proofData.toBytes(),
        );

        const recordAccountInfo: RecordAccountInfo = {
            account: recordAccountAddress,
            offset: RECORD_META_DATA_SIZE,
        };

        const transaction = new Transaction().add(
            createVerifyBatchedGroupedCiphertext3HandlesValidityInstruction(recordAccountInfo),
        );
        await sendAndConfirmTransaction(connection, transaction, [payer]);

        const destinationAccount = Keypair.generate();
        const destinationAccountAddress = destinationAccount.publicKey;

        await closeRecord(connection, payer, recordAccountAddress, recordAuthority, destinationAccountAddress);

        const closedRecordAccountInfo = await connection.getAccountInfo(recordAccountAddress);
        expect(closedRecordAccountInfo).to.equal(null);
    });

    it('verify, create, and close context', async () => {
        const contextState = Keypair.generate();
        const contextStateAddress = contextState.publicKey;
        const contextStateAuthority = Keypair.generate();
        const contextStateInfo: ContextStateInfo = {
            account: contextState,
            authority: contextStateAuthority.publicKey,
        };

        const destinationAccount = Keypair.generate();
        const destinationAccountAddress = destinationAccount.publicKey;

        await verifyBatchedGroupedCiphertext3HandlesValidity(
            connection,
            payer,
            {
                firstPubkey: testFirstElGamalPubkey,
                secondPubkey: testSecondElGamalPubkey,
                thirdPubkey: testThirdElGamalPubkey,
                groupedCiphertextLo: testGroupedCiphertextLo,
                groupedCiphertextHi: testGroupedCiphertextHi,
                amountLo: testAmountLo,
                amountHi: testAmountHi,
                openingLo: testOpeningLo,
                openingHi: testOpeningHi,
            },
            contextStateInfo,
        );

        const createdContextStateInfo = await connection.getAccountInfo(contextStateAddress);
        expect(createdContextStateInfo).to.not.equal(null);

        await closeContextStateProof(
            connection,
            payer,
            contextStateAddress,
            destinationAccountAddress,
            contextStateAuthority,
        );

        const closedContextStateInfo = await connection.getAccountInfo(contextStateAddress);
        expect(closedContextStateInfo).to.equal(null);
    });

    it('read proof data record and create context', async () => {
        const contextState = Keypair.generate();
        const contextStateAddress = contextState.publicKey;
        const contextStateAuthority = Keypair.generate();
        const contextStateInfo: ContextStateInfo = {
            account: contextState,
            authority: contextStateAuthority.publicKey,
        };

        const recordAccount = Keypair.generate();
        const recordAccountAddress = recordAccount.publicKey;
        const recordAuthority = Keypair.generate();

        const destinationAccount = Keypair.generate();
        const destinationAccountAddress = destinationAccount.publicKey;

        const proofData = BatchedGroupedCiphertext3HandlesValidityProofData.new(
            testFirstElGamalPubkey,
            testSecondElGamalPubkey,
            testThirdElGamalPubkey,
            testGroupedCiphertextLo,
            testGroupedCiphertextHi,
            testAmountLo,
            testAmountHi,
            testOpeningLo,
            testOpeningHi,
        );

        await createInitializeWriteRecord(
            connection,
            payer,
            recordAccount,
            recordAuthority,
            BigInt(0),
            proofData.toBytes(),
        );

        const recordAccountInfo: RecordAccountInfo = {
            account: recordAccountAddress,
            offset: RECORD_META_DATA_SIZE,
        };

        await verifyBatchedGroupedCiphertext3HandlesValidity(connection, payer, recordAccountInfo, contextStateInfo);

        await closeRecord(connection, payer, recordAccountAddress, recordAuthority, destinationAccountAddress);

        const closedRecordAccountInfo = await connection.getAccountInfo(recordAccountAddress);
        expect(closedRecordAccountInfo).to.equal(null);

        const createdContextStateInfo = await connection.getAccountInfo(contextStateAddress);
        expect(createdContextStateInfo).to.not.equal(null);

        await closeContextStateProof(
            connection,
            payer,
            contextStateAddress,
            destinationAccountAddress,
            contextStateAuthority,
        );

        const closedContextStateInfo = await connection.getAccountInfo(contextStateAddress);
        expect(closedContextStateInfo).to.equal(null);
    });
});
