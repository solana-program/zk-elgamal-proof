import { expect } from 'chai';
import type { Connection, Signer } from '@solana/web3.js';
import { Keypair, sendAndConfirmTransaction, Transaction } from '@solana/web3.js';
import { newAccountWithLamports, getConnection } from './common';
import type { ContextStateInfo, RecordAccountInfo } from '../src';
import {
    closeContextStateProof,
    createVerifyGroupedCiphertext2HandlesValidityInstruction,
    verifyGroupedCiphertext2HandlesValidity,
} from '../src';
import type { ElGamalPubkey } from '@solana/zk-sdk';
import {
    ElGamalKeypair,
    PedersenOpening,
    GroupedCiphertext2HandlesValidityProofData,
    GroupedElGamalCiphertext2Handles,
} from '@solana/zk-sdk';
import { RECORD_META_DATA_SIZE, createInitializeWriteRecord, closeRecord } from '@solana/spl-record';

describe('groupedCiphertext2HandlesValidity', () => {
    let connection: Connection;
    let payer: Signer;

    let testFirstElGamalPubkey: ElGamalPubkey;
    let testSecondElGamalPubkey: ElGamalPubkey;
    let testGroupedCiphertext: GroupedElGamalCiphertext2Handles;
    let testAmount: bigint;
    let testOpening: PedersenOpening;

    before(async () => {
        connection = await getConnection();
        payer = await newAccountWithLamports(connection, 1000000000);
        testAmount = BigInt(10);

        const testFirstElGamalKeypair = ElGamalKeypair.newRand();
        testFirstElGamalPubkey = testFirstElGamalKeypair.pubkeyOwned();

        const testSecondElGamalKeypair = ElGamalKeypair.newRand();
        testSecondElGamalPubkey = testSecondElGamalKeypair.pubkeyOwned();

        testOpening = PedersenOpening.newRand();

        testGroupedCiphertext = GroupedElGamalCiphertext2Handles.encryptionWithU64(
            testFirstElGamalPubkey,
            testSecondElGamalPubkey,
            testAmount,
            testOpening,
        );
    });

    it('verify proof data', async () => {
        const transaction = new Transaction().add(
            createVerifyGroupedCiphertext2HandlesValidityInstruction({
                firstPubkey: testFirstElGamalPubkey,
                secondPubkey: testSecondElGamalPubkey,
                groupedCiphertext: testGroupedCiphertext,
                amount: testAmount,
                opening: testOpening,
            }),
        );
        await sendAndConfirmTransaction(connection, transaction, [payer]);
    });

    it('read proof data record', async () => {
        const recordAccount = Keypair.generate();
        const recordAccountAddress = recordAccount.publicKey;
        const recordAuthority = Keypair.generate();

        const proofData = GroupedCiphertext2HandlesValidityProofData.new(
            testFirstElGamalPubkey,
            testSecondElGamalPubkey,
            testGroupedCiphertext,
            testAmount,
            testOpening,
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
            createVerifyGroupedCiphertext2HandlesValidityInstruction(recordAccountInfo),
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

        await verifyGroupedCiphertext2HandlesValidity(
            connection,
            payer,
            {
                firstPubkey: testFirstElGamalPubkey,
                secondPubkey: testSecondElGamalPubkey,
                groupedCiphertext: testGroupedCiphertext,
                amount: testAmount,
                opening: testOpening,
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

        const proofData = GroupedCiphertext2HandlesValidityProofData.new(
            testFirstElGamalPubkey,
            testSecondElGamalPubkey,
            testGroupedCiphertext,
            testAmount,
            testOpening,
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

        await verifyGroupedCiphertext2HandlesValidity(connection, payer, recordAccountInfo, contextStateInfo);

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
