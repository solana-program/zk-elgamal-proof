import { expect } from 'chai';
import type { Connection, Signer } from '@solana/web3.js';
import { Keypair, sendAndConfirmTransaction, Transaction } from '@solana/web3.js';
import { newAccountWithLamports, getConnection } from './common';
import type { ContextStateInfo, RecordAccountInfo } from '../src';
import {
    closeContextStateProof,
    createVerifyCiphertextCommitmentEqualityInstruction,
    verifyCiphertextCommitmentEquality,
} from '../src';
import type { ElGamalCiphertext, PedersenCommitment } from '@solana/zk-sdk';
import { ElGamalKeypair, Pedersen, PedersenOpening, CiphertextCommitmentEqualityProofData } from '@solana/zk-sdk';
import { RECORD_META_DATA_SIZE, createInitializeWriteRecord, closeRecord } from '@solana/spl-record';

describe('ciphertextCommitmentEquality', () => {
    let connection: Connection;
    let payer: Signer;

    let testElGamalKeypair: ElGamalKeypair;
    let testElGamalCiphertext: ElGamalCiphertext;
    let testPedersenCommitment: PedersenCommitment;
    let testPedersenOpening: PedersenOpening;
    let testAmount: bigint;

    before(async () => {
        connection = await getConnection();
        payer = await newAccountWithLamports(connection, 1000000000);
        testAmount = BigInt(10);

        testElGamalKeypair = ElGamalKeypair.newRand();
        const testElGamalPubkey = testElGamalKeypair.pubkeyOwned();
        testElGamalCiphertext = testElGamalPubkey.encryptU64(testAmount);

        testPedersenOpening = PedersenOpening.newRand();
        testPedersenCommitment = Pedersen.withU64(testAmount, testPedersenOpening);
    });

    it('verify proof data', async () => {
        const transaction = new Transaction().add(
            createVerifyCiphertextCommitmentEqualityInstruction({
                elgamalKeypair: testElGamalKeypair,
                elgamalCiphertext: testElGamalCiphertext,
                pedersenCommitment: testPedersenCommitment,
                pedersenOpening: testPedersenOpening,
                amount: testAmount,
            }),
        );
        await sendAndConfirmTransaction(connection, transaction, [payer]);
    });

    it('read proof data record', async () => {
        const recordAccount = Keypair.generate();
        const recordAccountAddress = recordAccount.publicKey;
        const recordAuthority = Keypair.generate();

        const proofData = CiphertextCommitmentEqualityProofData.new(
            testElGamalKeypair,
            testElGamalCiphertext,
            testPedersenCommitment,
            testPedersenOpening,
            testAmount,
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
            createVerifyCiphertextCommitmentEqualityInstruction(recordAccountInfo),
        );
        await sendAndConfirmTransaction(connection, transaction, [payer]);

        const destinationAccount = Keypair.generate();
        const destinationAccountAddress = destinationAccount.publicKey;

        await closeRecord(connection, payer, recordAccountAddress, recordAuthority, destinationAccountAddress);
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

        await verifyCiphertextCommitmentEquality(
            connection,
            payer,
            {
                elgamalKeypair: testElGamalKeypair,
                elgamalCiphertext: testElGamalCiphertext,
                pedersenCommitment: testPedersenCommitment,
                pedersenOpening: testPedersenOpening,
                amount: testAmount,
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

        const proofData = CiphertextCommitmentEqualityProofData.new(
            testElGamalKeypair,
            testElGamalCiphertext,
            testPedersenCommitment,
            testPedersenOpening,
            testAmount,
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

        await verifyCiphertextCommitmentEquality(connection, payer, recordAccountInfo, contextStateInfo);

        await closeRecord(connection, payer, recordAccountAddress, recordAuthority, destinationAccountAddress);

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
