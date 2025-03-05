import { expect } from 'chai';
import type { Connection, Signer } from '@solana/web3.js';
import { Keypair, sendAndConfirmTransaction, Transaction } from '@solana/web3.js';
import { newAccountWithLamports, getConnection } from './common';
import type { ContextStateInfo, RecordAccountInfo } from '../src';
import { closeContextStateProof, createVerifyPubkeyValidityInstruction, verifyPubkeyValidity } from '../src';
import { ElGamalKeypair, PubkeyValidityProofData } from '@solana/zk-sdk';
import { RECORD_META_DATA_SIZE, createInitializeWriteRecord, closeRecord } from '@solana/spl-record';

describe('pubkeyValidity', () => {
    let connection: Connection;
    let payer: Signer;
    let testElGamalKeypair: ElGamalKeypair;
    before(async () => {
        connection = await getConnection();
        payer = await newAccountWithLamports(connection, 1000000000);
        testElGamalKeypair = ElGamalKeypair.newRand();
    });

    it('verify proof data', async () => {
        const transaction = new Transaction().add(
            createVerifyPubkeyValidityInstruction({ elgamalKeypair: testElGamalKeypair }),
        );
        await sendAndConfirmTransaction(connection, transaction, [payer]);
    });

    it('read proof data record', async () => {
        const recordAccount = Keypair.generate();
        const recordAccountAddress = recordAccount.publicKey;
        const recordAuthority = Keypair.generate();

        const proofData = PubkeyValidityProofData.new(testElGamalKeypair);

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

        const transaction = new Transaction().add(createVerifyPubkeyValidityInstruction(recordAccountInfo));
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

        await verifyPubkeyValidity(connection, payer, { elgamalKeypair: testElGamalKeypair }, contextStateInfo);

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

        const proofData = PubkeyValidityProofData.new(testElGamalKeypair);

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

        await verifyPubkeyValidity(connection, payer, recordAccountInfo, contextStateInfo);

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
