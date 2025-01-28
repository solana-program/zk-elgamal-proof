import { expect } from 'chai';
import type { Connection, Signer } from '@solana/web3.js';
import { Keypair, sendAndConfirmTransaction, Transaction } from '@solana/web3.js';
import { newAccountWithLamports, getConnection } from './common';
import type { ContextStateInfo } from '../src';
import {
    closeContextStateProof,
    createVerifyCiphertextCommitmentEqualityInstruction,
    verifyCiphertextCommitmentEquality,
} from '../src';
import type { ElGamalCiphertext, PedersenCommitment } from '@solana/zk-sdk';
import { ElGamalKeypair, Pedersen, PedersenOpening } from '@solana/zk-sdk';

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
            createVerifyCiphertextCommitmentEqualityInstruction(
                testElGamalKeypair,
                testElGamalCiphertext,
                testPedersenCommitment,
                testPedersenOpening,
                testAmount,
            ),
        );
        await sendAndConfirmTransaction(connection, transaction, [payer]);
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
            testElGamalKeypair,
            testElGamalCiphertext,
            testPedersenCommitment,
            testPedersenOpening,
            testAmount,
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
});
