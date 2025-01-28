import { expect } from 'chai';
import type { Connection, Signer } from '@solana/web3.js';
import { Keypair, sendAndConfirmTransaction, Transaction } from '@solana/web3.js';
import { newAccountWithLamports, getConnection } from './common';
import {
    closeContextStateProof,
    createVerifyCiphertextCiphertextEqualityInstruction,
    ContextStateInfo,
    verifyCiphertextCiphertextEquality,
} from '../src';
import { ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey, PedersenOpening } from '@solana/zk-sdk';

describe('ciphertextCiphertextEquality', () => {
    let connection: Connection;
    let payer: Signer;

    let testFirstElGamalKeypair: ElGamalKeypair;
    let testSecondElGamalPubkey: ElGamalPubkey;
    let testFirstElGamalCiphertext: ElGamalCiphertext;
    let testSecondElGamalCiphertext: ElGamalCiphertext;
    let testSecondPedersenOpening: PedersenOpening;
    let testAmount: bigint;

    before(async () => {
        connection = await getConnection();
        payer = await newAccountWithLamports(connection, 1000000000);
        testAmount = BigInt(10);

        testFirstElGamalKeypair = ElGamalKeypair.newRand();
        const testFirstElGamalPubkey = testFirstElGamalKeypair.pubkeyOwned();
        testFirstElGamalCiphertext = testFirstElGamalPubkey.encryptU64(testAmount);

        const testSecondElGamalKeypair = ElGamalKeypair.newRand();
        testSecondElGamalPubkey = testSecondElGamalKeypair.pubkeyOwned();
        testSecondPedersenOpening = PedersenOpening.newRand();
        testSecondElGamalCiphertext = testSecondElGamalPubkey.encryptWithU64(
            testAmount,
            testSecondPedersenOpening
        );
    })

    it('verify proof data', async () => {
        let transaction = new Transaction().add(
            createVerifyCiphertextCiphertextEqualityInstruction(
                testFirstElGamalKeypair,
                testSecondElGamalPubkey,
                testFirstElGamalCiphertext,
                testSecondElGamalCiphertext,
                testSecondPedersenOpening,
                testAmount,
            )
        );
        await sendAndConfirmTransaction(connection, transaction, [payer]);
    })

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

        await verifyCiphertextCiphertextEquality(
            connection,
            payer,
            testFirstElGamalKeypair,
            testSecondElGamalPubkey,
            testFirstElGamalCiphertext,
            testSecondElGamalCiphertext,
            testSecondPedersenOpening,
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
        )

        const closedContextStateInfo = await connection.getAccountInfo(contextStateAddress);
        expect(closedContextStateInfo).to.equal(null);
    })
})
