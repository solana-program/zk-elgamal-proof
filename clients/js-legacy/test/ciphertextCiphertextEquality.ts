import type { Connection, Signer } from '@solana/web3.js';
import { Keypair } from '@solana/web3.js';
import { newAccountWithLamports, getConnection } from './common';
import {
    closeContextStateProof,
    contextStateInfo,
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
        await verifyCiphertextCiphertextEquality(
            connection,
            payer,
            testFirstElGamalKeypair,
            testSecondElGamalPubkey,
            testFirstElGamalCiphertext,
            testSecondElGamalCiphertext,
            testSecondPedersenOpening,
            testAmount,
        );
    })

    it('verify, create, and close context', async () => {
        const contextState = Keypair.generate();
        const contextStateAddress = contextState.publicKey;
        const contextStateAuthority = Keypair.generate();
        const contextStateInfo: contextStateInfo = {
            keypair: contextState,
            address: contextStateAddress,
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

        await closeContextStateProof(
            connection,
            payer,
            contextStateAddress,
            contextStateAuthority,
            destinationAccountAddress,
        )
    })
})
