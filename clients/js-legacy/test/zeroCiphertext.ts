import { expect } from 'chai';
import type { Connection, Signer } from '@solana/web3.js';
import { Keypair } from '@solana/web3.js';
import { newAccountWithLamports, getConnection } from './common';
import {
    closeContextStateProof,
    contextStateInfo,
    verifyZeroCiphertext,
} from '../src';
import { ElGamalCiphertext, ElGamalKeypair } from '@solana/zk-sdk';

describe('zeroCiphertext', () => {
    let connection: Connection;
    let payer: Signer;

    let testElGamalKeypair: ElGamalKeypair;
    let testElGamalCiphertext: ElGamalCiphertext;

    before(async () => {
        connection = await getConnection();
        payer = await newAccountWithLamports(connection, 1000000000);

        testElGamalKeypair = ElGamalKeypair.newRand();
        const testElGamalPubkey = testElGamalKeypair.pubkeyOwned();
        testElGamalCiphertext = testElGamalPubkey.encryptU64(BigInt(0));
    })

    it('verify proof data', async () => {
        await verifyZeroCiphertext(
            connection,
            payer,
            testElGamalKeypair,
            testElGamalCiphertext
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

        await verifyZeroCiphertext(
            connection,
            payer,
            testElGamalKeypair,
            testElGamalCiphertext,
            contextStateInfo
        );

        const createdContextStateInfo = await connection.getAccountInfo(contextStateAddress);
        expect(createdContextStateInfo).to.not.equal(null);

        await closeContextStateProof(
            connection,
            payer,
            contextStateAddress,
            contextStateAuthority,
            destinationAccountAddress,
        )

        const closedContextStateInfo = await connection.getAccountInfo(contextStateAddress);
        expect(closedContextStateInfo).to.equal(null);
    })
})
