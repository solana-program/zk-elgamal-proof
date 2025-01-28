import { expect } from 'chai';
import type { Connection, Signer } from '@solana/web3.js';
import { Keypair } from '@solana/web3.js';
import { newAccountWithLamports, getConnection } from './common';
import {
    closeContextStateProof,
    ContextStateInfo,
    verifyPubkeyValidity,
} from '../src';
import { ElGamalKeypair } from '@solana/zk-sdk';

describe('pubkeyValidity', () => {
    let connection: Connection;
    let payer: Signer;
    let testElGamalKeypair: ElGamalKeypair;
    before(async () => {
        connection = await getConnection();
        payer = await newAccountWithLamports(connection, 1000000000);
        testElGamalKeypair = ElGamalKeypair.newRand();
    })

    it('verify proof data', async () => {
        await verifyPubkeyValidity(connection, payer, testElGamalKeypair);
    })

    it('verify, create, and close context', async () => {
        const contextState = Keypair.generate();
        const contextStateAddress = contextState.publicKey;
        const contextStateAuthority = Keypair.generate();
        const contextStateInfo: ContextStateInfo = {
            keypair: contextState,
            address: contextStateAddress,
            authority: contextStateAuthority.publicKey,
        };

        const destinationAccount = Keypair.generate();
        const destinationAccountAddress = destinationAccount.publicKey;

        await verifyPubkeyValidity(
            connection,
            payer,
            testElGamalKeypair,
            contextStateInfo
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
