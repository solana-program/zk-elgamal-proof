const { Keypair } = require('@solana/web3.js');
const { createCloseContextStateInstruction } = require('../../lib/cjs/index.js');

const contextStateAddress = Keypair.generate().publicKey;
const destinationAccount = Keypair.generate().publicKey;
const contextStateAuthority = Keypair.generate().publicKey;

createCloseContextStateInstruction(contextStateAddress, destinationAccount, contextStateAuthority);
