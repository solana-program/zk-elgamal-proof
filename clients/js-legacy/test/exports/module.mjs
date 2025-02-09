// This ensures that we do not rely on `__dirname` in ES modules even when it is polyfilled.
globalThis.__dirname = 'DO_NOT_USE';

import { Keypair } from '@solana/web3.js';
import { createCloseContextStateInstruction } from '../../lib/esm/index.js';

const contextStateAddress = Keypair.generate().publicKey;
const destinationAccount = Keypair.generate().publicKey;
const contextStateAuthority = Keypair.generate().publicKey;

createCloseContextStateInstruction(contextStateAddress, destinationAccount, contextStateAuthority);
