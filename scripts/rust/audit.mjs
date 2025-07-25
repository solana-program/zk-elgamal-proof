#!/usr/bin/env zx
import 'zx/globals';

const advisories = [
    // ed25519-dalek: Double Public Key Signing Function Oracle Attack
    //
    // Remove once repo upgrades to ed25519-dalek v2
    'RUSTSEC-2022-0093',

    // curve25519-dalek
    //
    // Remove once repo upgrades to curve25519-dalek v4
    'RUSTSEC-2024-0344',
];
const ignores = []
advisories.forEach(x => {
    ignores.push('--ignore');
    ignores.push(x);
});

// Check Solana version.
await $`cargo audit ${ignores}`;
