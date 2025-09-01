use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn hello() -> String {
    "Hello, World!".to_string()
}

// TODO
// - Write all zdk relevant helpers here. Find all wasm-relevant functions and import them here and create [wasm-bindgen] functions (those get exported). Sub-issue for chunks of work to do (handling slices).
// - Testing strategy:
//    - compile down to node and run actual test suite (js tests) (purpose to ensure correctness of implementation)
// - Update examples to use a sample function (a few?) to ensure it compiles (purpose is to give external examples in a hello-world style)
// - CI/CD checks to run examples + tests and ensure they build
// - NPM publish CI/CD workflow (gabe likes changesets: https://github.com/solana-program/token-wrap/blob/main/.github/workflows/npm-publish.yml)
// - Create new JS client library (one or many?)
// - Three examples: bundler, web, node
// - Publish js library (export craziness) + CI/CD workflow (changesets)

// === Big, flash web application that does confidential transfers e2e ===
// - Add wallet connections
// - Add widget to see your own balances
// - Add actions to perform confidential transfer
// - Make design awesome
