## How to Run

Native ESM (`"type": "module"`) counterpart of `../node-integration`. It covers the
imports a Node ESM consumer actually writes: the root `@solana/zk-sdk` specifier, and
`@solana/zk-sdk/bundler` as imported by packages like `@solana-program/token-2022`.

You must first build the WASM artifacts. From the root directory of the WASM crate (`zk-sdk-wasm-js`):

```bash
make -C ../../.. build-wasm-js-zk-sdk-wasm-js
```

Install the dependencies:

```bash
pnpm install
```

Run the test script:

```bash
pnpm test
```
