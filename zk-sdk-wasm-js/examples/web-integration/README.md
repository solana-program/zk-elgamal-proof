## How to Run

You must first build the WASM artifacts. From the root directory of the WASM crate (`zk-sdk-wasm-js`):

```bash
make -C ../../.. build-wasm-js-zk-sdk-wasm-js
```

Install the dependencies:

```bash
pnpm install
```

Run the test server:

```bash
pnpm start
```

Open your web browser and navigate to the address shown in the terminal.
