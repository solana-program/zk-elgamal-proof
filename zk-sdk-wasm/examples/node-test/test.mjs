import * as wasmModule from 'hello-wasm-universal/node';

const message = wasmModule.hello();

console.log(message);

