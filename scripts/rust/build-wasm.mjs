#!/usr/bin/env zx
import 'zx/globals';
import {
    cliArguments,
    workingDirectory,
} from '../utils.mjs';

const [folder, ...args] = cliArguments();

if (folder === 'zk-sdk-wasm-js') {
  const cratePath = path.join(workingDirectory, folder);
  const compileScriptPath = path.join(cratePath, 'compile-wasm.sh');
  await $`chmod +x ${compileScriptPath}`;
  await within(async () => {
    cd(cratePath);
    await $`./compile-wasm.sh`;
  });
} else {
  const manifestPath = path.join(workingDirectory, folder, 'Cargo.toml');
  await $`cargo build --target wasm32-unknown-unknown --manifest-path ${manifestPath} ${args}`;
}
