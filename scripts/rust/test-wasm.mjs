#!/usr/bin/env zx
import "zx/globals";
import { cliArguments, workingDirectory } from "../utils.mjs";

const [folder, ...args] = cliArguments();
const cratePath = path.join(workingDirectory, folder);

await $`wasm-pack test --node ${cratePath} ${args}`;
await $`wasm-pack test --headless --firefox ${cratePath} ${args} --features test-browser`;
await $`wasm-pack test --headless --chrome ${cratePath} ${args} --features test-browser`;
