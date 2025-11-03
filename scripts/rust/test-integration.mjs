#!/usr/bin/env zx
import "zx/globals";
import { cliArguments, workingDirectory } from "../utils.mjs";

const [folder, ...args] = cliArguments();
const cratePath = path.join(workingDirectory, folder);
const examplesPath = path.join(cratePath, "examples");

console.log(chalk.blue("\n--- Checking prerequisites ---"));
if (!fs.existsSync(path.join(cratePath, "dist"))) {
  console.error(
    chalk.red(
      "Error: 'dist' directory not found. The build step (pnpm zk-sdk-wasm-js:build-wasm) must run first.",
    ),
  );
  process.exit(1);
}
console.log(chalk.green("✅ Wasm artifacts found."));

console.log(chalk.blue("\n--- Installing dependencies for examples ---"));

const examples = [
  "node-integration",
  "web-integration",
  "vite-integration",
  "webpack-integration",
];
for (const example of examples) {
  console.log(chalk.yellow(`Installing dependencies for ${example}...`));
  await $`pnpm install --dir ${path.join(examplesPath, example)}`;
}

console.log(chalk.blue("\n--- Running Node.js integration test ---"));
try {
  await $`pnpm test --dir ${path.join(examplesPath, "node-integration")}`;
  console.log(chalk.green("✅ Node.js integration test passed."));
} catch (error) {
  console.error(chalk.red("❌ Node.js integration test failed."));
  process.exit(1);
}

console.log(
  chalk.blue("\n--- Running Browser integration tests (Playwright) ---"),
);

console.log(
  chalk.yellow(
    "Installing Playwright browsers (Chromium) and system dependencies...",
  ),
);

await $`pnpm exec playwright install --with-deps`;

console.log(chalk.yellow("Starting servers and running Playwright tests..."));
try {
  await $`pnpm exec playwright test --config ${path.join(examplesPath, "playwright.config.js")}`;
  console.log(chalk.green("✅ Browser integration tests passed."));
} catch (error) {
  console.error(chalk.red("❌ Browser integration tests failed."));
  process.exit(1);
}

console.log(chalk.green("\n🎉 All integration tests passed!"));
