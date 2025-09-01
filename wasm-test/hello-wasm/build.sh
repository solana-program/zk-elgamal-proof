#!/bin/sh
# This script will exit immediately if any command fails.
set -e

# 1. Clean up previous build artifacts
echo "--- Cleaning up old builds ---"
rm -rf dist pkg-node pkg-web pkg-bundler

# 2. Build for each target using wasm-pack
echo "--- Building for Node.js, Web, and Bundler targets ---"
wasm-pack build --target nodejs --out-dir pkg-node
wasm-pack build --target web --out-dir pkg-web
wasm-pack build --target bundler --out-dir pkg-bundler

# 3. Create the final 'dist' directory structure
echo "--- Creating final dist directory ---"
mkdir -p dist/node dist/web dist/bundler

# 4. Copy Node.js artifacts
echo "--- Copying Node.js files ---"
cp pkg-node/hello_wasm.js dist/node/index.cjs
cp pkg-node/hello_wasm_bg.wasm dist/node/hello_wasm_bg.wasm
cp pkg-node/hello_wasm.d.ts dist/node/index.d.ts

# 5. Copy Web artifacts
echo "--- Copying Web files ---"
cp pkg-web/hello_wasm.js dist/web/index.js
cp pkg-web/hello_wasm_bg.wasm dist/web/hello_wasm_bg.wasm
cp pkg-web/hello_wasm.d.ts dist/web/index.d.ts

# 6. Copy Bundler artifacts
echo "--- Copying Bundler files ---"
cp pkg-bundler/hello_wasm.js dist/bundler/index.js
cp pkg-bundler/hello_wasm_bg.wasm dist/bundler/hello_wasm_bg.wasm
cp pkg-bundler/hello_wasm.d.ts dist/bundler/index.d.ts
cp pkg-bundler/hello_wasm_bg.js dist/bundler/hello_wasm_bg.js

echo "--- Build complete! ---"
