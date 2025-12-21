import { defineConfig } from "vite";
import wasm from "vite-plugin-wasm";

export default defineConfig({
  plugins: [wasm()],
  server: {
    port: 8081,
  },
  build: {
    target: "esnext",
  },
  optimizeDeps: {
    exclude: ["@solana/zk-sdk"],
  },
});
