import { defineConfig, devices } from "@playwright/test";
import path from "path";

const defineServer = (command, port) => ({
  command,
  url: `http://localhost:${port}`,
  reuseExistingServer: !process.env.CI,
  waitForNavigation: true,
});

const examplePath = (name) => path.resolve(__dirname, name);

export default defineConfig({
  testDir: ".",
  testMatch: ["*.spec.js"],
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: "list",

  webServer: [
    defineServer(`pnpm --dir ${examplePath("web-integration")} start`, 8080),
    defineServer(`pnpm --dir ${examplePath("vite-integration")} start`, 8081),
    defineServer(
      `pnpm --dir ${examplePath("webpack-integration")} start`,
      8082,
    ),
  ],

  use: {
    trace: "on-first-retry",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
