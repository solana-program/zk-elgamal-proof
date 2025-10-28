import { test, expect } from "@playwright/test";

async function checkWasmStatus(page) {
  const status = page.locator("#status");

  await expect(status).not.toHaveClass("running", { timeout: 20000 });

  if (await status.evaluate((el) => el.classList.contains("failure"))) {
    const logs = await page.locator("#logs").textContent();
    const message = await status.textContent();
    throw new Error(
      `❌ Wasm integration tests failed: ${message}\n--- Logs ---\n${logs}`,
    );
  }

  await expect(status).toHaveClass("success");
}

test.describe("Wasm Integration Tests", () => {
  test("Web (Static Server) @ 8080", async ({ page }) => {
    await page.goto("http://localhost:8080");
    await checkWasmStatus(page);
  });

  test("Vite (Bundler) @ 8081", async ({ page }) => {
    await page.goto("http://localhost:8081");
    await checkWasmStatus(page);
  });

  test("Webpack (Bundler) @ 8082", async ({ page }) => {
    await page.goto("http://localhost:8082");
    await checkWasmStatus(page);
  });
});
