import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: ".",
  testMatch: "*.browser.mjs",
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  reporter: "list",
  outputDir: "../../../test-results/console",
  use: {
    browserName: "chromium",
    headless: true,
    launchOptions: {
      executablePath: process.env.XEIP_CHROME_PATH || undefined,
    },
  },
});
