import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.js"],
    coverage: {
      provider: "v8",
      include: ["extension/detector/**", "extension/utils/extractor.js"],
      reporter: ["text", "json-summary"],
    },
  },
});
