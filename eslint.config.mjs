import js from "@eslint/js";

export default [
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "coverage/**",
      "planning/**",
      "vendor/**",
      // Ignored immutable review copies and local toolchain workspaces are not source.
      "tmp/**",
      "artifacts/verification/**",
      "artifacts/review/**",
      "artifacts/sbom/**",
      "artifacts/license-report/**"
    ]
  },
  js.configs.recommended,
  {
    files: ["**/*.cjs"],
    languageOptions: {
      globals: {
        module: "readonly",
        require: "readonly",
        __dirname: "readonly"
      }
    }
  },
  {
    files: ["**/*.mjs", "**/*.cjs", "**/*.js"],
    languageOptions: { ecmaVersion: 2024, sourceType: "module" },
    rules: {
      "no-console": "error",
      "no-eval": "error",
      "no-implied-eval": "error"
    }
  }
];
