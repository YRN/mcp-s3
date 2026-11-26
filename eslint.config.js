// @ts-check
import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig(
  globalIgnores(["dist/", "coverage/", "node_modules/"]),

  js.configs.recommended,
  tseslint.configs.strictTypeChecked,

  {
    languageOptions: {
      parserOptions: {
        // src/ uses tsconfig.json, test/ uses test/tsconfig.json (nearest tsconfig wins).
        projectService: {
          allowDefaultProject: ["vitest.config.ts"],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // stdout is reserved for the MCP stdio protocol (PLAN.md section 8).
      "no-console": ["error", { allow: ["error"] }],
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true }],
    },
  },

  {
    // Plain JS config files: no type information available.
    files: ["**/*.js", "**/*.mjs", "**/*.cjs"],
    extends: [tseslint.configs.disableTypeChecked],
  },
);
