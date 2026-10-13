// Depot-owned ESLint configuration: the PROJECT's config and plugins are never loaded.
// Installed by the depot at pinned versions (policy/tool-registry.yml node_tools) and mounted read-only into the sandbox.
import js from "@eslint/js";
import security from "eslint-plugin-security";
export default [
  { ignores: ["**/node_modules/**", "**/dist/**", "**/build/**", "**/.next/**", "**/*.min.js", "**/coverage/**"] },
  { files: ["**/*.{js,mjs,cjs,jsx,ts,tsx}"], languageOptions: { ecmaVersion: "latest", sourceType: "module", globals: {} },
    plugins: { security }, rules: { ...security.configs.recommended.rules } },
];
