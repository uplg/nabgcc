import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite";

export default defineConfig({
  // Relative paths: the build works from any directory it is served from.
  base: "./",
  plugins: [svelte()],
  worker: { format: "es" },
});
