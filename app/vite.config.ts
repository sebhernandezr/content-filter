import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Fixed port: tauri.conf.json's devUrl points at it, and Tauri fails rather than silently
  // loading the wrong thing if it moves.
  server: { port: 1420, strictPort: true },
  build: { outDir: "dist", emptyOutDir: true, target: "safari15" },
  clearScreen: false,
});
