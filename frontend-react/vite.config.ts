import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During dev, proxy the API to the backend so the app can use same-origin /api calls.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/health": "http://localhost:8000",
    },
  },
  build: { outDir: "dist" },
});
