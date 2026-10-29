import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// The build lands in ui/dist and is copied into the Python package by
// `make web`; the BFF serves it at "/" (same origin, same cookie).
export default defineConfig({
  plugins: [svelte()],
  server: {
    // `npm run dev` talks to a credarr-server started separately (make ui-dev);
    // CREDARR_API lets a second worktree point at its own port.
    proxy: { "/api": process.env.CREDARR_API ?? "http://127.0.0.1:8080" },
  },
});
