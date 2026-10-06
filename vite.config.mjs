import { defineConfig } from "vite";

export default defineConfig({
    root: "web",
    build: { outDir: "../dist", emptyOutDir: true, sourcemap: false },
    server: { proxy: { "/api": "http://127.0.0.1:5329" } },
    preview: { proxy: { "/api": "http://127.0.0.1:5329" } },
});
