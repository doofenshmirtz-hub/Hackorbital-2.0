import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  base: "/Hackorbital-2.0/",
  plugins: [react(), tailwindcss()],
  server: { host: "0.0.0.0" },
});
