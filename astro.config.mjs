// @ts-check
import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import react from "@astrojs/react";
import { siteConfig } from "./config/site.ts";

// https://astro.build/config
export default defineConfig({
  site: siteConfig.siteUrl,
  base: siteConfig.basePath,
  trailingSlash: "never",
  output: "static",
  vite: {
    plugins: [tailwindcss()],
  },
  integrations: [react()],
});
