import type { APIRoute } from "astro";
import { siteConfig } from "../../config/site";
import { getCveIndex } from "../lib/data";

const CHUNK_SIZE = 40000;

export const GET: APIRoute = () => {
  const base = siteConfig.siteUrl.replace(/\/$/, "") + siteConfig.basePath.replace(/\/$/, "");
  const totalCves = Object.keys(getCveIndex()).length;
  // chunk 0 always exists (static pages, years, CWEs, vendors, and CVEs overflow);
  // additional chunks exist only for CVE overflow beyond what fits in chunk 0.
  const cveChunks = Math.max(1, Math.ceil(totalCves / CHUNK_SIZE));

  const sitemaps = Array.from({ length: cveChunks }, (_, i) => `${base}/sitemap-${i}.xml`);

  const body = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${sitemaps.map((u) => `  <sitemap><loc>${u}</loc></sitemap>`).join("\n")}
</sitemapindex>
`;

  return new Response(body, { headers: { "Content-Type": "application/xml" } });
};
