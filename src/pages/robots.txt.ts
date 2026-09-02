import type { APIRoute } from "astro";
import { siteConfig } from "../../config/site";

export const GET: APIRoute = () => {
  const base = siteConfig.siteUrl.replace(/\/$/, "") + siteConfig.basePath.replace(/\/$/, "");
  const body = `User-agent: *
Allow: /

Sitemap: ${base}/sitemap.xml
`;
  return new Response(body, { headers: { "Content-Type": "text/plain" } });
};
