import type { APIRoute } from "astro";
import { siteConfig } from "../../config/site";
import { getCveIndex, getYearIndex, getCweIndex, getVendorIndex } from "../lib/data";

const CHUNK_SIZE = 40000;

export function getStaticPaths() {
  const totalCves = Object.keys(getCveIndex()).length;
  const cveChunks = Math.max(1, Math.ceil(totalCves / CHUNK_SIZE));
  return Array.from({ length: cveChunks }, (_, i) => ({ params: { chunk: String(i) } }));
}

export const GET: APIRoute = ({ params }) => {
  const chunk = Number(params.chunk ?? "0");
  const base = siteConfig.siteUrl.replace(/\/$/, "") + siteConfig.basePath.replace(/\/$/, "");
  const cveIndex = getCveIndex();
  const allCveIds = Object.keys(cveIndex);

  let urls: string[] = [];

  if (chunk === 0) {
    const staticPaths = ["/", "/search", "/cves", "/statistics", "/downloads", "/about"];
    const years = Object.keys(getYearIndex());
    const cwes = Object.keys(getCweIndex());
    const vendors = Object.keys(getVendorIndex()).slice(0, 5000);
    urls.push(
      ...staticPaths.map((p) => `${base}${p}`),
      ...years.map((y) => `${base}/year/${y}`),
      ...cwes.map((c) => `${base}/cwe/${c}`),
      ...vendors.filter((v) => !v.includes("/")).map((v) => `${base}/vendor/${encodeURIComponent(v)}`),
    );
  }

  const remainingCapacity = CHUNK_SIZE - urls.length;
  const cveSliceStart = chunk * CHUNK_SIZE;
  const cveIds = chunk === 0 ? allCveIds.slice(0, remainingCapacity) : allCveIds.slice(cveSliceStart, cveSliceStart + CHUNK_SIZE);
  urls.push(...cveIds.map((id) => `${base}/cve/${id}`));

  const body = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `  <url><loc>${u}</loc></url>`).join("\n")}
</urlset>
`;

  return new Response(body, { headers: { "Content-Type": "application/xml" } });
};
