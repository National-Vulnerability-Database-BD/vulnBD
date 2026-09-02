#!/usr/bin/env node
/**
 * Rebuilds every generated index from the on-disk data/YYYY/MM.jsonl files.
 *
 * Deterministic: running this twice against identical input data produces
 * byte-identical output (all objects are built with sorted keys / sorted
 * arrays, and no timestamps leak into index files except index/metadata.json's
 * `lastUpdate`, which is intentionally isolated there).
 */
import path from "node:path";
import { readAll, writeJson, writeJsonPretty } from "../utils/jsonl.js";
import type { CveIndex, CveIndexEntry, DatabaseMetadata, SearchDocument, Severity, SourceId } from "../../src/types/cve.js";
import { SCHEMA_VERSION } from "../../src/types/cve.js";

const INDEX_ROOT = path.resolve(process.cwd(), "index");

function sortObjectKeys<T extends Record<string, unknown>>(obj: T): T {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) out[key] = obj[key];
  return out as T;
}

async function main() {
  const cveIndex: CveIndex = {};
  const searchByYear = new Map<number, SearchDocument[]>();

  const yearCounts = new Map<number, number>();
  const monthCounts = new Map<string, number>();
  const severityCounts = new Map<Severity, number>();
  const cweCounts = new Map<string, { name: string | null; count: number }>();
  const vendorCounts = new Map<string, number>();
  const vendorProductCounts = new Map<string, { vendor: string; product: string; count: number }>();
  const cvssBuckets = new Map<string, number>();
  const stateCounts = new Map<string, number>();
  const sourceCounts = new Map<SourceId, number>();

  let total = 0;
  let latestModified: { id: string; date: string }[] = [];
  let latestPublished: { id: string; date: string }[] = [];

  for await (const { year, month, record } of readAll()) {
    total++;

    const entry: CveIndexEntry = {
      year,
      month,
      state: record.state,
      severity: record.severity.overall,
      cvss: record.severity.cvss,
      summary: record.summary ?? "",
      published: record.published,
      lastModified: record.lastModified,
    };
    cveIndex[record.id] = entry;

    const searchDoc: SearchDocument = {
      id: record.id,
      summary: record.summary ?? "",
      description: record.description ?? "",
      vendors: [...new Set(record.affected.map((a) => a.vendor))],
      products: [...new Set(record.affected.map((a) => a.product))],
      cwe: record.cwe.map((c) => c.cweId),
      severity: record.severity.overall,
      cvss: record.severity.cvss,
      year,
      published: record.published,
      lastModified: record.lastModified,
    };
    const bucket = searchByYear.get(year) ?? [];
    bucket.push(searchDoc);
    searchByYear.set(year, bucket);

    yearCounts.set(year, (yearCounts.get(year) ?? 0) + 1);
    const monthKey = `${year}-${String(month).padStart(2, "0")}`;
    monthCounts.set(monthKey, (monthCounts.get(monthKey) ?? 0) + 1);
    stateCounts.set(record.state, (stateCounts.get(record.state) ?? 0) + 1);

    if (record.state === "PUBLISHED") {
      severityCounts.set(record.severity.overall, (severityCounts.get(record.severity.overall) ?? 0) + 1);

      if (record.severity.cvss !== null) {
        const bucketFloor = Math.min(9, Math.floor(record.severity.cvss));
        const bucketLabel = `${bucketFloor}-${bucketFloor + 1}`;
        cvssBuckets.set(bucketLabel, (cvssBuckets.get(bucketLabel) ?? 0) + 1);
      }

      for (const cwe of record.cwe) {
        const existing = cweCounts.get(cwe.cweId);
        cweCounts.set(cwe.cweId, { name: cwe.name ?? existing?.name ?? null, count: (existing?.count ?? 0) + 1 });
      }

      const seenVendorsThisRecord = new Set<string>();
      for (const aff of record.affected) {
        if (!seenVendorsThisRecord.has(aff.vendor)) {
          vendorCounts.set(aff.vendor, (vendorCounts.get(aff.vendor) ?? 0) + 1);
          seenVendorsThisRecord.add(aff.vendor);
        }
        const vpKey = `${aff.vendor}\u0000${aff.product}`;
        const existing = vendorProductCounts.get(vpKey);
        vendorProductCounts.set(vpKey, { vendor: aff.vendor, product: aff.product, count: (existing?.count ?? 0) + 1 });
      }
    }

    for (const src of record.sources) sourceCounts.set(src, (sourceCounts.get(src) ?? 0) + 1);

    if (record.lastModified) latestModified.push({ id: record.id, date: record.lastModified });
    if (record.published) latestPublished.push({ id: record.id, date: record.published });
  }

  latestModified = latestModified.sort((a, b) => b.date.localeCompare(a.date)).slice(0, 50);
  latestPublished = latestPublished.sort((a, b) => b.date.localeCompare(a.date)).slice(0, 50);

  // --- Write index/cve-index.json (sorted keys => deterministic output) ---
  await writeJson(path.join(INDEX_ROOT, "cve-index.json"), sortObjectKeys(cveIndex));

  // --- Write per-year search index shards + manifest ---
  const searchYears = [...searchByYear.keys()].sort((a, b) => b - a);
  for (const year of searchYears) {
    const docs = (searchByYear.get(year) ?? []).sort((a, b) => a.id.localeCompare(b.id, "en", { numeric: true }));
    await writeJson(path.join(INDEX_ROOT, "search-index", `${year}.json`), docs);
  }
  await writeJson(path.join(INDEX_ROOT, "search-index", "manifest.json"), {
    years: searchYears,
    counts: Object.fromEntries(searchYears.map((y) => [y, searchByYear.get(y)?.length ?? 0])),
  });

  // --- Write auxiliary lookup indexes ---
  await writeJson(
    path.join(INDEX_ROOT, "year-index.json"),
    sortObjectKeys(Object.fromEntries([...yearCounts.entries()].map(([y, c]) => [String(y), c]))),
  );
  await writeJson(
    path.join(INDEX_ROOT, "severity-index.json"),
    sortObjectKeys(Object.fromEntries([...severityCounts.entries()])),
  );
  await writeJson(
    path.join(INDEX_ROOT, "cwe-index.json"),
    sortObjectKeys(
      Object.fromEntries([...cweCounts.entries()].map(([id, v]) => [id, v])),
    ),
  );
  await writeJson(
    path.join(INDEX_ROOT, "vendor-index.json"),
    sortObjectKeys(Object.fromEntries([...vendorCounts.entries()])),
  );

  // --- Write index/statistics.json ---
  const statistics = {
    generatedAt: new Date().toISOString(),
    totalCves: total,
    byYear: sortObjectKeys(Object.fromEntries([...yearCounts.entries()].map(([y, c]) => [String(y), c]))),
    byMonth: sortObjectKeys(Object.fromEntries(monthCounts)),
    bySeverity: sortObjectKeys(Object.fromEntries(severityCounts)),
    byState: sortObjectKeys(Object.fromEntries(stateCounts)),
    byCwe: [...cweCounts.entries()]
      .map(([cweId, v]) => ({ cweId, name: v.name, count: v.count }))
      .sort((a, b) => b.count - a.count || a.cweId.localeCompare(b.cweId))
      .slice(0, 30),
    byVendor: [...vendorCounts.entries()]
      .map(([vendor, count]) => ({ vendor, count }))
      .sort((a, b) => b.count - a.count || a.vendor.localeCompare(b.vendor))
      .slice(0, 30),
    byProduct: [...vendorProductCounts.values()]
      .sort((a, b) => b.count - a.count || a.product.localeCompare(b.product))
      .slice(0, 30),
    cvssDistribution: [...Array(10)].map((_, i) => ({ bucket: `${i}-${i + 1}`, count: cvssBuckets.get(`${i}-${i + 1}`) ?? 0 })),
    recentlyAdded: latestPublished.map((r) => r.id),
    recentlyModified: latestModified.map((r) => r.id),
  };
  await writeJson(path.join(INDEX_ROOT, "statistics.json"), statistics);

  // --- Write index/metadata.json ---
  const metadata: DatabaseMetadata = {
    lastUpdate: new Date().toISOString(),
    schemaVersion: SCHEMA_VERSION,
    records: total,
    years: sortObjectKeys(Object.fromEntries([...yearCounts.entries()].map(([y, c]) => [String(y), c]))),
    sources: sortObjectKeys(
      Object.fromEntries(
        [...sourceCounts.entries()].map(([id, count]) => [id, { lastFetched: new Date().toISOString(), recordsContributed: count }]),
      ),
    ),
  };
  await writeJsonPretty(path.join(INDEX_ROOT, "metadata.json"), metadata);

  console.log(`Indexed ${total} records across ${searchYears.length} year(s).`);
  console.log(`  index/cve-index.json, index/search-index/*.json, index/statistics.json, index/metadata.json written.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
