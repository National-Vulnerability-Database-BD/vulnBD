import { readFileSync } from "node:fs";
import path from "node:path";
import type { CveIndex, CveRecord, DatabaseMetadata, SearchDocument, StatisticsData } from "../types/cve";

const ROOT = process.cwd();

function readJson<T>(relPath: string, fallback: T): T {
  try {
    return JSON.parse(readFileSync(path.join(ROOT, relPath), "utf-8")) as T;
  } catch {
    return fallback;
  }
}

export function getCveIndex(): CveIndex {
  return readJson<CveIndex>("index/cve-index.json", {});
}

export function getStatistics(): StatisticsData {
  return readJson<StatisticsData>("index/statistics.json", {
    generatedAt: new Date(0).toISOString(),
    totalCves: 0,
    byYear: {},
    byMonth: {},
    bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0, UNKNOWN: 0 },
    byCwe: [],
    byVendor: [],
    byProduct: [],
    cvssDistribution: [],
    recentlyAdded: [],
    recentlyModified: [],
  });
}

export function getMetadata(): DatabaseMetadata {
  return readJson<DatabaseMetadata>("index/metadata.json", {
    lastUpdate: new Date(0).toISOString(),
    schemaVersion: 1,
    records: 0,
    years: {},
    sources: {},
  });
}

export function getYearIndex(): Record<string, number> {
  return readJson<Record<string, number>>("index/year-index.json", {});
}

export function getSeverityIndex(): Record<string, number> {
  return readJson<Record<string, number>>("index/severity-index.json", {});
}

export function getCweIndex(): Record<string, { name: string | null; count: number }> {
  return readJson("index/cwe-index.json", {});
}

export function getVendorIndex(): Record<string, number> {
  return readJson<Record<string, number>>("index/vendor-index.json", {});
}

export function getSearchManifest(): { years: number[]; counts: Record<string, number> } {
  return readJson("index/search-index/manifest.json", { years: [], counts: {} });
}

export function getSearchDocsForYear(year: number): SearchDocument[] {
  return readJson<SearchDocument[]>(`index/search-index/${year}.json`, []);
}

export function getAllSearchDocs(): SearchDocument[] {
  const manifest = getSearchManifest();
  return manifest.years.flatMap((y) => getSearchDocsForYear(y));
}

/** Reads one full normalized record by ID, using the lightweight index to locate its file (no full-database scan). */
export function getRecordById(id: string): CveRecord | null {
  const index = getCveIndex();
  const entry = index[id.toUpperCase()];
  if (!entry) return null;
  const mm = String(entry.month).padStart(2, "0");
  const filePath = path.join(ROOT, "data", String(entry.year), `${mm}.jsonl`);
  let raw: string;
  try {
    raw = readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    const rec = JSON.parse(line) as CveRecord;
    if (rec.id === id.toUpperCase()) return rec;
  }
  return null;
}

/** Reads every record for a given year (used by year pages / static path generation). Bounded to one year at a time by design. */
export function getRecordsForYear(year: number): CveRecord[] {
  const index = getCveIndex();
  const ids = Object.entries(index)
    .filter(([, e]) => e.year === year)
    .map(([id]) => id);
  const out: CveRecord[] = [];
  const seen = new Set<string>();
  for (const id of ids) {
    const entry = index[id];
    const key = `${entry.year}-${entry.month}`;
    if (seen.has(key)) continue; // we'll batch-read the file once below instead
  }
  // Batch-read month files once instead of re-reading per record.
  const months = new Set(ids.map((id) => index[id].month));
  for (const month of months) {
    const mm = String(month).padStart(2, "0");
    const filePath = path.join(ROOT, "data", String(year), `${mm}.jsonl`);
    let raw: string;
    try {
      raw = readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }
    for (const line of raw.split("\n")) {
      if (!line.trim()) continue;
      out.push(JSON.parse(line) as CveRecord);
    }
  }
  return out;
}

export function formatCveIdSlug(id: string): string {
  return id.toUpperCase();
}
