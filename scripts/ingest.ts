#!/usr/bin/env node
/**
 * Orchestrates a full ingestion run:
 *
 *   fetch (source adapter) -> normalize -> validate -> dedupe/merge
 *   -> write only the affected data/YYYY/MM.jsonl files
 *
 * Usage:
 *   npm run fetch                    # incremental, since last recorded update
 *   npm run fetch -- --limit=1000    # cap how many CVEs this run pulls
 *   npm run fetch -- --full          # ignore metadata's lastUpdate cursor
 */
import path from "node:path";
import { readFile } from "node:fs/promises";
import { cveOrgAdapter } from "./fetch/cve-org.js";
import { validateRecords } from "./validate/validate.js";
import { readMonth, writeMonth, yearMonthFromDate } from "./utils/jsonl.js";
import { writeJsonPretty } from "./utils/jsonl.js";
import type { CveRecord, DatabaseMetadata } from "../src/types/cve.js";

const METADATA_PATH = path.resolve(process.cwd(), "index/metadata.json");

function parseArgs(argv: string[]) {
  const args = { limit: 500, full: false };
  for (const a of argv) {
    if (a.startsWith("--limit=")) args.limit = Number(a.split("=")[1]);
    if (a === "--full") args.full = true;
  }
  return args;
}

async function loadMetadata(): Promise<DatabaseMetadata | null> {
  try {
    const raw = await readFile(METADATA_PATH, "utf-8");
    return JSON.parse(raw) as DatabaseMetadata;
  } catch {
    return null;
  }
}

/** Merges a new/updated record into an existing month's records by CVE ID (last-write-wins, keyed by id). Keeps the run idempotent. */
function mergeIntoMonth(existing: CveRecord[], incoming: CveRecord): CveRecord[] {
  const idx = existing.findIndex((r) => r.id === incoming.id);
  if (idx === -1) return [...existing, incoming];
  const merged = [...existing];
  merged[idx] = incoming;
  return merged;
}

async function main() {
  const { limit, full } = parseArgs(process.argv.slice(2));
  const metadata = full ? null : await loadMetadata();
  const since = metadata?.lastUpdate ? new Date(metadata.lastUpdate) : null;

  console.log(`Fetching from ${cveOrgAdapter.id}${since ? ` (since ${since.toISOString()})` : " (full/first run)"}, limit=${limit}...`);
  const raws = await cveOrgAdapter.fetch({ since, limit });

  const normalized: CveRecord[] = [];
  let skipped = 0;
  for (const raw of raws) {
    const rec = cveOrgAdapter.normalize(raw);
    if (rec) normalized.push(rec);
    else skipped++;
  }
  console.log(`Normalized ${normalized.length} record(s), skipped ${skipped} unparseable.`);

  const summary = validateRecords(normalized);
  if (summary.errors.length > 0) {
    console.error(`Validation found ${summary.errors.length} error(s) in freshly fetched data — aborting before write.`);
    for (const e of summary.errors.slice(0, 30)) console.error(`  [error] ${e.cveId} ${e.field}: ${e.message}`);
    process.exit(1);
  }
  if (summary.warnings.length > 0) {
    console.warn(`${summary.warnings.length} warning(s) (non-fatal).`);
  }

  // Group incoming records by their destination YYYY/MM file (based on
  // publication date; records with no publication date fall back to today).
  const byMonth = new Map<string, CveRecord[]>();
  for (const rec of normalized) {
    const dateBasis = rec.published ?? rec.lastModified ?? new Date().toISOString();
    let ym: { year: number; month: number };
    try {
      ym = yearMonthFromDate(dateBasis);
    } catch {
      ym = yearMonthFromDate(new Date().toISOString());
    }
    const key = `${ym.year}-${String(ym.month).padStart(2, "0")}`;
    const bucket = byMonth.get(key) ?? [];
    bucket.push(rec);
    byMonth.set(key, bucket);
  }

  let filesChanged = 0;
  let recordsWritten = 0;
  const yearsTouched: Record<string, number> = { ...(metadata?.years ?? {}) };

  for (const [key, incomingRecords] of byMonth) {
    const [yearStr, monthStr] = key.split("-");
    const year = Number(yearStr);
    const month = Number(monthStr);

    const existing = await readMonth(year, month);
    let merged = existing;
    for (const rec of incomingRecords) merged = mergeIntoMonth(merged, rec);

    // Idempotency check: skip the write entirely if nothing actually changed.
    const before = JSON.stringify([...existing].sort((a, b) => a.id.localeCompare(b.id)));
    const after = JSON.stringify([...merged].sort((a, b) => a.id.localeCompare(b.id)));
    if (before === after) continue;

    await writeMonth(year, month, merged);
    filesChanged++;
    recordsWritten += incomingRecords.length;
    yearsTouched[yearStr] = merged.length + (yearsTouched[yearStr] ?? 0) - (existing.length ?? 0) - (yearsTouched[yearStr] ? 0 : 0);
    console.log(`  updated data/${year}/${monthStr}.jsonl (${existing.length} -> ${merged.length} records)`);
  }

  console.log(`\nDone: ${filesChanged} file(s) changed, ${recordsWritten} record(s) touched.`);

  // Metadata is updated by scripts/index/build-index.ts (which recomputes
  // exact per-year counts from disk), but we stamp lastUpdate here so a
  // subsequent incremental run knows the new cursor even if indexing is run
  // as a separate CI step.
  const newMetadata: Partial<DatabaseMetadata> = {
    lastUpdate: new Date().toISOString(),
  };
  await writeJsonPretty(path.resolve(process.cwd(), "index/.last-fetch.json"), newMetadata);

  if (filesChanged === 0) {
    console.log("No changes detected — nothing to commit.");
    process.exitCode = 0;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
