#!/usr/bin/env node
/**
 * One-time (or occasional) HISTORICAL backfill from the CVE Program's
 * GitHub mirror.
 *
 * scripts/ingest.ts (npm run fetch) uses cves/deltaLog.json, a rolling
 * changelog of *recent* changes — great for daily incremental updates, but
 * it does not reach back into CVE history. This script instead downloads a
 * full snapshot of the source repository and extracts specific year
 * directories directly, so you can backfill 1999-2020-whatever at your own
 * pace without re-downloading the whole archive's file tree over the
 * GitHub API (which would be extremely rate-limit-hungry).
 *
 * Usage:
 *   npm run backfill -- --years=1999-2005
 *   npm run backfill -- --years=2020,2021,2022
 *   npm run backfill -- --years=2015
 *
 * Downloads ONE tarball of the whole cvelistV5 repository (~150-250 MB,
 * cached for the duration of this run), then extracts only the requested
 * cves/<year>/ directories from it. Safe to run repeatedly and
 * incrementally (e.g. a few years per run) — already-present records are
 * simply overwritten in place (see mergeIntoMonth), so nothing is
 * duplicated by re-running with overlapping years.
 */
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, rm, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { normalizeCveOrgRecord } from "./normalize/cve-org.js";
import { validateRecords } from "./validate/validate.js";
import { readMonth, writeMonth, yearMonthFromDate } from "./utils/jsonl.js";
import type { CveRecord } from "../src/types/cve.js";

const TARBALL_URL = "https://codeload.github.com/CVEProject/cvelistV5/tar.gz/refs/heads/main";

function parseYears(spec: string): number[] {
  const years = new Set<number>();
  for (const part of spec.split(",")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const rangeMatch = trimmed.match(/^(\d{4})-(\d{4})$/);
    if (rangeMatch) {
      const start = Number(rangeMatch[1]);
      const end = Number(rangeMatch[2]);
      for (let y = Math.min(start, end); y <= Math.max(start, end); y++) years.add(y);
    } else if (/^\d{4}$/.test(trimmed)) {
      years.add(Number(trimmed));
    } else {
      throw new Error(`Unrecognized --years segment: "${trimmed}" (use e.g. 1999-2005, or 2020,2021, or 2020)`);
    }
  }
  const currentYear = new Date().getUTCFullYear();
  for (const y of years) {
    if (y < 1999 || y > currentYear + 1) throw new Error(`Year ${y} is out of the plausible CVE range (1999-${currentYear + 1}).`);
  }
  return [...years].sort((a, b) => a - b);
}

async function downloadTarball(destPath: string): Promise<void> {
  console.log(`Downloading full repository snapshot from ${TARBALL_URL} ...`);
  const res = await fetch(TARBALL_URL, { headers: { "User-Agent": "cve-db-backfill/1.0" } });
  if (!res.ok || !res.body) throw new Error(`Failed to download tarball: HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  await writeFile(destPath, buf);
  console.log(`Downloaded ${(buf.byteLength / 1024 / 1024).toFixed(1)} MB.`);
}

async function extractYear(tarballPath: string, year: number, workDir: string): Promise<string> {
  const yearDest = path.join(workDir, `extract-${year}`);
  await mkdir(yearDest, { recursive: true });
  try {
    execFileSync("tar", ["--wildcards", "-xzf", tarballPath, "-C", yearDest, `*/cves/${year}/*`], { stdio: "inherit" });
  } catch {
    // tar exits non-zero if a wildcard matches nothing on some platforms —
    // that just means this year has no records in the mirror; not fatal.
  }
  return yearDest;
}

async function collectCveJsonFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(d: string) {
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) await walk(full);
      else if (e.isFile() && /^CVE-\d{4}-\d+\.json$/.test(e.name)) out.push(full);
    }
  }
  await walk(dir);
  return out;
}

async function main() {
  const yearsArg = process.argv.find((a) => a.startsWith("--years="))?.split("=")[1];
  if (!yearsArg) {
    console.error("Usage: npm run backfill -- --years=1999-2005 (or --years=2020,2021 or --years=2020)");
    process.exit(1);
  }
  const years = parseYears(yearsArg);
  console.log(`Backfilling ${years.length} year(s): ${years.join(", ")}`);

  const workDir = await mkdtemp(path.join(tmpdir(), "cve-backfill-"));
  const tarballPath = path.join(workDir, "cvelistV5.tar.gz");

  let totalNormalized = 0;
  let totalSkipped = 0;
  let filesChanged = 0;

  try {
    await downloadTarball(tarballPath);

    for (const year of years) {
      console.log(`\n--- Year ${year} ---`);
      const yearDir = await extractYear(tarballPath, year, workDir);
      const files = await collectCveJsonFiles(yearDir);
      console.log(`Found ${files.length} record file(s) for ${year} in the source mirror.`);

      if (files.length === 0) {
        await rm(yearDir, { recursive: true, force: true });
        continue;
      }

      const normalized: CveRecord[] = [];
      for (const file of files) {
        let raw: unknown;
        try {
          raw = JSON.parse(await readFile(file, "utf-8"));
        } catch {
          totalSkipped++;
          continue;
        }
        const rec = normalizeCveOrgRecord(raw as Parameters<typeof normalizeCveOrgRecord>[0]);
        if (rec) normalized.push(rec);
        else totalSkipped++;
      }
      totalNormalized += normalized.length;

      const summary = validateRecords(normalized);
      if (summary.errors.length > 0) {
        console.error(`Validation found ${summary.errors.length} error(s) in ${year} — skipping this year's write. First few:`);
        for (const e of summary.errors.slice(0, 20)) console.error(`  [error] ${e.cveId} ${e.field}: ${e.message}`);
        await rm(yearDir, { recursive: true, force: true });
        continue;
      }

      // Group by actual destination month (publication date, which can
      // differ from the CVE ID's year — e.g. a 1999-numbered CVE published
      // years later still files under its real publication month).
      const byMonth = new Map<string, CveRecord[]>();
      for (const rec of normalized) {
        const dateBasis = rec.published ?? rec.lastModified ?? `${year}-01-01T00:00:00.000Z`;
        let ym;
        try {
          ym = yearMonthFromDate(dateBasis);
        } catch {
          ym = { year, month: 1 };
        }
        const key = `${ym.year}-${String(ym.month).padStart(2, "0")}`;
        const bucket = byMonth.get(key) ?? [];
        bucket.push(rec);
        byMonth.set(key, bucket);
      }

      for (const [key, incoming] of byMonth) {
        const [y, m] = key.split("-").map(Number);
        const existing = await readMonth(y, m);
        const merged = [...existing];
        for (const rec of incoming) {
          const idx = merged.findIndex((r) => r.id === rec.id);
          if (idx === -1) merged.push(rec);
          else merged[idx] = rec;
        }
        const before = JSON.stringify([...existing].sort((a, b) => a.id.localeCompare(b.id)));
        const after = JSON.stringify([...merged].sort((a, b) => a.id.localeCompare(b.id)));
        if (before === after) continue;
        await writeMonth(y, m, merged);
        filesChanged++;
        console.log(`  updated data/${y}/${String(m).padStart(2, "0")}.jsonl (${existing.length} -> ${merged.length} records)`);
      }

      // Free disk as we go — some years are tens of thousands of small files.
      await rm(yearDir, { recursive: true, force: true });
    }

    console.log(`\nBackfill done: ${totalNormalized} normalized, ${totalSkipped} skipped, ${filesChanged} data file(s) changed.`);
    console.log(`Now run: npm run validate && npm run index`);
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
