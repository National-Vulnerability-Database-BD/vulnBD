#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { CveIndex } from "../../src/types/cve.js";
import { readMonth } from "../utils/jsonl.js";

async function main() {
  const id = process.argv[2];
  if (!id || !/^CVE-\d{4}-\d{4,}$/i.test(id)) {
    console.error("Usage: npm run cve -- CVE-YYYY-NNNNN");
    process.exit(1);
  }
  const normalizedId = id.toUpperCase();

  const indexRaw = await readFile(path.resolve(process.cwd(), "index/cve-index.json"), "utf-8").catch(() => null);
  if (!indexRaw) {
    console.error("index/cve-index.json not found — run `npm run index` first.");
    process.exit(1);
  }
  const index = JSON.parse(indexRaw) as CveIndex;
  const entry = index[normalizedId];
  if (!entry) {
    console.error(`${normalizedId} not found in the database.`);
    process.exit(1);
  }

  const records = await readMonth(entry.year, entry.month);
  const record = records.find((r) => r.id === normalizedId);
  if (!record) {
    console.error(`${normalizedId} is in the index but missing from data/${entry.year}/${String(entry.month).padStart(2, "0")}.jsonl — index may be stale.`);
    process.exit(1);
  }

  console.log(JSON.stringify(record, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
