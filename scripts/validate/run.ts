#!/usr/bin/env node
import { readAll } from "../utils/jsonl.js";
import { validateRecords } from "./validate.js";

async function main() {
  const records = [];
  const idsByYearMonth = new Map<string, string>();
  const misfiled: string[] = [];

  for await (const { year, month, record } of readAll()) {
    records.push(record);
    if (record.published) {
      const pubYear = new Date(record.published).getUTCFullYear();
      const pubMonth = new Date(record.published).getUTCMonth() + 1;
      if (pubYear !== year || pubMonth !== month) {
        misfiled.push(`${record.id} is stored in ${year}/${String(month).padStart(2, "0")} but published date implies ${pubYear}/${String(pubMonth).padStart(2, "0")}`);
      }
    }
  }

  console.log(`Validating ${records.length} record(s)...`);
  const summary = validateRecords(records);

  if (summary.warnings.length > 0) {
    console.log(`\n${summary.warnings.length} warning(s):`);
    for (const w of summary.warnings.slice(0, 50)) console.log(`  [warn] ${w.cveId} ${w.field}: ${w.message}`);
    if (summary.warnings.length > 50) console.log(`  ...and ${summary.warnings.length - 50} more`);
  }

  if (misfiled.length > 0) {
    console.log(`\n${misfiled.length} misfiled record(s):`);
    for (const m of misfiled.slice(0, 50)) console.log(`  [warn] ${m}`);
  }

  if (summary.errors.length > 0) {
    console.error(`\n${summary.errors.length} error(s):`);
    for (const e of summary.errors) console.error(`  [error] ${e.cveId} ${e.field}: ${e.message}`);
    console.error(`\nValidation FAILED.`);
    process.exit(1);
  }

  console.log(`\nValidation passed: ${summary.recordsChecked} records, 0 errors, ${summary.warnings.length} warnings.`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
