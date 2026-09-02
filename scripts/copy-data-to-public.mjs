// Copies data/ into public/data/ so the built site can serve JSONL files
// directly from its own domain (no external repository links needed on the
// public-facing Downloads page). Also builds a single concatenated
// full-export.jsonl for convenience, and copies SHA256SUMS alongside it.
// Runs after `npm run index`, before `astro build`.
import { cp, rm, readdir, readFile, appendFile, writeFile, copyFile } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const src = path.join(root, "data");
const dest = path.join(root, "public", "data");

await rm(dest, { recursive: true, force: true });
await cp(src, dest, { recursive: true });

// Build one combined file across all years/months, sorted for determinism.
const fullExportPath = path.join(dest, "full-export.jsonl");
await rm(fullExportPath, { force: true });

const years = (await readdir(src, { withFileTypes: true }))
  .filter((e) => e.isDirectory() && /^\d{4}$/.test(e.name))
  .map((e) => e.name)
  .sort();

let totalLines = 0;
for (const year of years) {
  const yearDir = path.join(src, year);
  const files = (await readdir(yearDir)).filter((f) => f.endsWith(".jsonl")).sort();
  for (const file of files) {
    const content = await readFile(path.join(yearDir, file), "utf-8");
    if (content.trim().length === 0) continue;
    await appendFile(fullExportPath, content.endsWith("\n") ? content : content + "\n");
    totalLines += content.trim().split("\n").length;
  }
}

// Copy the integrity checksums alongside the data if present.
try {
  await copyFile(path.join(root, "SHA256SUMS"), path.join(root, "public", "SHA256SUMS"));
} catch {
  // No checksums file yet — fine on a fresh clone before the first data run.
}

console.log(`Copied ${src} -> ${dest}, wrote full-export.jsonl (${totalLines} records).`);
