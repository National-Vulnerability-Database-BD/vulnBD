import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readdir, rename, writeFile } from "node:fs/promises";
import { createInterface } from "node:readline";
import path from "node:path";
import type { CveRecord } from "../../src/types/cve.js";

export const DATA_ROOT = path.resolve(process.cwd(), "data");

/**
 * Resolves the on-disk destination(s) for a given year/month.
 *
 * The reader/writer abstraction here is deliberately partition-aware even
 * though we only ever write `MM.jsonl` today: if a month's file grows too
 * large in the future, it can be split into `MM/part-01.jsonl`,
 * `MM/part-02.jsonl`, ... without any caller of readMonth/writeMonth
 * changing. See docs/DATA_FORMAT.md.
 */
export async function monthFiles(year: number, month: number): Promise<string[]> {
  const yearDir = path.join(DATA_ROOT, String(year));
  const mm = String(month).padStart(2, "0");
  const singleFile = path.join(yearDir, `${mm}.jsonl`);
  const partDir = path.join(yearDir, mm);

  try {
    const entries = await readdir(partDir);
    const parts = entries
      .filter((f) => /^part-\d+\.jsonl$/.test(f))
      .sort()
      .map((f) => path.join(partDir, f));
    if (parts.length > 0) return parts;
  } catch {
    // no partition directory — fall through to single file
  }

  return [singleFile];
}

/** Streams every record from a single JSONL file. Skips blank lines. */
export async function* readJsonlFile(filePath: string): AsyncGenerator<CveRecord> {
  const stream = createReadStream(filePath, { encoding: "utf-8" });
  stream.on("error", () => {
    /* swallowed below via the try/catch around the async iteration */
  });
  let rl;
  try {
    // Triggers the underlying open(); throws (into this try) on ENOENT etc.
    await new Promise<void>((resolve, reject) => {
      stream.once("open", () => resolve());
      stream.once("error", (err) => reject(err));
    });
    rl = createInterface({ input: stream, crlfDelay: Infinity });
  } catch (err: unknown) {
    if (err && typeof err === "object" && "code" in err && (err as { code?: string }).code === "ENOENT") {
      return; // file doesn't exist yet — treat as an empty month
    }
    throw err;
  }
  let lineNo = 0;
  for await (const line of rl) {
    lineNo++;
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      yield JSON.parse(trimmed) as CveRecord;
    } catch (err) {
      throw new Error(`Malformed JSONL at ${filePath}:${lineNo} — ${(err as Error).message}`);
    }
  }
}

/** Reads every record for a given year+month across all partition files. */
export async function readMonth(year: number, month: number): Promise<CveRecord[]> {
  const files = await monthFiles(year, month);
  const out: CveRecord[] = [];
  for (const file of files) {
    for await (const rec of readJsonlFile(file)) out.push(rec);
  }
  return out;
}

/** Iterates every record in the entire database, year-then-month ascending. */
export async function* readAll(): AsyncGenerator<{ year: number; month: number; record: CveRecord }> {
  let years: string[] = [];
  try {
    years = (await readdir(DATA_ROOT)).filter((d) => /^\d{4}$/.test(d)).sort();
  } catch {
    return;
  }
  for (const yearStr of years) {
    const year = Number(yearStr);
    const yearDir = path.join(DATA_ROOT, yearStr);
    let entries: string[] = [];
    try {
      entries = await readdir(yearDir);
    } catch {
      continue;
    }
    const months = new Set<number>();
    for (const e of entries) {
      const fileMatch = e.match(/^(\d{2})\.jsonl$/);
      if (fileMatch) months.add(Number(fileMatch[1]));
      if (/^\d{2}$/.test(e)) months.add(Number(e));
    }
    for (const month of [...months].sort((a, b) => a - b)) {
      for (const record of await readMonth(year, month)) {
        yield { year, month, record };
      }
    }
  }
}

/**
 * Writes a full set of records to a month's JSONL file, sorted by CVE ID.
 * Always writes the single-file form (`MM.jsonl`); partitioning is applied
 * manually by an operator splitting a directory (see monthFiles) — the
 * writer intentionally stays simple and deterministic.
 *
 * Uses a temp-file-then-rename to avoid ever leaving a half-written file on
 * disk (important since this runs inside CI on a schedule).
 */
export async function writeMonth(year: number, month: number, records: CveRecord[]): Promise<void> {
  const yearDir = path.join(DATA_ROOT, String(year));
  await mkdir(yearDir, { recursive: true });
  const mm = String(month).padStart(2, "0");
  const finalPath = path.join(yearDir, `${mm}.jsonl`);
  const tmpPath = `${finalPath}.tmp`;

  const sorted = [...records].sort((a, b) => a.id.localeCompare(b.id, "en", { numeric: true }));

  await new Promise<void>((resolve, reject) => {
    const ws = createWriteStream(tmpPath, { encoding: "utf-8" });
    ws.on("error", reject);
    ws.on("finish", resolve);
    for (const rec of sorted) {
      ws.write(JSON.stringify(rec) + "\n");
    }
    ws.end();
  });

  await rename(tmpPath, finalPath);
}

export function yearMonthFromDate(iso: string): { year: number; month: number } {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) throw new Error(`Invalid date: ${iso}`);
  return { year: d.getUTCFullYear(), month: d.getUTCMonth() + 1 };
}

export async function writeJson(filePath: string, data: unknown): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, JSON.stringify(data, null, 0), "utf-8");
}

export async function writeJsonPretty(filePath: string, data: unknown): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, JSON.stringify(data, null, 2) + "\n", "utf-8");
}
