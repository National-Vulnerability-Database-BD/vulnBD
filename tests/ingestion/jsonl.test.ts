import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SCHEMA_VERSION, type CveRecord } from "../../src/types/cve.js";

function makeRecord(id: string): CveRecord {
  return {
    schemaVersion: SCHEMA_VERSION,
    id,
    state: "PUBLISHED",
    summary: "s",
    description: "d",
    published: "2026-03-01T00:00:00.000Z",
    lastModified: "2026-03-01T00:00:00.000Z",
    withdrawn: null,
    severity: { overall: "MEDIUM", cvss: 5.0 },
    cvss: { v2: null, v3_0: null, v3_1: null, v4_0: null },
    cwe: [],
    affected: [],
    configurations: [],
    references: [],
    exploit: null,
    credits: [],
    sources: ["cve.org"],
    primarySource: "cve.org",
  };
}

describe("jsonl storage", () => {
  let tmpDir: string;
  let originalCwd: string;

  beforeEach(async () => {
    originalCwd = process.cwd();
    tmpDir = await mkdtemp(path.join(os.tmpdir(), "cve-db-test-"));
    process.chdir(tmpDir);
  });

  afterEach(async () => {
    process.chdir(originalCwd);
    await rm(tmpDir, { recursive: true, force: true });
  });

  it("reading a nonexistent month returns an empty array, not an error", async () => {
    const { readMonth } = await import("../../scripts/utils/jsonl.js?t=" + tmpDir);
    const records = await readMonth(2026, 3);
    expect(records).toEqual([]);
  });

  it("writes and reads back records sorted by CVE ID", async () => {
    const { writeMonth, readMonth } = await import("../../scripts/utils/jsonl.js?t=" + tmpDir);
    await writeMonth(2026, 3, [makeRecord("CVE-2026-00003"), makeRecord("CVE-2026-00001"), makeRecord("CVE-2026-00002")]);
    const records = await readMonth(2026, 3);
    expect(records.map((r: { id: string }) => r.id)).toEqual(["CVE-2026-00001", "CVE-2026-00002", "CVE-2026-00003"]);
  });

  it("writing identical data twice produces byte-identical output (idempotent)", async () => {
    const { writeMonth } = await import("../../scripts/utils/jsonl.js?t=" + tmpDir);
    const { readFile } = await import("node:fs/promises");
    const records = [makeRecord("CVE-2026-00001"), makeRecord("CVE-2026-00002")];
    await writeMonth(2026, 3, records);
    const first = await readFile(path.join(tmpDir, "data/2026/03.jsonl"), "utf-8");
    await writeMonth(2026, 3, [...records].reverse());
    const second = await readFile(path.join(tmpDir, "data/2026/03.jsonl"), "utf-8");
    expect(second).toBe(first);
  });
});
