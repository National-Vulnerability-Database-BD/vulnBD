import { describe, expect, it } from "vitest";
import { validateRecord, validateRecords } from "../../scripts/validate/validate.js";
import { SCHEMA_VERSION, type CveRecord } from "../../src/types/cve.js";

function makeRecord(overrides: Partial<CveRecord> = {}): CveRecord {
  return {
    schemaVersion: SCHEMA_VERSION,
    id: "CVE-2026-00001",
    state: "PUBLISHED",
    summary: "Example summary",
    description: "Example description",
    published: "2026-01-01T00:00:00.000Z",
    lastModified: "2026-01-02T00:00:00.000Z",
    withdrawn: null,
    severity: { overall: "HIGH", cvss: 7.5 },
    cvss: {
      v2: null,
      v3_0: null,
      v3_1: { vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", baseScore: 7.5, baseSeverity: "HIGH", source: "cve.org" },
      v4_0: null,
    },
    cwe: [{ cweId: "CWE-79", name: "XSS", source: "cve.org" }],
    affected: [{ vendor: "Acme", product: "Widget", cpe: null, versions: [], platforms: [] }],
    configurations: [],
    references: [{ url: "https://example.com", source: "cve.org", tags: [] }],
    exploit: null,
    credits: [],
    sources: ["cve.org"],
    primarySource: "cve.org",
    ...overrides,
  };
}

describe("validateRecord", () => {
  it("passes a well-formed record with no issues", () => {
    expect(validateRecord(makeRecord())).toEqual([]);
  });

  it("flags a malformed CVE ID", () => {
    const issues = validateRecord(makeRecord({ id: "CVE-26-1" }));
    expect(issues.some((i) => i.field === "id" && i.severity === "error")).toBe(true);
  });

  it("flags an invalid CVSS vector", () => {
    const rec = makeRecord();
    rec.cvss.v3_1!.vectorString = "not-a-vector";
    const issues = validateRecord(rec);
    expect(issues.some((i) => i.field.includes("vectorString"))).toBe(true);
  });

  it("flags an out-of-range CVSS score", () => {
    const rec = makeRecord();
    rec.cvss.v3_1!.baseScore = 15;
    const issues = validateRecord(rec);
    expect(issues.some((i) => i.field.includes("baseScore"))).toBe(true);
  });

  it("flags an invalid CWE ID format", () => {
    const rec = makeRecord({ cwe: [{ cweId: "79", name: null, source: "cve.org" }] });
    const issues = validateRecord(rec);
    expect(issues.some((i) => i.field === "cwe")).toBe(true);
  });

  it("flags an unsafe reference URL", () => {
    const rec = makeRecord({ references: [{ url: "javascript:alert(1)", source: "cve.org", tags: [] }] });
    const issues = validateRecord(rec);
    expect(issues.some((i) => i.field === "references" && i.severity === "error")).toBe(true);
  });

  it("warns (not errors) when WITHDRAWN state has no withdrawn date", () => {
    const rec = makeRecord({ state: "WITHDRAWN", withdrawn: null });
    const issues = validateRecord(rec);
    expect(issues.some((i) => i.field === "withdrawn" && i.severity === "warning")).toBe(true);
    expect(issues.some((i) => i.severity === "error")).toBe(false);
  });
});

describe("validateRecords", () => {
  it("detects duplicate CVE IDs within a batch", () => {
    const summary = validateRecords([makeRecord(), makeRecord()]);
    expect(summary.errors.some((e) => e.message.includes("duplicate"))).toBe(true);
  });

  it("is idempotent-friendly: an empty batch produces no issues", () => {
    const summary = validateRecords([]);
    expect(summary.errors).toEqual([]);
    expect(summary.warnings).toEqual([]);
  });
});
